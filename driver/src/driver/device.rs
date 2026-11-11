use core::{
    mem::size_of,
    ptr::{null, null_mut},
};
use std::sync::Mutex;

use wdk_sys::{
    _WDF_EXECUTION_LEVEL, _WDF_IO_QUEUE_DISPATCH_TYPE, _WDF_SYNCHRONIZATION_SCOPE, _WDF_TRI_STATE,
    GUID, NTSTATUS, WDF_DEVICE_POWER_STATE, WDF_IO_QUEUE_CONFIG, WDF_OBJECT_ATTRIBUTES,
    WDF_OBJECT_CONTEXT_TYPE_INFO, WDF_PNPPOWER_EVENT_CALLBACKS, WDFCMRESLIST, WDFDEVICE,
    WDFDEVICE_INIT, WDFDRIVER, WDFOBJECT, WDFQUEUE, WDFREQUEST, call_unsafe_wdf_function_binding,
};
#[cfg(feature = "pcsc")]
use windows_sys::Win32::Security::Credentials::GUID_DEVINTERFACE_SMARTCARD_READER;

#[cfg(feature = "pcsc")]
use super::unit::UnitLease;
use super::{
    queue::{Queues, Request},
    status::{self, Status},
    usb::UsbDevice,
    worker::Worker,
};

#[cfg(feature = "pcsc")]
const INTERFACE: GUID = GUID {
    Data1: GUID_DEVINTERFACE_SMARTCARD_READER.data1,
    Data2: GUID_DEVINTERFACE_SMARTCARD_READER.data2,
    Data3: GUID_DEVINTERFACE_SMARTCARD_READER.data3,
    Data4: GUID_DEVINTERFACE_SMARTCARD_READER.data4,
};

#[cfg(feature = "usb")]
const INTERFACE: GUID = GUID {
    Data1: rcs956_usb_abi::INTERFACE.0,
    Data2: rcs956_usb_abi::INTERFACE.1,
    Data3: rcs956_usb_abi::INTERFACE.2,
    Data4: rcs956_usb_abi::INTERFACE.3,
};

struct DeviceState {
    queues: Queues,
    usb: Option<UsbDevice>,
    worker: Option<Worker>,
    /// Released with the device context at cleanup.
    #[cfg(feature = "pcsc")]
    unit: UnitLease,
}

struct ContextType(WDF_OBJECT_CONTEXT_TYPE_INFO);

// SAFETY: The descriptor is immutable and points only to static storage.
unsafe impl Sync for ContextType {}

static DEVICE_CONTEXT: ContextType = ContextType(WDF_OBJECT_CONTEXT_TYPE_INFO {
    Size: size_of::<WDF_OBJECT_CONTEXT_TYPE_INFO>() as u32,
    ContextName: c"Rcs956Device".as_ptr(),
    ContextSize: size_of::<*mut Mutex<DeviceState>>(),
    UniqueType: null(),
    EvtDriverGetUniqueContextType: None,
});

pub(crate) extern "C" fn add(_: WDFDRIVER, mut init: *mut WDFDEVICE_INIT) -> NTSTATUS {
    let mut callbacks = WDF_PNPPOWER_EVENT_CALLBACKS {
        Size: size_of::<WDF_PNPPOWER_EVENT_CALLBACKS>() as u32,
        EvtDevicePrepareHardware: Some(prepare),
        EvtDeviceReleaseHardware: Some(release),
        EvtDeviceD0Entry: Some(d0_entry),
        EvtDeviceD0Exit: Some(d0_exit),
        ..Default::default()
    };
    // SAFETY: WDF supplies the writable initialization object and copies the callback table.
    unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDeviceInitSetPnpPowerEventCallbacks,
            init,
            &mut callbacks
        )
    };
    let mut attributes = WDF_OBJECT_ATTRIBUTES {
        Size: size_of::<WDF_OBJECT_ATTRIBUTES>() as u32,
        EvtCleanupCallback: Some(cleanup),
        ExecutionLevel: _WDF_EXECUTION_LEVEL::WdfExecutionLevelPassive,
        SynchronizationScope: _WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeNone,
        ContextTypeInfo: &DEVICE_CONTEXT.0,
        ..Default::default()
    };
    let mut device = null_mut();
    // SAFETY: The initialization object is owned by this callback until creation succeeds.
    let result = unsafe {
        call_unsafe_wdf_function_binding!(WdfDeviceCreate, &mut init, &mut attributes, &mut device)
    };
    if result < 0 {
        return result;
    }
    create(device).map_or_else(|error| error.0, |()| status::SUCCESS)
}

fn create(device: WDFDEVICE) -> Result<(), Status> {
    let slot = context_slot(device);
    if slot.is_null() {
        return Err(Status(status::INSUFFICIENT_RESOURCES));
    }
    let queues = Queues::new(device)?;
    let context = Box::new(Mutex::new(DeviceState {
        queues,
        usb: None,
        worker: None,
        #[cfg(feature = "pcsc")]
        unit: UnitLease::acquire()?,
    }));
    // SAFETY: WDF allocated an aligned pointer slot. No device callback can
    // use it until device creation returns. Cleanup now owns this allocation.
    unsafe { slot.write(Box::into_raw(context)) };
    let mut config = WDF_IO_QUEUE_CONFIG {
        Size: size_of::<WDF_IO_QUEUE_CONFIG>() as u32,
        DispatchType: _WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchSequential,
        DefaultQueue: 1,
        PowerManaged: _WDF_TRI_STATE::WdfTrue,
        EvtIoDeviceControl: Some(device_control),
        ..Default::default()
    };
    // SAFETY: WDF copies the queue configuration and owns the queue.
    status::check(unsafe {
        call_unsafe_wdf_function_binding!(
            WdfIoQueueCreate,
            device,
            &mut config,
            null_mut(),
            null_mut()
        )
    })?;
    // SAFETY: The live device owns the selected application interface.
    status::check(unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDeviceCreateDeviceInterface,
            device,
            &INTERFACE,
            null()
        )
    })
}

extern "C" fn prepare(device: WDFDEVICE, _: WDFCMRESLIST, _: WDFCMRESLIST) -> NTSTATUS {
    with_state(device, |state| {
        let Some(state) = state else {
            return status::DEVICE_NOT_READY;
        };
        if state.usb.is_some() {
            return status::INVALID_DEVICE_STATE;
        }
        match UsbDevice::open(device) {
            Ok(usb) => {
                state.usb = Some(usb);
                status::SUCCESS
            }
            Err(error) => error.0,
        }
    })
}

extern "C" fn release(device: WDFDEVICE, _: WDFCMRESLIST) -> NTSTATUS {
    stop(device);
    if let Some(usb) = with_state(device, |state| state.and_then(|state| state.usb.take())) {
        usb.release();
    }
    status::SUCCESS
}

extern "C" fn d0_entry(device: WDFDEVICE, _: WDF_DEVICE_POWER_STATE) -> NTSTATUS {
    with_state(device, |state| {
        let Some(state) = state else {
            return status::DEVICE_NOT_READY;
        };
        let Some(usb) = &state.usb else {
            return status::DEVICE_NOT_READY;
        };
        let queues = state.queues;
        queues.start();
        match Worker::start(
            usb.pipes,
            queues,
            #[cfg(feature = "usb")]
            usb.release,
            #[cfg(feature = "pcsc")]
            state.unit.unit(),
        ) {
            Ok(worker) => {
                state.worker = Some(worker);
                status::SUCCESS
            }
            Err(error) => {
                queues.purge();
                super::trace(format_args!("D0 initialization: {}", super::Chain(&error)));
                error.0
            }
        }
    })
}

extern "C" fn d0_exit(device: WDFDEVICE, _: WDF_DEVICE_POWER_STATE) -> NTSTATUS {
    stop(device);
    status::SUCCESS
}

fn stop(device: WDFDEVICE) {
    let work = with_state(device, |state| {
        let state = state?;
        Some((state.worker.take()?, state.queues))
    });
    if let Some((worker, queues)) = work {
        worker.stop();
        queues.purge();
    }
}

extern "C" fn device_control(queue: WDFQUEUE, request: WDFREQUEST, _: usize, _: usize, _: u32) {
    // SAFETY: WDF supplied the live default queue for this device-control request.
    let device = unsafe { call_unsafe_wdf_function_binding!(WdfIoQueueGetDevice, queue) };
    let request = Request(request);
    let dispatch = with_state(device, |state| {
        let state = state?;
        Some((state.queues, state.worker.as_ref()?.waker()?))
    });
    let Some((queues, waker)) = dispatch else {
        request.fail(Status(status::DEVICE_NOT_READY));
        return;
    };
    match queues.submit(request) {
        Ok(()) => waker.unpark(),
        Err((request, error)) => request.fail(error),
    }
}

extern "C" fn cleanup(object: WDFOBJECT) {
    let slot = context_slot(object.cast());
    if !slot.is_null() {
        // SAFETY: The framework zeroes the slot before creation and calls
        // cleanup once, after PnP and queue dispatch have ceased.
        let context = unsafe { slot.read() };
        if !context.is_null() {
            // SAFETY: The non-null pointer was transferred by Box::into_raw in create.
            drop(unsafe { Box::from_raw(context) });
        }
    }
}

fn context_slot(device: WDFDEVICE) -> *mut *mut Mutex<DeviceState> {
    // SAFETY: The device is live and the same static descriptor supplied at creation identifies its pointer slot.
    let slot = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfObjectGetTypedContextWorker,
            device.cast(),
            &DEVICE_CONTEXT.0
        )
    };
    slot.cast()
}

fn with_state<R>(device: WDFDEVICE, call: impl FnOnce(Option<&mut DeviceState>) -> R) -> R {
    let slot = context_slot(device);
    if slot.is_null() {
        return call(None);
    }
    // SAFETY: The framework callback keeps the device live for this scope.
    let context = unsafe { slot.read().as_ref() };
    let mut state = context.and_then(|context| context.lock().ok());
    call(state.as_deref_mut())
}
