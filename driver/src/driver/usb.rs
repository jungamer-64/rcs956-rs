use core::{ffi::c_void, fmt, mem::size_of, ptr::null_mut, time::Duration};
use std::{rc::Rc, time::Instant};

use rcs956::transport::Transport;
use wdk_sys::{
    _WDF_MEMORY_DESCRIPTOR__bindgen_ty_1, _WDF_MEMORY_DESCRIPTOR__bindgen_ty_1__bindgen_ty_1,
    _WDF_MEMORY_DESCRIPTOR_TYPE, _WDF_REQUEST_SEND_OPTIONS_FLAGS, _WDF_USB_PIPE_TYPE,
    _WdfUsbTargetDeviceSelectConfigType, USB_DEVICE_DESCRIPTOR, USBD_CLIENT_CONTRACT_VERSION_602,
    WDF_MEMORY_DESCRIPTOR, WDF_REQUEST_SEND_OPTIONS, WDF_USB_DEVICE_CREATE_CONFIG,
    WDF_USB_DEVICE_SELECT_CONFIG_PARAMS, WDF_USB_PIPE_INFORMATION, WDFDEVICE, WDFUSBDEVICE,
    WDFUSBPIPE, call_unsafe_wdf_function_binding,
};

use super::{
    status::{self, Status},
    worker::Control,
};

const PACKET_SIZE: usize = 64;

pub(crate) struct UsbDevice {
    device: WDFUSBDEVICE,
    pub(crate) pipes: Pipes,
    /// `bcdDevice` of the descriptor validated when the target was opened.
    #[cfg_attr(
        feature = "pcsc",
        expect(
            dead_code,
            reason = "only the USB interface publishes the device release"
        )
    )]
    pub(crate) release: u16,
}

// SAFETY: The framework handle is used by serialized PnP callbacks. Its
// pipes remain live until the D0 worker has been joined.
unsafe impl Send for UsbDevice {}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Pipes {
    input: WDFUSBPIPE,
    output: WDFUSBPIPE,
}

// SAFETY: WDF pipe handles can be used on the passive worker thread. PnP
// joins that thread before deleting the parent USB device and its pipes.
unsafe impl Send for Pipes {}

impl UsbDevice {
    pub(crate) fn open(parent: WDFDEVICE) -> Result<Self, Status> {
        let mut config = WDF_USB_DEVICE_CREATE_CONFIG {
            Size: size_of::<WDF_USB_DEVICE_CREATE_CONFIG>() as u32,
            USBDClientContractVersion: USBD_CLIENT_CONTRACT_VERSION_602,
        };
        let mut device = null_mut();
        // SAFETY: PrepareHardware supplies the live framework device.
        status::check(unsafe {
            call_unsafe_wdf_function_binding!(
                WdfUsbTargetDeviceCreateWithParameters,
                parent,
                &mut config,
                null_mut(),
                &mut device
            )
        })?;
        match Self::select(device) {
            Ok((pipes, release)) => Ok(Self {
                device,
                pipes,
                release,
            }),
            Err(error) => {
                delete(device);
                Err(error)
            }
        }
    }

    fn select(device: WDFUSBDEVICE) -> Result<(Pipes, u16), Status> {
        let mut descriptor = USB_DEVICE_DESCRIPTOR::default();
        // SAFETY: The USB target owns a descriptor and writes it into this buffer.
        unsafe {
            call_unsafe_wdf_function_binding!(
                WdfUsbTargetDeviceGetDeviceDescriptor,
                device,
                &mut descriptor
            );
        }
        if (descriptor.idVendor, descriptor.idProduct) != (0x054c, 0x02e1) {
            return Err(Status(status::DEVICE_CONFIGURATION_ERROR));
        }
        let mut select = WDF_USB_DEVICE_SELECT_CONFIG_PARAMS {
            Size: size_of::<WDF_USB_DEVICE_SELECT_CONFIG_PARAMS>() as u32,
            Type: _WdfUsbTargetDeviceSelectConfigType::WdfUsbTargetDeviceSelectConfigTypeSingleInterface,
            ..Default::default()
        };
        // SAFETY: The device is live and the input discriminant selects the single-interface union member.
        status::check(unsafe {
            call_unsafe_wdf_function_binding!(
                WdfUsbTargetDeviceSelectConfig,
                device,
                null_mut(),
                &mut select
            )
        })?;
        // SAFETY: Successful single-interface selection initializes this union member.
        let setting = unsafe { select.Types.SingleInterface };
        let mut input = None;
        let mut output = None;
        for index in 0..setting.NumberConfiguredPipes {
            let mut info = WDF_USB_PIPE_INFORMATION {
                Size: size_of::<WDF_USB_PIPE_INFORMATION>() as u32,
                ..Default::default()
            };
            // SAFETY: WDF returned the interface handle and the index is within its configured pipes.
            let pipe = unsafe {
                call_unsafe_wdf_function_binding!(
                    WdfUsbInterfaceGetConfiguredPipe,
                    setting.ConfiguredUsbInterface,
                    index,
                    &mut info
                )
            };
            if pipe.is_null() || info.PipeType != _WDF_USB_PIPE_TYPE::WdfUsbPipeTypeBulk {
                continue;
            }
            if info.MaximumPacketSize != PACKET_SIZE as u32 {
                return Err(Status(status::DEVICE_CONFIGURATION_ERROR));
            }
            let slot = if info.EndpointAddress & 0x80 != 0 {
                &mut input
            } else {
                &mut output
            };
            if slot.replace(pipe).is_some() {
                return Err(Status(status::DEVICE_CONFIGURATION_ERROR));
            }
        }
        let (Some(input), Some(output)) = (input, output) else {
            return Err(Status(status::DEVICE_CONFIGURATION_ERROR));
        };
        // SAFETY: WDF owns the input pipe. Transport provides the bounded receive buffer.
        unsafe {
            call_unsafe_wdf_function_binding!(WdfUsbTargetPipeSetNoMaximumPacketSizeCheck, input)
        };
        Ok((Pipes { input, output }, descriptor.bcdDevice))
    }

    pub(crate) fn release(self) {
        delete(self.device);
    }
}

fn delete(device: WDFUSBDEVICE) {
    // SAFETY: The caller transfers its unique USB target ownership after all I/O has ended.
    unsafe { call_unsafe_wdf_function_binding!(WdfObjectDelete, device.cast()) };
}

pub(crate) struct UsbTransport {
    pipes: Pipes,
    epoch: Instant,
    control: Rc<Control>,
}

impl fmt::Debug for UsbTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsbTransport").finish_non_exhaustive()
    }
}

impl UsbTransport {
    pub(crate) fn new(pipes: Pipes, control: Rc<Control>) -> Self {
        Self {
            pipes,
            epoch: Instant::now(),
            control,
        }
    }

    fn timeout(&self, requested: Duration) -> Result<WDF_REQUEST_SEND_OPTIONS, Status> {
        let wait = self.control.wait_budget(requested)?;
        if wait.is_zero() {
            return Err(Status(status::IO_TIMEOUT));
        }
        // WDF uses a negative relative count of 100 ns units. Round up
        // because a zero timeout has different semantics at this boundary.
        let ticks = wait.as_nanos().div_ceil(100).min(i64::MAX as u128) as i64;
        Ok(WDF_REQUEST_SEND_OPTIONS {
            Size: size_of::<WDF_REQUEST_SEND_OPTIONS>() as u32,
            Flags: _WDF_REQUEST_SEND_OPTIONS_FLAGS::WDF_REQUEST_SEND_OPTION_TIMEOUT as u32,
            Timeout: -ticks,
        })
    }

    fn write_pipe(&self, data: &[u8], timeout: Duration) -> Result<usize, Status> {
        let mut options = self.timeout(timeout)?;
        let placeholder = 0u8;
        let source = if data.is_empty() {
            &raw const placeholder
        } else {
            data.as_ptr()
        };
        let mut memory = buffer(source.cast_mut().cast(), data.len())?;
        let mut count = 0;
        // SAFETY: The synchronous request reads the valid buffer and finishes using it before returning.
        status::check(unsafe {
            call_unsafe_wdf_function_binding!(
                WdfUsbTargetPipeWriteSynchronously,
                self.pipes.output,
                null_mut(),
                &mut options,
                &mut memory,
                &mut count
            )
        })?;
        Ok(count as usize)
    }
}

impl Transport for UsbTransport {
    type Error = Status;

    fn monotonic_time(&self) -> Duration {
        self.epoch.elapsed()
    }

    fn wait(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn write(&mut self, data: &[u8], timeout: Duration) -> Result<usize, Status> {
        let start = Instant::now();
        let count = self.write_pipe(data, timeout)?;
        if count == data.len() && !data.is_empty() && data.len().is_multiple_of(PACKET_SIZE) {
            let zlp = self.write_pipe(&[], timeout.saturating_sub(start.elapsed()))?;
            if zlp != 0 {
                return Err(Status(status::DEVICE_PROTOCOL_ERROR));
            }
        }
        Ok(count)
    }

    fn read(&mut self, data: &mut [u8], timeout: Duration) -> Result<usize, Status> {
        let mut options = self.timeout(timeout)?;
        let mut memory = buffer(data.as_mut_ptr().cast(), data.len())?;
        let mut count = 0;
        // SAFETY: The synchronous request writes within the exclusive buffer and finishes before returning.
        status::check(unsafe {
            call_unsafe_wdf_function_binding!(
                WdfUsbTargetPipeReadSynchronously,
                self.pipes.input,
                null_mut(),
                &mut options,
                &mut memory,
                &mut count
            )
        })?;
        Ok(count as usize)
    }

    fn recover(&mut self) -> Result<(), Status> {
        for pipe in [self.pipes.input, self.pipes.output] {
            let mut options = self.timeout(Duration::from_secs(1))?;
            // SAFETY: Only this worker owns outstanding I/O, and no transfer is outstanding here.
            status::check(unsafe {
                call_unsafe_wdf_function_binding!(
                    WdfUsbTargetPipeResetSynchronously,
                    pipe,
                    null_mut(),
                    &mut options
                )
            })?;
        }
        Ok(())
    }
}

fn buffer(ptr: *mut c_void, length: usize) -> Result<WDF_MEMORY_DESCRIPTOR, Status> {
    let length = u32::try_from(length).map_err(|_| Status(status::INVALID_BUFFER_SIZE))?;
    Ok(WDF_MEMORY_DESCRIPTOR {
        Type: _WDF_MEMORY_DESCRIPTOR_TYPE::WdfMemoryDescriptorTypeBuffer,
        u: _WDF_MEMORY_DESCRIPTOR__bindgen_ty_1 {
            BufferType: _WDF_MEMORY_DESCRIPTOR__bindgen_ty_1__bindgen_ty_1 {
                Buffer: ptr,
                Length: length,
            },
        },
    })
}
