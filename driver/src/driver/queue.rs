use core::{
    mem::size_of,
    ptr::{copy_nonoverlapping, null_mut},
    slice,
};

use wdk_sys::{
    _WDF_IO_QUEUE_DISPATCH_TYPE, _WDF_REQUEST_TYPE, _WDF_TRI_STATE, WDF_IO_QUEUE_CONFIG,
    WDF_REQUEST_PARAMETERS, WDFDEVICE, WDFQUEUE, WDFREQUEST, call_unsafe_wdf_function_binding,
};

use super::status::{self, Status};

const WORK_LIMIT: u32 = 64;
#[cfg(feature = "usb")]
const MAX_INPUT: usize = rcs956_usb_abi::WORD + rcs956_usb_abi::MAX_TRANSFER;
#[cfg(feature = "pcsc")]
const MAX_INPUT: usize = super::pcsc::MAX_INPUT;

#[derive(Clone, Copy)]
pub(crate) struct Queues {
    work: WDFQUEUE,
    #[cfg(feature = "pcsc")]
    present: WDFQUEUE,
    #[cfg(feature = "pcsc")]
    absent: WDFQUEUE,
}

// SAFETY: WDF queues permit concurrent framework access. The device owns
// these handles, and joins its worker before releasing any child objects.
unsafe impl Send for Queues {}

impl Queues {
    pub(crate) fn new(device: WDFDEVICE) -> Result<Self, Status> {
        Ok(Self {
            work: manual(device)?,
            #[cfg(feature = "pcsc")]
            present: manual(device)?,
            #[cfg(feature = "pcsc")]
            absent: manual(device)?,
        })
    }

    fn all(self) -> impl IntoIterator<Item = WDFQUEUE> {
        [
            self.work,
            #[cfg(feature = "pcsc")]
            self.present,
            #[cfg(feature = "pcsc")]
            self.absent,
        ]
    }

    pub(crate) fn start(self) {
        for queue in self.all() {
            // SAFETY: These device-owned queues are restarted on D0 entry.
            unsafe { call_unsafe_wdf_function_binding!(WdfIoQueueStart, queue) };
        }
    }

    pub(crate) fn purge(self) {
        for queue in self.all() {
            // SAFETY: The worker has stopped and no request is held outside the queues.
            unsafe { call_unsafe_wdf_function_binding!(WdfIoQueuePurgeSynchronously, queue) };
        }
    }

    pub(crate) fn submit(self, request: Request) -> Result<(), (Request, Status)> {
        if queued(self.work) >= WORK_LIMIT {
            return Err((request, Status(status::DEVICE_BUSY)));
        }
        request.forward(self.work)
    }

    pub(crate) fn pop(self) -> Option<Request> {
        pop(self.work)
    }

    #[cfg(feature = "pcsc")]
    pub(crate) fn watch(self, request: Request, present: bool) {
        let queue = if present { self.present } else { self.absent };
        if queued(queue) != 0 {
            request.fail(Status(status::DEVICE_BUSY));
        } else if let Err((request, error)) = request.forward(queue) {
            request.fail(error);
        }
    }

    #[cfg(feature = "pcsc")]
    pub(crate) fn signal(self, present: bool) {
        let queue = if present { self.present } else { self.absent };
        while let Some(request) = pop(queue) {
            request.reply(&[]);
        }
    }

    #[cfg(feature = "pcsc")]
    pub(crate) fn fail_watches(self, error: Status) {
        for queue in [self.present, self.absent] {
            while let Some(request) = pop(queue) {
                request.fail(error);
            }
        }
    }
}

fn manual(device: WDFDEVICE) -> Result<WDFQUEUE, Status> {
    let mut config = WDF_IO_QUEUE_CONFIG {
        Size: size_of::<WDF_IO_QUEUE_CONFIG>() as u32,
        DispatchType: _WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchManual,
        PowerManaged: _WDF_TRI_STATE::WdfFalse,
        ..Default::default()
    };
    let mut queue = null_mut();
    // SAFETY: The live parent device owns the new manual queue.
    status::check(unsafe {
        call_unsafe_wdf_function_binding!(
            WdfIoQueueCreate,
            device,
            &mut config,
            null_mut(),
            &mut queue
        )
    })?;
    Ok(queue)
}

fn queued(queue: WDFQUEUE) -> u32 {
    let mut count = 0;
    // The return value is queue state flags. Admission uses its queued count.
    // SAFETY: The device-owned queue is live and the output pointer is writable.
    let _state = unsafe {
        call_unsafe_wdf_function_binding!(WdfIoQueueGetState, queue, &mut count, null_mut())
    };
    count
}

fn pop(queue: WDFQUEUE) -> Option<Request> {
    let mut request = null_mut();
    // SAFETY: WDF transfers ownership of a live request on successful retrieval.
    let result = unsafe {
        call_unsafe_wdf_function_binding!(WdfIoQueueRetrieveNextRequest, queue, &mut request)
    };
    (result >= 0).then_some(Request(request))
}

/// A request owned by one dispatch callback or the worker. Forwarding
/// transfers cancellation and completion back to WDF until retrieval.
pub(crate) struct Request(pub(crate) WDFREQUEST);

impl Request {
    pub(crate) fn decode(&self) -> Result<(u32, Vec<u8>, usize), Status> {
        let mut params = WDF_REQUEST_PARAMETERS {
            Size: size_of::<WDF_REQUEST_PARAMETERS>() as u16,
            ..Default::default()
        };
        // SAFETY: The request is owned by this worker and the output is writable.
        unsafe { call_unsafe_wdf_function_binding!(WdfRequestGetParameters, self.0, &mut params) };
        if params.Type != _WDF_REQUEST_TYPE::WdfRequestTypeDeviceControl {
            return Err(Status(status::INVALID_DEVICE_REQUEST));
        }
        // SAFETY: The checked request type identifies this union member.
        let control = unsafe { params.Parameters.DeviceIoControl };
        let length = control.InputBufferLength;
        if length > MAX_INPUT {
            return Err(Status(status::INVALID_BUFFER_SIZE));
        }
        let input = if length == 0 {
            Vec::new()
        } else {
            let mut buffer = null_mut();
            // SAFETY: The request retains the input buffer until it is completed or forwarded.
            status::check(unsafe {
                call_unsafe_wdf_function_binding!(
                    WdfRequestRetrieveInputBuffer,
                    self.0,
                    length,
                    &mut buffer,
                    null_mut()
                )
            })?;
            // SAFETY: WDF just validated the minimum size. Copy before accessing
            // the output because buffered IOCTLs can share the same memory.
            unsafe { slice::from_raw_parts(buffer.cast::<u8>(), length) }.to_vec()
        };
        Ok((control.IoControlCode, input, control.OutputBufferLength))
    }

    pub(crate) fn reply(self, data: &[u8]) {
        if !data.is_empty() {
            let mut buffer = null_mut();
            // SAFETY: The framework checks the output buffer's writable size.
            let result = unsafe {
                call_unsafe_wdf_function_binding!(
                    WdfRequestRetrieveOutputBuffer,
                    self.0,
                    data.len(),
                    &mut buffer,
                    null_mut()
                )
            };
            if result < 0 {
                self.fail(Status(result));
                return;
            }
            // SAFETY: The source is owned independently of the request and WDF validated the destination length.
            unsafe { copy_nonoverlapping(data.as_ptr(), buffer.cast::<u8>(), data.len()) };
        }
        // SAFETY: This is the single completion of the owned request.
        unsafe {
            call_unsafe_wdf_function_binding!(
                WdfRequestCompleteWithInformation,
                self.0,
                status::SUCCESS,
                data.len() as _
            )
        };
    }

    pub(crate) fn fail(self, error: Status) {
        // SAFETY: This is the single completion of the owned request.
        unsafe { call_unsafe_wdf_function_binding!(WdfRequestComplete, self.0, error.0) };
    }

    fn forward(self, queue: WDFQUEUE) -> Result<(), (Self, Status)> {
        // SAFETY: The worker or callback owns the request and the destination is on the same device.
        match status::check(unsafe {
            call_unsafe_wdf_function_binding!(WdfRequestForwardToIoQueue, self.0, queue)
        }) {
            Ok(()) => Ok(()),
            Err(error) => Err((self, error)),
        }
    }
}
