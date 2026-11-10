use core::fmt;

pub(crate) use windows_sys::Win32::Foundation::{
    STATUS_BUFFER_TOO_SMALL as BUFFER_TOO_SMALL, STATUS_CANCELLED as CANCELLED,
    STATUS_DEVICE_BUSY as DEVICE_BUSY,
    STATUS_DEVICE_CONFIGURATION_ERROR as DEVICE_CONFIGURATION_ERROR,
    STATUS_DEVICE_NOT_READY as DEVICE_NOT_READY,
    STATUS_DEVICE_PROTOCOL_ERROR as DEVICE_PROTOCOL_ERROR,
    STATUS_INSUFFICIENT_RESOURCES as INSUFFICIENT_RESOURCES,
    STATUS_INVALID_BUFFER_SIZE as INVALID_BUFFER_SIZE,
    STATUS_INVALID_DEVICE_REQUEST as INVALID_DEVICE_REQUEST,
    STATUS_INVALID_DEVICE_STATE as INVALID_DEVICE_STATE,
    STATUS_INVALID_PARAMETER as INVALID_PARAMETER, STATUS_IO_TIMEOUT as IO_TIMEOUT,
    STATUS_NOT_SUPPORTED as NOT_SUPPORTED, STATUS_SUCCESS as SUCCESS,
};

#[cfg(feature = "pcsc")]
pub(crate) use windows_sys::Win32::Foundation::STATUS_NO_MEDIA as NO_MEDIA;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Status(pub(crate) i32);

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NTSTATUS {:#010x}", self.0 as u32)
    }
}

impl core::error::Error for Status {}

pub(crate) fn check(value: i32) -> Result<(), Status> {
    if value >= 0 {
        Ok(())
    } else {
        Err(Status(value))
    }
}
