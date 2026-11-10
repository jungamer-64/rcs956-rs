use core::ptr::null;

use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, GetLastError, HANDLE},
    System::Threading::{CreateMutexExW, SYNCHRONIZATION_SYNCHRONIZE},
};

use super::status::{self, Status};

/// Units probed before device creation fails.
const UNITS: u32 = 256;

/// Exclusive claim on one `SCARD_ATTR_DEVICE_UNIT` value. The resource manager
/// names readers from vendor, type and unit, so each live reader of this
/// driver holds the lowest unit not claimed by another, in any host process.
/// A named kernel object is the claim; closing its handle, including at
/// process termination, releases the unit for the next reader.
pub(crate) struct UnitLease {
    unit: u32,
    handle: HANDLE,
}

impl UnitLease {
    pub(crate) fn acquire() -> Result<Self, Status> {
        for unit in 0..UNITS {
            let name: Vec<u16> = format!("Global\\rcs956-rs-pcsc-unit-{unit}")
                .encode_utf16()
                .chain([0])
                .collect();
            // SAFETY: The name is NUL-terminated and outlives the call. Null
            // attributes select the default security of the host token.
            let handle =
                unsafe { CreateMutexExW(null(), name.as_ptr(), 0, SYNCHRONIZATION_SYNCHRONIZE) };
            // SAFETY: Reads this thread's error from the preceding call.
            let error = unsafe { GetLastError() };
            if handle.is_null() {
                // Another principal's object denies us access: the unit is taken.
                if error == ERROR_ACCESS_DENIED {
                    continue;
                }
                return Err(Status(status::INSUFFICIENT_RESOURCES));
            }
            let lease = Self { unit, handle };
            if error != ERROR_ALREADY_EXISTS {
                return Ok(lease);
            }
        }
        Err(Status(status::INSUFFICIENT_RESOURCES))
    }

    pub(crate) fn unit(&self) -> u32 {
        self.unit
    }
}

impl Drop for UnitLease {
    fn drop(&mut self) {
        // SAFETY: The lease owns this handle and closes it once. A close
        // failure leaves nothing to recover; the claim ends with the process.
        unsafe { CloseHandle(self.handle) };
    }
}
