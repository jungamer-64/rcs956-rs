//! Host binding for RC-S956 device discovery and synchronous USB transfers.
#![deny(unsafe_code)]

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Windows USB and device enumeration ABI is isolated in this module"
)]
pub mod windows;
