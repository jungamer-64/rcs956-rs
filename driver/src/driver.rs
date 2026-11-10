mod device;
#[cfg(feature = "pcsc")]
#[path = "driver/smartcard.rs"]
mod frontend;
#[cfg(feature = "usb")]
#[path = "driver/raw.rs"]
mod frontend;
#[cfg(feature = "pcsc")]
mod pcsc;
mod queue;
mod status;
#[cfg(feature = "pcsc")]
mod unit;
mod usb;
mod worker;

use core::{fmt, mem::size_of, ptr::null_mut};
use std::ffi::CString;
use wdk_sys::{
    NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, WDF_DRIVER_CONFIG, call_unsafe_wdf_function_binding,
};

// SAFETY: WDF supplies the live driver object and registry path to its unique DLL entry point.
#[cfg_attr(not(test), unsafe(export_name = "DriverEntry"))]
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "WDF invokes the exported entry point only in the driver DLL"
    )
)]
unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let mut config = WDF_DRIVER_CONFIG {
        Size: size_of::<WDF_DRIVER_CONFIG>() as u32,
        EvtDriverDeviceAdd: Some(device::add),
        ..Default::default()
    };
    // SAFETY: WDF calls this entry point with valid driver and registry objects.
    unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDriverCreate,
            driver,
            registry_path,
            null_mut(),
            &mut config,
            null_mut()
        )
    }
}

fn trace(message: fmt::Arguments<'_>) {
    if let Ok(line) = CString::new(format!("rcs956-driver: {message}\n")) {
        // SAFETY: The string is nul-terminated and valid for the call.
        unsafe { wdk_sys::windows::OutputDebugStringA(line.as_ptr()) };
    }
}
