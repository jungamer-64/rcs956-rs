//! RC-S956 UMDF 2 USB or smart card reader driver.

#[cfg(not(any(feature = "usb", feature = "pcsc")))]
compile_error!("select one driver interface with --features usb or --features pcsc");
#[cfg(all(feature = "usb", feature = "pcsc"))]
compile_error!("usb and pcsc are mutually exclusive driver interfaces");

#[cfg(any(
    all(feature = "usb", not(feature = "pcsc")),
    all(feature = "pcsc", not(feature = "usb"))
))]
mod driver;
