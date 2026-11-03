//! RC-S956 reader communication, with separate USB, frame, and FeliCa boundaries.
//!
//! Transactions are exclusive and are never automatically replayed after a transport
//! failure. A failed transaction poisons the stream until an explicit recovery.
#![deny(unsafe_code)]

pub mod felica;
pub mod reader;
pub mod transport;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Windows USB and device enumeration ABI is isolated in this module"
)]
pub mod windows;
pub mod wire;
