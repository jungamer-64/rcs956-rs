//! RC-S956 reader and card protocol logic.
//!
//! Transactions are exclusive and are never automatically replayed after a transport
//! failure. A failed transaction poisons the stream until an explicit recovery.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod felica;
pub mod isodep;
pub mod mifare;
pub mod ndef;
pub mod nfca;
pub mod nfcb;
pub mod reader;
pub mod transport;
pub mod wire;
