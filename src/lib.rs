//! RC-S956 reader and card protocol logic.
//!
//! Transactions are exclusive and are never automatically replayed after a transport
//! failure. A failed transaction poisons the stream until an explicit recovery.
#![no_std]
#![forbid(unsafe_code)]
// Wire fields are narrower than host sizes; every narrowing names its bound.
#![deny(clippy::cast_possible_truncation)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod falp;
pub mod felica;
pub mod isodep;
pub mod mifare;
pub mod ndef;
pub mod nfca;
pub mod nfcb;
pub mod reader;
pub mod transport;
pub mod wire;
