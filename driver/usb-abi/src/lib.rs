//! Buffered IOCTL contract between the exclusive USB client and the UMDF driver.
#![no_std]

use core::time::Duration;

/// Private application interface registered by the USB build.
pub const INTERFACE: (u32, u16, u16, [u8; 8]) = (
    0xf73a_a175,
    0x0e9f,
    0x4c84,
    [0xa2, 0x7b, 0x35, 0x0e, 0x7c, 0xb0, 0xd3, 0x45],
);

const DEVICE_TYPE: u32 = 0x8000;

const fn ioctl(function: u32) -> u32 {
    // Vendor device type, buffered I/O, read and write handle access.
    (DEVICE_TYPE << 16) | (3 << 14) | (function << 2)
}

/// Write one bulk transfer. Input is a timeout followed by bytes.
/// Output is a little-endian u32 count of completed bytes.
pub const WRITE: u32 = ioctl(0x800);
/// Read one bulk transfer. Input is a timeout. Output capacity is the
/// requested length, and the completion count is the received length.
pub const READ: u32 = ioctl(0x801);
/// Reset both USB pipes. Input and output are empty.
pub const RECOVER: u32 = ioctl(0x802);
/// Maximum USB transfer size admitted by this interface, in bytes.
pub const MAX_TRANSFER: usize = 4096;
/// Encoded timeout and write completion count size, in bytes.
pub const WORD: usize = 4;

const MAX_TIMEOUT_MS: u32 = 60_000;

/// Encode a positive, bounded timeout as little-endian milliseconds.
pub fn encode_timeout(wait: Duration) -> Option<[u8; WORD]> {
    let milliseconds = u32::try_from(wait.as_nanos().div_ceil(1_000_000)).ok()?;
    valid(milliseconds).then(|| milliseconds.to_le_bytes())
}

/// Decode the timeout header and return the remaining request body.
pub fn decode_timeout(input: &[u8]) -> Option<(Duration, &[u8])> {
    let (encoded, body) = input.split_first_chunk::<WORD>()?;
    let milliseconds = u32::from_le_bytes(*encoded);
    valid(milliseconds).then(|| (Duration::from_millis(u64::from(milliseconds)), body))
}

fn valid(milliseconds: u32) -> bool {
    (1..=MAX_TIMEOUT_MS).contains(&milliseconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_encoding_matches_wire_and_bounds() {
        assert_eq!(encode_timeout(Duration::from_nanos(1)), Some([1, 0, 0, 0]));
        assert_eq!(encode_timeout(Duration::ZERO), None);
        assert_eq!(
            encode_timeout(Duration::from_secs(60)),
            Some([0x60, 0xea, 0, 0])
        );
        assert_eq!(encode_timeout(Duration::from_millis(60_001)), None);
        assert_eq!(
            decode_timeout(&[0xe8, 3, 0, 0, 0xaa]),
            Some((Duration::from_secs(1), &[0xaa][..]))
        );
        assert_eq!(decode_timeout(&[0, 0, 0, 0]), None);
        assert_eq!(decode_timeout(&[0x61, 0xea, 0, 0]), None);
        assert_eq!(decode_timeout(&[1, 0, 0]), None);
    }
}
