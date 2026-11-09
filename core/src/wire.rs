//! Bounded RC-S956 host frames, independent of USB transfer boundaries.
//!
//! A successful decode establishes frame integrity, not command completion.
//! Transaction code must still match the response command to its request.

use alloc::vec::Vec;
use core::fmt;

/// Largest frame accepted by this RC-S956 profile, including its envelope.
pub const MAX_FRAME: usize = 275;
/// Largest payload, including direction and command, accepted by this profile.
pub const MAX_PAYLOAD: usize = 265;
/// Transport acknowledgement; this does not mean that a card operation succeeded.
pub const ACK: [u8; 6] = [0, 0, 0xff, 0, 0xff, 0];
/// Transport negative acknowledgement.
pub const NAK: [u8; 6] = [0, 0, 0xff, 0xff, 0, 0];
const READER_ERROR: [u8; 8] = [0, 0, 0xff, 1, 0xff, 0x7f, 0x81, 0];

/// Sender whose direction byte a data frame must contain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Host command, direction byte `D4`.
    Host,
    /// Reader response, direction byte `D5`.
    Reader,
}

impl Direction {
    fn byte(self) -> u8 {
        match self {
            Self::Host => 0xd4,
            Self::Reader => 0xd5,
        }
    }
}

/// Verified frame with its direction and checksum envelope removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Frame<'a> {
    /// Reader transport accepted a frame.
    Ack,
    /// Reader returned a transport negative acknowledgement.
    Nak,
    /// Reader returned the special `7F` error frame.
    ReaderError,
    /// Command or response payload, excluding the direction byte.
    Data {
        /// Request or response command byte.
        command: u8,
        /// Command-specific bytes; these do not universally start with status.
        data: &'a [u8],
    },
}

/// Frame integrity or profile-size failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// Input does not start with `00 00 FF`.
    Preamble,
    /// More bytes are needed to establish or complete the frame.
    Truncated,
    /// A complete single-frame decode received the wrong total length.
    Length {
        /// Number of bytes required by the header.
        expected: usize,
        /// Number of supplied bytes.
        actual: usize,
    },
    /// Payload exceeds the RC-S956 profile limit.
    PayloadTooLarge {
        /// Rejected payload size, including direction and command.
        length: usize,
    },
    /// Data lacks a direction or command byte.
    PayloadTooShort,
    /// Length checksum is invalid.
    LengthChecksum,
    /// Payload checksum is invalid.
    DataChecksum,
    /// Postamble is not zero.
    Postamble,
    /// Direction does not match the expected sender.
    Direction {
        /// Required direction byte.
        expected: u8,
        /// Direction byte found in the payload.
        actual: u8,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preamble => f.write_str("invalid frame preamble"),
            Self::Truncated => f.write_str("incomplete frame"),
            Self::Length { expected, actual } => {
                write!(f, "frame length {actual}, expected {expected}")
            }
            Self::PayloadTooLarge { length } => {
                write!(f, "payload length {length} exceeds {MAX_PAYLOAD}")
            }
            Self::PayloadTooShort => f.write_str("data frame has no direction or command"),
            Self::LengthChecksum => f.write_str("invalid length checksum"),
            Self::DataChecksum => f.write_str("invalid data checksum"),
            Self::Postamble => f.write_str("invalid postamble"),
            Self::Direction { expected, actual } => {
                write!(f, "direction {actual:02X}, expected {expected:02X}")
            }
        }
    }
}

impl core::error::Error for FrameError {}

/// Encode a host command, choosing normal or extended format by payload length.
///
/// # Errors
///
/// Returns [`FrameError::PayloadTooLarge`] when direction, command and arguments
/// would exceed 265 bytes. No transport action occurs here.
pub fn encode(command: u8, args: &[u8]) -> Result<Vec<u8>, FrameError> {
    let length = args
        .len()
        .checked_add(2)
        .ok_or(FrameError::PayloadTooLarge { length: args.len() })?;
    if length > MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge { length });
    }
    let mut bytes = Vec::with_capacity(length + 10);
    bytes.extend_from_slice(&[0, 0, 0xff]);
    if let Ok(short) = u8::try_from(length) {
        bytes.extend_from_slice(&[short, short.wrapping_neg()]);
    } else {
        let [high, low] = u16::try_from(length)
            .map_err(|_| FrameError::PayloadTooLarge { length })?
            .to_be_bytes();
        bytes.extend_from_slice(&[0xff, 0xff, high, low, high.wrapping_add(low).wrapping_neg()]);
    }
    bytes.extend_from_slice(&[0xd4, command]);
    bytes.extend_from_slice(args);
    let sum = args
        .iter()
        .fold(0xd4_u8.wrapping_add(command), |sum, byte| {
            sum.wrapping_add(*byte)
        });
    bytes.extend_from_slice(&[sum.wrapping_neg(), 0]);
    Ok(bytes)
}

/// Establish the first frame's total length from a possibly partial stream.
///
/// `None` means that more header bytes are needed. `Some(n)` can be returned
/// before all `n` bytes arrive; it does not establish payload integrity. Bytes
/// after that first frame belong to the stream owner.
///
/// # Errors
///
/// Rejects an invalid preamble, length checksum or oversized payload. The special
/// error frame's one-byte payload is left for [`parse`] to classify.
pub fn frame_length(input: &[u8]) -> Result<Option<usize>, FrameError> {
    if input.iter().zip([0, 0, 0xff]).take(3).any(|(a, b)| *a != b) {
        return Err(FrameError::Preamble);
    }
    let Some(header) = input.get(..5) else {
        return Ok(None);
    };
    if header == &ACK[..5] || header == &NAK[..5] {
        return Ok(Some(6));
    }
    let (payload, overhead) = if header[3..] == [0xff, 0xff] {
        let Some(extended) = input.get(..8) else {
            return Ok(None);
        };
        if extended[5]
            .wrapping_add(extended[6])
            .wrapping_add(extended[7])
            != 0
        {
            return Err(FrameError::LengthChecksum);
        }
        (
            usize::from(u16::from_be_bytes([extended[5], extended[6]])),
            10,
        )
    } else {
        if header[3].wrapping_add(header[4]) != 0 {
            return Err(FrameError::LengthChecksum);
        }
        (usize::from(header[3]), 7)
    };
    if payload > MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge { length: payload });
    }
    if payload == 0 {
        return Err(FrameError::PayloadTooShort);
    }
    Ok(Some(payload + overhead))
}

/// Decode exactly one complete frame, verifying checksums and direction.
///
/// # Errors
///
/// Returns the specific integrity error. Extra trailing bytes are a length
/// failure; split or coalesced USB reads must first be framed by the stream owner.
pub fn parse(input: &[u8], direction: Direction) -> Result<Frame<'_>, FrameError> {
    let expected = frame_length(input)?.ok_or(FrameError::Truncated)?;
    if input.len() != expected {
        return Err(FrameError::Length {
            expected,
            actual: input.len(),
        });
    }
    if input.last() != Some(&0) {
        return Err(FrameError::Postamble);
    }
    if input == ACK {
        return Ok(Frame::Ack);
    }
    if input == NAK {
        return Ok(Frame::Nak);
    }
    if input == READER_ERROR {
        return Ok(Frame::ReaderError);
    }
    let start = if input.get(..5) == Some(&[0, 0, 0xff, 0xff, 0xff]) {
        8
    } else {
        5
    };
    let payload = input
        .get(start..input.len() - 2)
        .ok_or(FrameError::PayloadTooShort)?;
    if payload.len() < 2 {
        return Err(FrameError::PayloadTooShort);
    }
    let checksum = input
        .get(input.len() - 2)
        .copied()
        .ok_or(FrameError::Truncated)?;
    if payload
        .iter()
        .fold(checksum, |sum, byte| sum.wrapping_add(*byte))
        != 0
    {
        return Err(FrameError::DataChecksum);
    }
    let actual = payload[0];
    if actual != direction.byte() {
        return Err(FrameError::Direction {
            expected: direction.byte(),
            actual,
        });
    }
    Ok(Frame::Data {
        command: payload[1],
        data: &payload[2..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn known_firmware_and_poll_commands() -> Result<(), FrameError> {
        assert_eq!(encode(2, &[])?, [0, 0, 0xff, 2, 0xfe, 0xd4, 2, 0x2a, 0]);
        assert_eq!(
            encode(0xa0, &[0xc8, 0, 6, 0, 0xff, 0xff, 0, 0])?,
            [
                0, 0, 0xff, 0x0a, 0xf6, 0xd4, 0xa0, 0xc8, 0, 6, 0, 0xff, 0xff, 0, 0, 0xc0, 0
            ]
        );
        Ok(())
    }

    #[test]
    fn length_boundary_vectors() -> Result<(), FrameError> {
        let mut normal = vec![0, 0, 0xff, 0xff, 1, 0xd5, 3];
        normal.extend_from_slice(&[0; 253]);
        normal.extend_from_slice(&[0x28, 0]);
        assert_eq!(
            parse(&normal, Direction::Reader)?,
            Frame::Data {
                command: 3,
                data: &[0; 253]
            }
        );
        let mut extended = vec![0, 0, 0xff, 0xff, 0xff, 1, 0, 0xff, 0xd5, 3];
        extended.extend_from_slice(&[0; 254]);
        extended.extend_from_slice(&[0x28, 0]);
        assert_eq!(
            parse(&extended, Direction::Reader)?,
            Frame::Data {
                command: 3,
                data: &[0; 254]
            }
        );
        assert_eq!(encode(3, &[0; 254])?.len(), 266);
        assert!(matches!(
            encode(3, &[0; 264]),
            Err(FrameError::PayloadTooLarge { length: 266 })
        ));
        Ok(())
    }

    #[test]
    fn special_frames_and_partial_streams() -> Result<(), FrameError> {
        assert_eq!(parse(&ACK, Direction::Reader)?, Frame::Ack);
        assert_eq!(parse(&NAK, Direction::Reader)?, Frame::Nak);
        assert_eq!(parse(&READER_ERROR, Direction::Reader)?, Frame::ReaderError);
        assert_eq!(frame_length(&ACK[..3])?, None);
        assert_eq!(frame_length(&ACK[..5])?, Some(6));
        assert_eq!(frame_length(&[0, 0, 0xff, 0xff, 0xff, 1])?, None);
        Ok(())
    }

    #[test]
    fn rejects_integrity_errors_and_wrong_direction() {
        let packet = [0, 0, 0xff, 2, 0xfe, 0xd4, 2, 0x2a, 0];
        assert_eq!(
            parse(&packet, Direction::Reader),
            Err(FrameError::Direction {
                expected: 0xd5,
                actual: 0xd4
            })
        );
        let mut bad = packet;
        bad[7] = 0x2b;
        assert_eq!(parse(&bad, Direction::Host), Err(FrameError::DataChecksum));
        bad = packet;
        bad[4] = 0xfd;
        assert_eq!(
            parse(&bad, Direction::Host),
            Err(FrameError::LengthChecksum)
        );
        assert!(matches!(
            parse(&packet[..8], Direction::Host),
            Err(FrameError::Length {
                expected: 9,
                actual: 8
            })
        ));
        assert_eq!(
            parse(&[0, 0, 0xff, 1, 0xff, 0xd5, 0x2b, 0], Direction::Reader),
            Err(FrameError::PayloadTooShort)
        );
    }
}
