//! Static known-answer fixtures. These verify codec behavior, not USB/RF conformance.

use rcs956_core::wire::{self, Direction, Frame, FrameError};
use serde_json::Value;
use std::{error::Error, io};

fn hex(text: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    text.split_whitespace()
        .map(|part| u8::from_str_radix(part, 16))
        .collect()
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, io::Error> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("fixture missing string {key}"),
        )
    })
}

fn number(value: &Value, key: &str) -> Result<u64, io::Error> {
    value.get(key).and_then(Value::as_u64).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("fixture missing number {key}"),
        )
    })
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], io::Error> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("fixture missing array {key}"),
            )
        })
}

fn rejection_reason(error: &FrameError) -> &'static str {
    match error {
        FrameError::Preamble => "preamble",
        FrameError::Truncated | FrameError::Length { .. } => "length",
        FrameError::PayloadTooLarge { .. } => "payload_too_large",
        FrameError::PayloadTooShort => "data_too_short",
        FrameError::LengthChecksum => "lcs",
        FrameError::DataChecksum => "dcs",
        FrameError::Postamble => "postamble",
        FrameError::Direction { .. } => "direction",
    }
}

#[test]
fn fixed_packet_vectors() -> Result<(), Box<dyn Error>> {
    let fixtures: Value = serde_json::from_str(include_str!("data/wire_vectors.json"))?;
    for case in array(&fixtures, "frames")? {
        let name = string(case, "name")?;
        let bytes = hex(string(case, "hex")?)?;
        let direction = match string(case, "direction")? {
            "host" => Direction::Host,
            "reader" => Direction::Reader,
            value => return Err(format!("unknown direction {value}: {name}").into()),
        };
        let result = wire::parse(&bytes, direction);
        match string(case, "expected")? {
            "reject" => match result {
                Err(error) => assert_eq!(
                    rejection_reason(&error),
                    string(case, "reason")?,
                    "{name}: {error}"
                ),
                Ok(frame) => return Err(format!("{name}: unexpectedly accepted {frame:?}").into()),
            },
            "ack" => assert_eq!(result?, Frame::Ack, "{name}"),
            "nak" => assert_eq!(result?, Frame::Nak, "{name}"),
            "reader_error" => assert_eq!(result?, Frame::ReaderError, "{name}"),
            format @ ("normal" | "extended") => {
                let command = u8::from_str_radix(string(case, "cc")?, 16)?;
                let expected_data = hex(string(case, "data_hex")?)?;
                let expected_extended = format == "extended";
                assert_eq!(
                    bytes.get(..5) == Some(&[0, 0, 0xff, 0xff, 0xff]),
                    expected_extended,
                    "{name}"
                );
                assert_eq!(
                    result?,
                    Frame::Data {
                        command,
                        data: &expected_data
                    },
                    "{name}"
                );
                if direction == Direction::Host {
                    assert_eq!(
                        wire::encode(command, &expected_data)?,
                        bytes,
                        "{name}: encode"
                    );
                }
                if case.get("payload_length").is_some() {
                    assert_eq!(
                        u64::try_from(expected_data.len() + 2)?,
                        number(case, "payload_length")?,
                        "{name}"
                    );
                }
                if case.get("a0_timeout_ticks").is_some() {
                    let timeout = expected_data.get(..2).ok_or("missing A0 timeout")?;
                    assert_eq!(
                        u64::from(u16::from_le_bytes([timeout[0], timeout[1]])),
                        number(case, "a0_timeout_ticks")?,
                        "{name}"
                    );
                    assert_eq!(
                        expected_data.get(2..),
                        Some(hex(string(case, "rf_hex")?)?.as_slice()),
                        "{name}"
                    );
                }
                if case.get("rf_status_masked").is_some() {
                    let status = *expected_data.first().ok_or("missing RF status")?;
                    assert_eq!(u64::from(status), number(case, "rf_status_raw")?, "{name}");
                    assert_eq!(
                        u64::from(status & 0x3f),
                        number(case, "rf_status_masked")?,
                        "{name}"
                    );
                }
            }
            other => return Err(format!("unknown expected classification {other}: {name}").into()),
        }
    }
    Ok(())
}

#[test]
fn fixed_extended_encoder_boundary() -> Result<(), FrameError> {
    let mut normal = vec![0, 0, 0xff, 0xff, 1, 0xd4, 3];
    normal.extend_from_slice(&[0; 253]);
    normal.extend_from_slice(&[0x29, 0]);
    assert_eq!(wire::encode(3, &[0; 253])?, normal);
    let mut extended = vec![0, 0, 0xff, 0xff, 0xff, 1, 0, 0xff, 0xd4, 3];
    extended.extend_from_slice(&[0; 254]);
    extended.extend_from_slice(&[0x29, 0]);
    assert_eq!(wire::encode(3, &[0; 254])?, extended);
    Ok(())
}

#[test]
fn split_and_coalesced_stream_fixtures() -> Result<(), Box<dyn Error>> {
    let fixtures: Value = serde_json::from_str(include_str!("data/wire_vectors.json"))?;
    let frames = array(&fixtures, "frames")?;
    for case in array(&fixtures, "stream_cases")? {
        let name = string(case, "name")?;
        let mut pending = Vec::new();
        let mut observed = Vec::new();
        for chunk in array(case, "chunks_hex")? {
            pending.extend_from_slice(&hex(chunk.as_str().ok_or("chunk is not a string")?)?);
            while let Some(length) = wire::frame_length(&pending)? {
                if pending.len() < length {
                    break;
                }
                let frame: Vec<u8> = pending.drain(..length).collect();
                wire::parse(&frame, Direction::Reader)?;
                observed.push(frame);
            }
        }
        assert!(pending.is_empty(), "{name}: incomplete final frame");
        let expected = array(case, "expected_frames")?
            .iter()
            .map(|frame_name| {
                let frame_name = frame_name.as_str().ok_or("frame name is not a string")?;
                let frame = frames
                    .iter()
                    .find(|frame| frame.get("name").and_then(Value::as_str) == Some(frame_name))
                    .ok_or("unknown expected frame")?;
                Ok(hex(string(frame, "hex")?)?)
            })
            .collect::<Result<Vec<Vec<u8>>, Box<dyn Error>>>()?;
        assert_eq!(observed, expected, "{name}");
    }
    Ok(())
}
