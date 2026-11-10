use alloc::{borrow::Cow, vec::Vec};
use core::fmt;

/// An NDEF message with record chunks assembled in wire order.
#[derive(Debug, Eq, PartialEq)]
pub struct Message<'a> {
    records: Vec<Record<'a>>,
}

/// One logical record. Type names, IDs and unchunked payloads borrow the input.
#[derive(Debug, Eq, PartialEq)]
pub struct Record<'a> {
    /// The type name and its format, when present.
    pub record_type: RecordType<'a>,
    /// The optional URI-reference identifier as stored.
    pub id: Option<&'a [u8]>,
    /// Application payload. Interpretation depends on the record type.
    pub payload: Cow<'a, [u8]>,
}

/// Type Name Format and, for formats that carry it, the type name.
#[derive(Debug, Eq, PartialEq)]
pub enum RecordType<'a> {
    /// The empty record carries no type, ID or payload.
    Empty,
    /// NFC Forum well-known type.
    WellKnown(&'a [u8]),
    /// MIME media type.
    Media(&'a [u8]),
    /// Absolute URI used as a type identifier.
    AbsoluteUri(&'a [u8]),
    /// NFC Forum external type.
    External(&'a [u8]),
    /// Untyped application payload.
    Unknown,
}

/// Malformed NDEF framing at a record boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageError {
    /// Byte offset of the offending record header or expected next header.
    pub offset: usize,
    /// Why decoding stopped.
    pub kind: MessageErrorKind,
}

/// NDEF record parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageErrorKind {
    /// Fields are missing or a length extends outside the input.
    Truncated,
    /// Message Begin/End does not match the input boundaries.
    Boundary,
    /// A chunk is out of order or has fields forbidden in a continuation.
    Chunk,
    /// The type name, ID, or payload is inconsistent with the type format.
    Format,
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NDEF {:?} at byte {}", self.kind, self.offset)
    }
}

impl core::error::Error for MessageError {}

impl<'a> Message<'a> {
    /// Decode exactly one complete message, accepting short, normal, and
    /// chunked records. A zero-byte tag value represents absence at the
    /// mapping layer. An empty NDEF record has its own encoding.
    pub fn parse(input: &'a [u8]) -> Result<Self, MessageError> {
        let mut tail = input;
        let mut records = Vec::new();
        let mut pending: Option<Record<'a>> = None;
        loop {
            let offset = input.len() - tail.len();
            let error = |kind| MessageError { offset, kind };
            let part =
                RecordPart::take(&mut tail).ok_or_else(|| error(MessageErrorKind::Truncated))?;
            let begin = part.flags & 0x80 != 0;
            let end = part.flags & 0x40 != 0;
            let continued = part.flags & 0x20 != 0;
            if begin != (offset == 0) || end != tail.is_empty() {
                return Err(error(MessageErrorKind::Boundary));
            }
            if end && continued {
                return Err(error(MessageErrorKind::Chunk));
            }
            if let Some(mut record) = pending.take() {
                if part.flags & 7 != 6 || !part.name.is_empty() || part.id.is_some() {
                    return Err(error(MessageErrorKind::Chunk));
                }
                if !part.payload.is_empty() {
                    record.payload.to_mut().extend_from_slice(part.payload);
                }
                if continued {
                    pending = Some(record);
                } else {
                    records.push(record);
                }
            } else {
                let record_type = part.record_type(continued).map_err(error)?;
                let record = Record {
                    record_type,
                    id: part.id.filter(|id| !id.is_empty()),
                    payload: Cow::Borrowed(part.payload),
                };
                if continued {
                    pending = Some(record);
                } else {
                    records.push(record);
                }
            }
            if end {
                return Ok(Self { records });
            }
        }
    }

    /// Borrow the assembled records in message order.
    pub fn records(&self) -> &[Record<'a>] {
        &self.records
    }
}

struct RecordPart<'a> {
    flags: u8,
    name: &'a [u8],
    id: Option<&'a [u8]>,
    payload: &'a [u8],
}

impl<'a> RecordPart<'a> {
    fn take(input: &mut &'a [u8]) -> Option<Self> {
        let [flags, name_length] = take(input, 2)?.try_into().ok()?;
        let payload_length = if flags & 0x10 != 0 {
            usize::from(take(input, 1)?[0])
        } else {
            let bytes = take(input, 4)?.try_into().ok()?;
            usize::try_from(u32::from_be_bytes(bytes)).ok()?
        };
        let id_length = if flags & 8 != 0 {
            Some(usize::from(take(input, 1)?[0]))
        } else {
            None
        };
        let name = take(input, usize::from(name_length))?;
        let id = match id_length {
            Some(length) => Some(take(input, length)?),
            None => None,
        };
        let payload = take(input, payload_length)?;
        Some(Self {
            flags,
            name,
            id,
            payload,
        })
    }

    fn record_type(&self, continued: bool) -> Result<RecordType<'a>, MessageErrorKind> {
        let tnf = self.flags & 7;
        match (tnf, self.name.is_empty()) {
            (0, true)
                if !continued
                    && self.payload.is_empty()
                    && self.id.is_none_or(<[u8]>::is_empty) =>
            {
                Ok(RecordType::Empty)
            }
            (1, false) => Ok(RecordType::WellKnown(self.name)),
            (2, false) => Ok(RecordType::Media(self.name)),
            (3, false) => Ok(RecordType::AbsoluteUri(self.name)),
            (4, false) => Ok(RecordType::External(self.name)),
            (5, true) => Ok(RecordType::Unknown),
            (6, _) => Err(MessageErrorKind::Chunk),
            _ => Err(MessageErrorKind::Format),
        }
    }
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Option<&'a [u8]> {
    let (value, rest) = input.split_at_checked(length)?;
    *input = rest;
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_short_normal_and_chunked_records() -> Result<(), MessageError> {
        let encoded = [
            0xb9, 1, 2, 1, b'T', b'i', b'a', b'b', 0x36, 0, 1, b'c', 0x16, 0, 1, b'd', 0x45, 0, 0,
            0, 0, 2, 0x80, 0xff,
        ];
        let message = Message::parse(&encoded)?;
        let [text, unknown] = message.records() else {
            panic!("expected two logical records");
        };
        assert_eq!(text.record_type, RecordType::WellKnown(b"T"));
        assert_eq!(text.id, Some(b"i".as_slice()));
        assert_eq!(text.payload.as_ref(), b"abcd");
        assert_eq!(unknown.record_type, RecordType::Unknown);
        assert_eq!(unknown.payload, Cow::Borrowed([0x80, 0xff].as_slice()));
        assert_eq!(
            Message::parse(&[0xd0, 0, 0])?.records()[0].record_type,
            RecordType::Empty
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_boundaries_lengths_and_chunk_headers() {
        for (encoded, offset, kind) in [
            (&[0x90, 0, 0][..], 0, MessageErrorKind::Boundary),
            (
                &[0xc5, 0, 0xff, 0xff, 0xff, 0xff],
                0,
                MessageErrorKind::Truncated,
            ),
            (&[0xd6, 0, 0], 0, MessageErrorKind::Chunk),
            (&[0xb5, 0, 0, 0x5e, 0, 0, 0], 3, MessageErrorKind::Chunk),
            (&[0xd0, 0, 1, 0], 0, MessageErrorKind::Format),
        ] {
            assert_eq!(Message::parse(encoded), Err(MessageError { offset, kind }));
        }
    }
}
