//! Bounded UTF-16 metadata queries and registered interface identifiers.
#![forbid(unsafe_code)]

use std::io;

const MAX_BYTES: u32 = 65_536;
const MAX_QUERIES: usize = 4;

/// Byte counts stay distinct from the UTF-16 buffer's code-unit capacity.
#[derive(Debug)]
pub(super) enum Query {
    Missing,
    NeededBytes(u32),
    ValueBytes(u32),
}

pub(super) fn capacity_bytes(buffer: &[u16]) -> io::Result<u32> {
    buffer
        .len()
        .checked_mul(2)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| invalid("UTF-16 byte capacity overflow"))
}

fn units(bytes: u32) -> io::Result<usize> {
    if bytes > MAX_BYTES || !bytes.is_multiple_of(2) {
        return Err(invalid("metadata exceeds 64KiB or has an odd byte length"));
    }
    usize::try_from(bytes / 2).map_err(io::Error::other)
}

/// Query at most four times, growing only to a reported, bounded byte count.
/// Missing is an API-reported absence; access/type errors remain errors.
pub(super) fn read_utf16(
    mut query: impl FnMut(&mut [u16]) -> io::Result<Query>,
) -> io::Result<Option<Vec<u16>>> {
    let mut buffer = Vec::new();
    for _ in 0..MAX_QUERIES {
        match query(&mut buffer)? {
            Query::Missing => return Ok(None),
            Query::NeededBytes(bytes) => {
                let count = units(bytes)?;
                if count <= buffer.len() {
                    return Err(invalid("metadata size query made no progress"));
                }
                buffer.resize(count, 0);
            }
            Query::ValueBytes(bytes) => {
                let count = units(bytes)?;
                if count > buffer.len() {
                    return Err(invalid("metadata result exceeds capacity"));
                }
                buffer.truncate(count);
                return Ok(Some(buffer));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "metadata size changed during four queries",
    ))
}

pub(super) fn string(data: &[u16]) -> io::Result<String> {
    let end = data
        .iter()
        .position(|c| *c == 0)
        .ok_or_else(|| invalid("unterminated UTF-16 string"))?;
    if data[end..].iter().any(|c| *c != 0) {
        return Err(invalid("data after string terminator"));
    }
    String::from_utf16(&data[..end]).map_err(|_| invalid("invalid UTF-16 string"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_follows_reported_size_when_value_grows() -> io::Result<()> {
        let mut call = 0;
        let result = read_utf16(|buffer| {
            call += 1;
            match call {
                1 => {
                    assert!(buffer.is_empty());
                    Ok(Query::NeededBytes(5000))
                }
                2 => {
                    assert_eq!(buffer.len(), 2500);
                    Ok(Query::NeededBytes(6000))
                }
                _ => {
                    buffer[0] = 0x41;
                    buffer[1] = 0;
                    Ok(Query::ValueBytes(4))
                }
            }
        })?
        .ok_or_else(|| invalid("expected value"))?;
        assert_eq!(result, [0x41, 0]);
        Ok(())
    }

    #[test]
    fn absence_errors_and_query_budget_are_distinct() -> io::Result<()> {
        assert!(read_utf16(|_| Ok(Query::Missing))?.is_none());
        let denied = read_utf16(|_| Err(io::Error::from_raw_os_error(5)));
        assert!(matches!(denied, Err(e) if e.raw_os_error() == Some(5)));
        let mut size = 0;
        let changing = read_utf16(|_| {
            size += 2;
            Ok(Query::NeededBytes(size))
        });
        assert!(matches!(changing, Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        for size in [0, 1, 65_538] {
            assert!(
                matches!(read_utf16(|_| Ok(Query::NeededBytes(size))), Err(e) if e.kind() == io::ErrorKind::InvalidData)
            );
        }
        assert!(
            matches!(read_utf16(|_| Ok(Query::ValueBytes(2))), Err(e) if e.kind() == io::ErrorKind::InvalidData)
        );
        Ok(())
    }
}
