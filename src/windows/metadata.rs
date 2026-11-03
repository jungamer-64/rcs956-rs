//! Bounded UTF-16 metadata queries and registered interface identifiers.
#![forbid(unsafe_code)]

use std::io;
use windows_sys::core::GUID;

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

fn guid(text: &str) -> io::Result<GUID> {
    let text = text
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(text);
    let fields: Vec<_> = text.split('-').collect();
    if fields.iter().map(|s| s.len()).ne([8, 4, 4, 4, 12]) {
        return Err(invalid("invalid interface GUID shape"));
    }
    let digits = fields.concat();
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("invalid interface GUID digits"));
    }
    let value =
        u128::from_str_radix(&digits, 16).map_err(|_| invalid("invalid interface GUID digits"))?;
    Ok(GUID::from_u128(value))
}

pub(super) fn interface_guids(
    multi: Option<&[u16]>,
    single: Option<&[u16]>,
) -> io::Result<Vec<GUID>> {
    let mut result = Vec::new();
    if let Some(data) = multi {
        if !data.ends_with(&[0, 0]) {
            return Err(invalid("unterminated interface GUID list"));
        }
        let mut remaining = data;
        while remaining.first().is_some_and(|c| *c != 0) {
            let end = remaining
                .iter()
                .position(|c| *c == 0)
                .ok_or_else(|| invalid("interface GUID list length"))?;
            result.push(guid(&string(&remaining[..=end])?)?);
            remaining = &remaining[end + 1..];
        }
        if remaining.iter().any(|c| *c != 0) {
            return Err(invalid("data after GUID list terminator"));
        }
    }
    if let Some(data) = single {
        result.push(guid(&string(data)?)?);
    }
    let mut unique = Vec::new();
    for value in result {
        if !unique.iter().any(|v: &GUID| {
            v.data1 == value.data1
                && v.data2 == value.data2
                && v.data3 == value.data3
                && v.data4 == value.data4
        }) {
            unique.push(value);
        }
    }
    Ok(unique)
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

    #[test]
    fn registry_string_and_multi_string_forms_preserve_registration() -> io::Result<()> {
        let first: Vec<_> = "{12345678-1234-5678-90AB-CDEF01234567}\0"
            .encode_utf16()
            .collect();
        let second: Vec<_> = "{87654321-1234-5678-90AB-CDEF01234567}\0"
            .encode_utf16()
            .collect();
        let mut multi = [first.as_slice(), second.as_slice()].concat();
        multi.push(0);
        let values = interface_guids(Some(&multi), Some(&first))?;
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].data1, 0x12345678);
        assert_eq!(interface_guids(None, Some(&second))?[0].data1, 0x87654321);
        assert!(interface_guids(None, None)?.is_empty());
        assert!(interface_guids(Some(&[0, 0]), None)?.is_empty());
        Ok(())
    }

    #[test]
    fn malformed_registration_is_not_absence() {
        for value in [
            "bogus\0\0",
            "{12345678-1234-5678-90AB-CDEF01234567}",
            "\0hidden\0\0",
            "{+2345678-1234-5678-90AB-CDEF01234567}\0\0",
        ] {
            let data: Vec<_> = value.encode_utf16().collect();
            assert!(interface_guids(Some(&data), None).is_err());
        }
        assert!(string(&[0xd800, 0]).is_err());
    }
}
