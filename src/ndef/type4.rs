use super::{Error, UpdateStage, WriteError};
use crate::{
    isodep,
    reader::{self, TypeACard, TypeBCard},
    transport::Transport,
};
use alloc::vec::Vec;
use core::ops::Range;

const UPDATE_BINARY_HEADER_BYTES: usize = 5;
const CAPABILITY_CONTAINER_ID: u16 = 0xe103;
const SHORT_FILE_END: usize = 0x8000;
const MAX_EXTENDED_FILE_BYTES: usize = 1 << 20;

/// Failure while retrieving a Type 4 message over NFC-A or NFC-B.
pub type Type4Error<E> = Error<isodep::Error<reader::Error<E>>>;

/// Failure while replacing a Type 4 message over NFC-A or NFC-B.
pub type Type4WriteError<E> = WriteError<isodep::Error<reader::Error<E>>>;

impl<T: Transport> TypeACard<'_, T> {
    /// Read the first publicly readable NDEF file on a Type 4A tag.
    /// This selects the NDEF application and files on the card.
    pub fn read_type4_ndef(&mut self) -> Result<Vec<u8>, Type4Error<T::Error>> {
        read_type4(|command| self.exchange_apdu(command))
    }

    /// Replace the NDEF message in the first publicly readable Type 4A file
    /// if it is also publicly writable. An empty slice clears the file.
    pub fn write_type4_ndef(&mut self, message: &[u8]) -> Result<(), Type4WriteError<T::Error>> {
        let max_apdu_bytes = self.maximum_apdu_bytes();
        write_type4(
            |command| self.exchange_apdu(command),
            max_apdu_bytes,
            message,
        )
    }
}

impl<T: Transport> TypeBCard<'_, T> {
    /// Read the first publicly readable NDEF file on a Type 4B tag.
    /// This selects the NDEF application and files on the card.
    pub fn read_type4_ndef(&mut self) -> Result<Vec<u8>, Type4Error<T::Error>> {
        read_type4(|command| self.exchange_apdu(command))
    }

    /// Replace the NDEF message in the first publicly readable Type 4B file
    /// if it is also publicly writable. An empty slice clears the file.
    /// The write size per APDU respects both MLc and the ISO-DEP session limit.
    pub fn write_type4_ndef(&mut self, message: &[u8]) -> Result<(), Type4WriteError<T::Error>> {
        let max_apdu_bytes = self.maximum_apdu_bytes();
        write_type4(
            |command| self.exchange_apdu(command),
            max_apdu_bytes,
            message,
        )
    }
}

fn read_type4<E>(
    mut exchange: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, Error<E>> {
    let file = select_ndef_file(&mut exchange)?;
    let encoded = read_binary(
        &mut exchange,
        BinaryAddress::Short(0),
        file.control.length.bytes(),
    )?;
    let length_bytes = usize::from(file.control.length.bytes());
    let length = file.control.length.decode(&encoded)?;
    if length > file.control.capacity - length_bytes {
        return Err(Error::Layout("Type 4 NLEN exceeds file capacity"));
    }
    if length > file.available() {
        return Err(Error::Capacity {
            requested: length,
            available: file.available(),
        });
    }
    let end = length_bytes + length;
    let addressing = file.addressing(end);
    read_file(&mut exchange, length_bytes..end, file.max_read, addressing)
}

fn write_type4<E>(
    mut exchange: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
    max_apdu_bytes: usize,
    message: &[u8],
) -> Result<(), WriteError<E>> {
    let file = select_ndef_file(&mut exchange).map_err(WriteError::Preparation)?;
    if !file.control.writable {
        return Err(WriteError::Preparation(Error::WriteAccess));
    }
    let max_write = file
        .max_write
        .min(max_apdu_bytes.saturating_sub(UPDATE_BINARY_HEADER_BYTES));
    let length_bytes = usize::from(file.control.length.bytes());
    if max_write < length_bytes {
        // Publish the complete length in one UPDATE BINARY.
        return Err(WriteError::Preparation(Error::Layout(
            "Type 4 UPDATE BINARY cannot fit NLEN",
        )));
    }
    let available = file.available();
    if message.len() > available {
        return Err(WriteError::Preparation(Error::Capacity {
            requested: message.len(),
            available,
        }));
    }
    let encoded_length = u32::try_from(message.len())
        .map_err(|_| {
            WriteError::Preparation(Error::Capacity {
                requested: message.len(),
                available,
            })
        })?
        .to_be_bytes();
    let length = &encoded_length[4 - length_bytes..];
    let addressing = file.addressing(message.len() + length_bytes);
    let chunk_size = match addressing {
        Addressing::Short => max_write,
        Addressing::OffsetObject => max_write.saturating_sub(7).min(127),
    };
    if chunk_size == 0 {
        return Err(WriteError::Preparation(Error::Layout(
            "Type 4 UPDATE BINARY cannot fit an offset and data object",
        )));
    }
    if message.is_empty() {
        return update_binary(&mut exchange, BinaryAddress::Short(0), length)
            .map_err(|cause| WriteError::update(UpdateStage::Publish, 0, cause));
    }
    update_binary(
        &mut exchange,
        BinaryAddress::Short(0),
        &[0; 4][..length_bytes],
    )
    .map_err(|cause| WriteError::update(UpdateStage::Begin, 0, cause))?;
    let mut written = 0;
    for chunk in message.chunks(chunk_size) {
        let offset = addressing
            .address(written + length_bytes)
            .map_err(|cause| WriteError::update(UpdateStage::Data, written, cause))?;
        update_binary(&mut exchange, offset, chunk)
            .map_err(|cause| WriteError::update(UpdateStage::Data, written, cause))?;
        written += chunk.len();
    }
    update_binary(&mut exchange, BinaryAddress::Short(0), length)
        .map_err(|cause| WriteError::update(UpdateStage::Publish, written, cause))
}

struct FileControl {
    id: [u8; 2],
    capacity: usize,
    length: LengthField,
    writable: bool,
}

#[derive(Clone, Copy)]
enum LengthField {
    Nlen,
    Extended,
}

impl LengthField {
    fn bytes(self) -> u8 {
        match self {
            Self::Nlen => 2,
            Self::Extended => 4,
        }
    }

    fn decode<E>(self, encoded: &[u8]) -> Result<usize, Error<E>> {
        let mut value = [0; 4];
        value[4 - usize::from(self.bytes())..].copy_from_slice(encoded);
        usize::try_from(u32::from_be_bytes(value)).map_err(|_| Error::Layout("Type 4 ENLEN"))
    }
}

struct Type4File {
    control: FileControl,
    extended_addressing: bool,
    /// READ BINARY limit from the capability container, at least 15.
    max_read: u8,
    max_write: usize,
}

impl Type4File {
    fn available(&self) -> usize {
        let addressable = if self.extended_addressing {
            MAX_EXTENDED_FILE_BYTES
        } else {
            SHORT_FILE_END
        };
        self.control.capacity.min(addressable) - usize::from(self.control.length.bytes())
    }

    fn addressing(&self, end: usize) -> Addressing {
        if end > SHORT_FILE_END {
            Addressing::OffsetObject
        } else {
            Addressing::Short
        }
    }
}

#[derive(Clone, Copy)]
enum Addressing {
    Short,
    OffsetObject,
}

impl Addressing {
    /// Encode a file offset; callers bound files to the addressable range.
    fn address<E>(self, offset: usize) -> Result<BinaryAddress, Error<E>> {
        let invalid = || Error::Layout("Type 4 file offset");
        match self {
            Self::Short => u16::try_from(offset)
                .map(BinaryAddress::Short)
                .map_err(|_| invalid()),
            Self::OffsetObject => match u32::try_from(offset).map(u32::to_be_bytes) {
                Ok([0, a, b, c]) => Ok(BinaryAddress::OffsetObject([a, b, c])),
                _ => Err(invalid()),
            },
        }
    }
}

enum BinaryAddress {
    Short(u16),
    OffsetObject([u8; 3]),
}

fn select_ndef_file<E>(
    exchange: &mut impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Type4File, Error<E>> {
    checked_apdu(
        exchange,
        &[0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0],
    )?;
    select_file(exchange, CAPABILITY_CONTAINER_ID.to_be_bytes())?;
    let header = read_binary(exchange, BinaryAddress::Short(0), 7)?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    let version = header[2] >> 4;
    if !matches!(version, 2 | 3) {
        return Err(Error::UnsupportedMapping);
    }
    if !(15..=SHORT_FILE_END).contains(&length) {
        return Err(Error::Layout("Type 4 capability container length"));
    }
    let max_read = u8::try_from(u16::from_be_bytes([header[3], header[4]])).unwrap_or(u8::MAX);
    if max_read < 15 {
        return Err(Error::Layout("Type 4 maximum read length"));
    }
    let max_write = usize::from(u16::from_be_bytes([header[5], header[6]])).min(255);
    let tlvs = read_file(exchange, 7..length, max_read, Addressing::Short)?;
    let control = ndef_file(&tlvs)?;
    select_file(exchange, control.id)?;
    Ok(Type4File {
        control,
        extended_addressing: version == 3,
        max_read,
        max_write,
    })
}

fn ndef_file<E>(mut tlvs: &[u8]) -> Result<FileControl, Error<E>> {
    while let [tag, length, tail @ ..] = tlvs {
        let Some((value, rest)) = tail.split_at_checked(usize::from(*length)) else {
            return Err(Error::Layout("Type 4 file control TLV length"));
        };
        let (id, capacity, length, read, write) = match (*tag, value) {
            (4, [a, b, hi, lo, read, write]) => (
                [*a, *b],
                u32::from(u16::from_be_bytes([*hi, *lo])),
                LengthField::Nlen,
                *read,
                *write,
            ),
            (6, [a, b, c, d, e, f, read, write]) => (
                [*a, *b],
                u32::from_be_bytes([*c, *d, *e, *f]),
                LengthField::Extended,
                *read,
                *write,
            ),
            (4 | 6, _) => return Err(Error::Layout("Type 4 NDEF file control length")),
            _ => {
                tlvs = rest;
                continue;
            }
        };
        if matches!(
            u16::from_be_bytes(id),
            0 | 0x3f00 | 0x3fff | 0xe102 | CAPABILITY_CONTAINER_ID | 0xffff
        ) {
            return Err(Error::Layout("Type 4 NDEF file identifier"));
        }
        if read == 0 {
            let capacity =
                usize::try_from(capacity).map_err(|_| Error::Layout("Type 4 file capacity"))?;
            if capacity < usize::from(length.bytes()) {
                return Err(Error::Layout("Type 4 file cannot hold NLEN"));
            }
            return Ok(FileControl {
                id,
                capacity,
                length,
                writable: write == 0,
            });
        }
        tlvs = rest;
    }
    Err(Error::ReadAccess)
}

fn update_binary<E>(
    exchange: &mut impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
    offset: BinaryAddress,
    data: &[u8],
) -> Result<(), Error<E>> {
    let length_error = || Error::Layout("Type 4 UPDATE BINARY data length");
    let length = u8::try_from(data.len()).map_err(|_| length_error())?;
    let mut command = Vec::with_capacity(UPDATE_BINARY_HEADER_BYTES + 7 + data.len());
    match offset {
        BinaryAddress::Short(offset) => {
            let [hi, lo] = offset.to_be_bytes();
            command.extend([0, 0xd6, hi, lo, length]);
        }
        BinaryAddress::OffsetObject([a, b, c]) => {
            let field = length.checked_add(7).ok_or_else(length_error)?;
            command.extend([0, 0xd7, 0, 0, field, 0x54, 3, a, b, c, 0x53, length]);
        }
    }
    command.extend_from_slice(data);
    if !checked_apdu(exchange, &command)?.is_empty() {
        return Err(Error::Layout("UPDATE BINARY response length"));
    }
    Ok(())
}

fn checked_apdu<E>(
    exchange: &mut impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
    command: &[u8],
) -> Result<Vec<u8>, Error<E>> {
    let mut reply = exchange(command).map_err(Error::Exchange)?;
    let Some(status_start) = reply.len().checked_sub(2) else {
        return Err(Error::Layout("APDU status word"));
    };
    let status = u16::from_be_bytes([reply[status_start], reply[status_start + 1]]);
    if status != 0x9000 {
        return Err(Error::Status(status));
    }
    reply.truncate(status_start);
    Ok(reply)
}

fn select_file<E>(
    exchange: &mut impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
    file: [u8; 2],
) -> Result<(), Error<E>> {
    checked_apdu(exchange, &[0, 0xa4, 0, 0x0c, 2, file[0], file[1]])?;
    Ok(())
}

fn read_binary<E>(
    exchange: &mut impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
    offset: BinaryAddress,
    length: u8,
) -> Result<Vec<u8>, Error<E>> {
    let data = match offset {
        BinaryAddress::Short(offset) => {
            let [hi, lo] = offset.to_be_bytes();
            checked_apdu(exchange, &[0, 0xb0, hi, lo, length])?
        }
        BinaryAddress::OffsetObject([a, b, c]) => {
            let mut reply =
                checked_apdu(exchange, &[0, 0xb1, 0, 0, 5, 0x54, 3, a, b, c, length + 2])?;
            if !reply.starts_with(&[0x53, length]) {
                return Err(Error::Layout("Type 4 READ BINARY data object"));
            }
            reply.split_off(2)
        }
    };
    if data.len() != usize::from(length) {
        return Err(Error::Layout("READ BINARY response length"));
    }
    Ok(data)
}

fn read_file<E>(
    exchange: &mut impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
    range: Range<usize>,
    max_read: u8,
    addressing: Addressing,
) -> Result<Vec<u8>, Error<E>> {
    // An offset reply wraps the data in a two-byte object with a short length.
    let max_read = match addressing {
        Addressing::Short => max_read,
        Addressing::OffsetObject => max_read.saturating_sub(2).min(127),
    };
    let mut data = Vec::with_capacity(range.len());
    let mut offset = range.start;
    while offset < range.end {
        let length = u8::try_from(range.end - offset).map_or(max_read, |rest| rest.min(max_read));
        data.extend(read_binary(exchange, addressing.address(offset)?, length)?);
        offset += usize::from(length);
    }
    Ok(data)
}
