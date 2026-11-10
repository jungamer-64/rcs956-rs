use super::{Error, UpdateStage, WriteError};
use crate::{
    isodep,
    reader::{self, TypeACard, TypeBCard},
    transport::Transport,
};
use alloc::vec::Vec;
use core::ops::Range;

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
        write_type4(|command| self.exchange_apdu(command), message)
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
    pub fn write_type4_ndef(&mut self, message: &[u8]) -> Result<(), Type4WriteError<T::Error>> {
        write_type4(|command| self.exchange_apdu(command), message)
    }
}

fn read_type4<E>(
    mut exchange: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, Error<E>> {
    let file = select_ndef_file(&mut exchange)?;
    let length = read_binary(&mut exchange, 0, 2)?;
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    if length + 2 > file.control.capacity {
        return Err(Error::Layout("Type 4 NLEN exceeds file capacity"));
    }
    read_file(&mut exchange, 2..length + 2, file.max_read)
}

fn write_type4<E>(
    mut exchange: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
    message: &[u8],
) -> Result<(), WriteError<E>> {
    let file = select_ndef_file(&mut exchange).map_err(WriteError::Preparation)?;
    if !file.control.writable {
        return Err(WriteError::Preparation(Error::WriteAccess));
    }
    if file.max_write < 2 {
        // Both bytes of NLEN must be published in the same UPDATE BINARY.
        return Err(WriteError::Preparation(Error::Layout(
            "Type 4 MLc cannot update NLEN",
        )));
    }
    let available = file.control.capacity.min(0x8000) - 2;
    if message.len() > available {
        return Err(WriteError::Preparation(Error::Capacity {
            requested: message.len(),
            available,
        }));
    }
    let length = (message.len() as u16).to_be_bytes();
    if message.is_empty() {
        return update_binary(&mut exchange, 0, &length)
            .map_err(|cause| WriteError::update(UpdateStage::Publish, 0, cause));
    }
    update_binary(&mut exchange, 0, &[0, 0])
        .map_err(|cause| WriteError::update(UpdateStage::Begin, 0, cause))?;
    let mut written = 0;
    for chunk in message.chunks(file.max_write) {
        // Admission bounds all offsets to the short READ/UPDATE BINARY range.
        update_binary(&mut exchange, (written + 2) as u16, chunk)
            .map_err(|cause| WriteError::update(UpdateStage::Data, written, cause))?;
        written += chunk.len();
    }
    update_binary(&mut exchange, 0, &length)
        .map_err(|cause| WriteError::update(UpdateStage::Publish, written, cause))
}

struct FileControl {
    id: [u8; 2],
    capacity: usize,
    writable: bool,
}

struct Type4File {
    control: FileControl,
    max_read: usize,
    max_write: usize,
}

fn select_ndef_file<E>(
    exchange: &mut impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Type4File, Error<E>> {
    checked_apdu(
        exchange,
        &[0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0],
    )?;
    select_file(exchange, [0xe1, 3])?;
    let header = read_binary(exchange, 0, 7)?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if header[2] >> 4 != 2 {
        return Err(Error::UnsupportedMapping);
    }
    if !(15..=0x8000).contains(&length) {
        return Err(Error::Layout("Type 4 capability container length"));
    }
    let max_read = usize::from(u16::from_be_bytes([header[3], header[4]])).min(255);
    if max_read < 15 {
        return Err(Error::Layout("Type 4 maximum read length"));
    }
    let max_write = usize::from(u16::from_be_bytes([header[5], header[6]])).min(255);
    let tlvs = read_file(exchange, 7..length, max_read)?;
    let control = ndef_file(&tlvs)?;
    select_file(exchange, control.id)?;
    Ok(Type4File {
        control,
        max_read,
        max_write,
    })
}

fn ndef_file<E>(mut tlvs: &[u8]) -> Result<FileControl, Error<E>> {
    while let [tag, length, tail @ ..] = tlvs {
        let Some((value, rest)) = tail.split_at_checked(usize::from(*length)) else {
            return Err(Error::Layout("Type 4 file control TLV length"));
        };
        if *tag == 4 {
            let [id_hi, id_lo, size_hi, size_lo, read, write] = value else {
                return Err(Error::Layout("Type 4 NDEF file control length"));
            };
            if *read == 0 {
                let capacity = usize::from(u16::from_be_bytes([*size_hi, *size_lo]));
                if capacity < 2 {
                    return Err(Error::Layout("Type 4 file cannot hold NLEN"));
                }
                return Ok(FileControl {
                    id: [*id_hi, *id_lo],
                    capacity,
                    writable: *write == 0,
                });
            }
        }
        tlvs = rest;
    }
    Err(Error::ReadAccess)
}

fn update_binary<E>(
    exchange: &mut impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
    offset: u16,
    data: &[u8],
) -> Result<(), Error<E>> {
    let [hi, lo] = offset.to_be_bytes();
    let mut command = Vec::with_capacity(5 + data.len());
    command.extend_from_slice(&[0, 0xd6, hi, lo, data.len() as u8]);
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
    offset: u16,
    length: u8,
) -> Result<Vec<u8>, Error<E>> {
    let [hi, lo] = offset.to_be_bytes();
    let data = checked_apdu(exchange, &[0, 0xb0, hi, lo, length])?;
    if data.len() != usize::from(length) {
        return Err(Error::Layout("READ BINARY response length"));
    }
    Ok(data)
}

fn read_file<E>(
    exchange: &mut impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
    range: Range<usize>,
    max_read: usize,
) -> Result<Vec<u8>, Error<E>> {
    if range.end > 0x8000 {
        return Err(Error::Address(range.end - 1));
    }
    let mut data = Vec::with_capacity(range.len());
    let mut offset = range.start;
    while offset < range.end {
        let length = (range.end - offset).min(max_read);
        data.extend(read_binary(exchange, offset as u16, length as u8)?);
        offset += length;
    }
    Ok(data)
}
