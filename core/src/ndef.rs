//! NFC Forum tag access for NDEF messages.
//!
//! Mapping and access checks are separate from RF exchange and record encoding.

mod type3;

pub use type3::Type3Tag;

use crate::{
    isodep,
    reader::{self, TypeACard, TypeBCard},
    transport::Transport,
};
use alloc::vec::Vec;
use core::{fmt, ops::Range};

/// NDEF mapping, card status, or underlying exchange failure.
#[derive(Debug)]
pub enum Error<E> {
    /// RF or reader exchange failed.
    Exchange(E),
    /// The tag or its mapping version is outside this operation's profile.
    UnsupportedMapping,
    /// This operation requires read access without authentication.
    ReadAccess,
    /// This operation requires write access without authentication.
    WriteAccess,
    /// The tag reports a write in progress or interrupted before publication.
    WriteInProgress,
    /// The message cannot fit the tag's addressable NDEF storage.
    Capacity {
        /// Requested message size in bytes.
        requested: usize,
        /// Available message bytes, excluding mapping metadata.
        available: usize,
    },
    /// A mapping field or response length is inconsistent.
    Layout(&'static str),
    /// Reading requires an address outside the supported range.
    Address(usize),
    /// A Type 4 tag returned an unsuccessful status word.
    Status(u16),
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Exchange(error) => Some(error),
            _ => None,
        }
    }
}

/// The persistent operation being attempted when an NDEF update failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateStage {
    /// Invalidate the previous message or mark the tag as being updated.
    Begin,
    /// Write data while the message is unpublished.
    Data,
    /// Publish the new message.
    Publish,
}

/// Failure to replace an NDEF message.
#[derive(Debug)]
pub enum WriteError<E> {
    /// No persistent write was attempted.
    Preparation(Error<E>),
    /// An update command failed. Its effect may be unknown. Re-select and
    /// inspect the tag before deciding whether to issue another write.
    Update {
        /// Stage of the command that failed.
        stage: UpdateStage,
        /// Prefix of message bytes acknowledged by prior write commands.
        acknowledged_bytes: usize,
        /// Cause reported by the mapping or transport.
        cause: Error<E>,
    },
}

impl<E> WriteError<E> {
    fn update(stage: UpdateStage, acknowledged_bytes: usize, cause: Error<E>) -> Self {
        Self::Update {
            stage,
            acknowledged_bytes,
            cause,
        }
    }
}

impl<E: fmt::Debug> fmt::Display for WriteError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<E: core::error::Error + 'static> core::error::Error for WriteError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Preparation(error) | Self::Update { cause: error, .. } => Some(error),
        }
    }
}

/// Failure while retrieving a Type 4 message over NFC-A or NFC-B.
pub type Type4Error<E> = Error<isodep::Error<reader::Error<E>>>;

impl<T: Transport> TypeACard<'_, T> {
    /// Read the NDEF message from a Type 2 tag's first physical sector.
    /// Reserved bytes and dynamic lock bytes are skipped. An empty mapped
    /// message is returned as an empty vector. No write is performed.
    pub fn read_type2_ndef(
        &mut self,
    ) -> Result<Option<Vec<u8>>, Error<reader::TypeAExchangeError<T::Error>>> {
        if self.observation().sel_res() != 0 {
            return Err(Error::UnsupportedMapping);
        }
        read_type2(|page| {
            let response = self.exchange(&[0x30, page]).map_err(Error::Exchange)?;
            if response.status != 0 {
                return Err(Error::Layout("Type 2 READ status"));
            }
            response
                .data
                .try_into()
                .map_err(|_| Error::Layout("Type 2 READ length"))
        })
    }

    /// Read the first publicly readable NDEF file on a Type 4A tag.
    /// This selects the NDEF application and files on the card.
    pub fn read_type4_ndef(&mut self) -> Result<Vec<u8>, Type4Error<T::Error>> {
        read_type4(|command| self.exchange_apdu(command))
    }
}

impl<T: Transport> TypeBCard<'_, T> {
    /// Read the first publicly readable NDEF file on a Type 4B tag.
    /// This selects the NDEF application and files on the card.
    pub fn read_type4_ndef(&mut self) -> Result<Vec<u8>, Type4Error<T::Error>> {
        read_type4(|command| self.exchange_apdu(command))
    }
}

fn read_type2<E>(
    mut read_pages: impl FnMut(u8) -> Result<[u8; 16], Error<E>>,
) -> Result<Option<Vec<u8>>, Error<E>> {
    let header = read_pages(0)?;
    let [magic, version, size, access] = header[12..]
        .try_into()
        .map_err(|_| Error::Layout("capability container"))?;
    if magic != 0xe1 || version >> 4 != 1 {
        return Err(Error::UnsupportedMapping);
    }
    if access >> 4 != 0 {
        return Err(Error::ReadAccess);
    }
    let mut memory = Type2Data {
        read_pages,
        cached_start: 0,
        cache: header,
        address: 16,
        remaining: usize::from(size) * 8,
        excluded: Vec::new(),
    };
    while memory.remaining != 0 {
        let tag = memory.byte()?;
        match tag {
            0 => continue,
            0xfe => return Ok(None),
            _ => {}
        }
        let length = match memory.byte()? {
            0xff => {
                let length = usize::from(u16::from_be_bytes([memory.byte()?, memory.byte()?]));
                if length < 255 {
                    return Err(Error::Layout("Type 2 extended TLV length"));
                }
                length
            }
            length => usize::from(length),
        };
        if length > memory.remaining {
            return Err(Error::Layout("Type 2 TLV exceeds data area"));
        }
        match tag {
            1 | 2 => {
                if length != 3 {
                    return Err(Error::Layout("Type 2 control TLV length"));
                }
                let position = memory.byte()?;
                let size = memory.byte()?;
                let control = memory.byte()?;
                let page_shift = control & 0x0f;
                let offset = usize::from(position & 0x0f);
                if page_shift == 0 || offset >= 1usize << page_shift {
                    return Err(Error::Layout("Type 2 control TLV address"));
                }
                let start = (usize::from(position >> 4) << page_shift) + offset;
                let size = if size == 0 { 256 } else { usize::from(size) };
                let bytes = if tag == 1 { size.div_ceil(8) } else { size };
                if start < memory.address
                    || memory
                        .excluded
                        .iter()
                        .any(|range| range.start < start + bytes && start < range.end)
                {
                    return Err(Error::Layout("Type 2 control TLV overlaps mapped bytes"));
                }
                memory.excluded.push(start..start + bytes);
            }
            3 => {
                return (0..length)
                    .map(|_| memory.byte())
                    .collect::<Result<Vec<_>, _>>()
                    .map(Some);
            }
            _ => {
                for _ in 0..length {
                    memory.byte()?;
                }
            }
        }
    }
    Ok(None)
}

struct Type2Data<F> {
    read_pages: F,
    cached_start: usize,
    cache: [u8; 16],
    address: usize,
    remaining: usize,
    excluded: Vec<Range<usize>>,
}

impl<F> Type2Data<F> {
    fn byte<E>(&mut self) -> Result<u8, Error<E>>
    where
        F: FnMut(u8) -> Result<[u8; 16], Error<E>>,
    {
        if self.remaining == 0 {
            return Err(Error::Layout("Type 2 data area exhausted"));
        }
        while let Some(range) = self
            .excluded
            .iter()
            .find(|range| range.contains(&self.address))
        {
            self.address = range.end;
        }
        let start = self.address / 16 * 16;
        if self.cached_start != start {
            let page = u8::try_from(start / 4).map_err(|_| Error::Address(self.address))?;
            self.cache = (self.read_pages)(page)?;
            self.cached_start = start;
        }
        let byte = self.cache[self.address - start];
        self.remaining -= 1;
        self.address += 1;
        Ok(byte)
    }
}

fn read_type4<E>(
    mut exchange: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, Error<E>> {
    checked_apdu(
        &mut exchange,
        &[0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0],
    )?;
    select_file(&mut exchange, [0xe1, 3])?;
    let header = read_binary(&mut exchange, 0, 7)?;
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
    let tlvs = read_file(&mut exchange, 7..length, max_read)?;
    let (file, capacity) = ndef_file(&tlvs)?;
    select_file(&mut exchange, file)?;
    let length = read_binary(&mut exchange, 0, 2)?;
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    if length + 2 > capacity {
        return Err(Error::Layout("Type 4 NLEN exceeds file capacity"));
    }
    read_file(&mut exchange, 2..length + 2, max_read)
}

fn ndef_file<E>(mut tlvs: &[u8]) -> Result<([u8; 2], usize), Error<E>> {
    while let [tag, length, tail @ ..] = tlvs {
        let Some((value, rest)) = tail.split_at_checked(usize::from(*length)) else {
            return Err(Error::Layout("Type 4 file control TLV length"));
        };
        if *tag == 4 {
            let [id_hi, id_lo, size_hi, size_lo, read, _] = value else {
                return Err(Error::Layout("Type 4 NDEF file control length"));
            };
            if *read == 0 {
                return Ok((
                    [*id_hi, *id_lo],
                    usize::from(u16::from_be_bytes([*size_hi, *size_lo])),
                ));
            }
        }
        tlvs = rest;
    }
    Err(Error::ReadAccess)
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
