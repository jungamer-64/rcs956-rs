use super::{Error, UpdateStage, WriteError, control_range};
use crate::{
    reader::{self, TypeACard, TypeAExchangeError},
    transport::Transport,
};
use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Range;

/// Failure while replacing a Type 2 message over NFC-A.
pub type Type2WriteError<E> = WriteError<TypeAExchangeError<E>>;

/// Failure while retrieving a Type 2 message over NFC-A.
pub type Type2Error<E> = Error<TypeAExchangeError<E>>;

impl<T: Transport> TypeACard<'_, T> {
    /// Read the NDEF message across the tag's Type 2 memory sectors.
    /// Reserved bytes and dynamic lock bytes are skipped. An empty mapped
    /// message is returned as an empty vector. No write is performed.
    pub fn read_type2_ndef(&mut self) -> Result<Option<Vec<u8>>, Type2Error<T::Error>> {
        let mut tag = Type2Data::open(self)?;
        if !tag.find_message()? {
            return Ok(None);
        }
        let length = tag.tlv_length()?;
        (0..length)
            .map(|_| tag.byte())
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// Replace the first NDEF TLV in an initialized, publicly writable Type 2
    /// mapping. The Terminator
    /// after the new message supersedes any TLVs that followed the old message.
    /// An empty slice clears the message.
    pub fn write_type2_ndef(&mut self, message: &[u8]) -> Result<(), Type2WriteError<T::Error>> {
        let mut tag = Type2Data::open(self).map_err(WriteError::Preparation)?;
        let write = tag
            .prepare_write(message)
            .map_err(WriteError::Preparation)?;
        tag.write_page(write.length_page, write.unpublished)
            .map_err(|cause| WriteError::update(UpdateStage::Begin, 0, cause))?;
        let mut written = 0;
        for (page, patch) in write.data {
            tag.write_page(page, patch.bytes)
                .map_err(|cause| WriteError::update(UpdateStage::Data, written, cause))?;
            written += patch.message_bytes;
        }
        tag.write_page(write.length_page, write.published)
            .map_err(|cause| WriteError::update(UpdateStage::Publish, written, cause))
    }
}

struct Type2Data<'card, 'reader, T: Transport> {
    card: &'card mut TypeACard<'reader, T>,
    cached_start: usize,
    cache: [u8; 16],
    address: usize,
    remaining: usize,
    excluded: Vec<Range<usize>>,
    writable: bool,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Type2Page(u16);

impl Type2Page {
    fn containing<E>(address: usize) -> Result<Self, Error<E>> {
        u16::try_from(address / 4)
            .map(Self)
            .map_err(|_| Error::Address(address))
    }

    fn offset(self) -> usize {
        usize::from(self.0) * 4
    }

    fn wire_address(self) -> (u8, u8) {
        let [sector, page] = self.0.to_be_bytes();
        (sector, page)
    }
}

struct PagePatch {
    bytes: [u8; 4],
    message_bytes: usize,
}

struct Type2Write {
    length_page: Type2Page,
    unpublished: [u8; 4],
    data: BTreeMap<Type2Page, PagePatch>,
    published: [u8; 4],
}

impl<'card, 'reader, T: Transport> Type2Data<'card, 'reader, T> {
    fn open(card: &'card mut TypeACard<'reader, T>) -> Result<Self, Type2Error<T::Error>> {
        if card.observation().sel_res() != 0 {
            return Err(Error::UnsupportedMapping);
        }
        let header = type2_read_window(card, Type2Page(0))?;
        let [magic, version, size, access] = [header[12], header[13], header[14], header[15]];
        if magic != 0xe1 || version >> 4 != 1 {
            return Err(Error::UnsupportedMapping);
        }
        if access >> 4 != 0 {
            return Err(Error::ReadAccess);
        }
        Ok(Self {
            card,
            cached_start: 0,
            cache: header,
            address: 16,
            remaining: usize::from(size) * 8,
            excluded: Vec::new(),
            writable: access & 0x0f == 0,
        })
    }

    fn find_message(&mut self) -> Result<bool, Type2Error<T::Error>> {
        while self.remaining != 0 {
            let tag = self.byte()?;
            match tag {
                0 => continue,
                0xfe => return Ok(false),
                3 => return Ok(true),
                _ => {}
            }
            let length = self.tlv_length()?;
            if matches!(tag, 1 | 2) {
                if length != 3 {
                    return Err(Error::Layout("Type 2 control TLV length"));
                }
                self.exclude(tag)?;
            } else {
                for _ in 0..length {
                    self.next_address()?;
                }
            }
        }
        Ok(false)
    }

    fn exclude(&mut self, tag: u8) -> Result<(), Type2Error<T::Error>> {
        let reserved = control_range(tag, [self.byte()?, self.byte()?, self.byte()?])?;
        if reserved.start < self.address
            || self
                .excluded
                .iter()
                .any(|range| range.start < reserved.end && reserved.start < range.end)
        {
            return Err(Error::Layout("Type 2 control TLV overlaps mapped bytes"));
        }
        self.excluded.push(reserved);
        Ok(())
    }

    fn tlv_length(&mut self) -> Result<usize, Type2Error<T::Error>> {
        let length = match self.byte()? {
            0xff => {
                let length = usize::from(u16::from_be_bytes([self.byte()?, self.byte()?]));
                if !(255..=65534).contains(&length) {
                    return Err(Error::Layout("Type 2 extended TLV length"));
                }
                length
            }
            length => usize::from(length),
        };
        if length > self.remaining {
            return Err(Error::Layout("Type 2 TLV exceeds data area"));
        }
        Ok(length)
    }

    fn next_address(&mut self) -> Result<usize, Type2Error<T::Error>> {
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
        let address = self.address;
        Type2Page::containing(address)?;
        self.remaining -= 1;
        self.address += 1;
        Ok(address)
    }

    fn window(&mut self, address: usize) -> Result<&[u8; 16], Type2Error<T::Error>> {
        let start = address / 16 * 16;
        if self.cached_start != start {
            self.cache = type2_read_window(self.card, Type2Page::containing(start)?)?;
            self.cached_start = start;
        }
        Ok(&self.cache)
    }

    fn byte(&mut self) -> Result<u8, Type2Error<T::Error>> {
        let address = self.next_address()?;
        Ok(self.window(address)?[address % 16])
    }

    fn prepare_write(&mut self, message: &[u8]) -> Result<Type2Write, Type2Error<T::Error>> {
        if !self.writable {
            return Err(Error::WriteAccess);
        }
        if !self.find_message()? {
            return Err(Error::MissingMessageTlv);
        }
        let position = (self.address, self.remaining);
        self.tlv_length()?;
        (self.address, self.remaining) = position;

        let address = self.next_address()?;
        let length_page = Type2Page::containing(address)?;
        let length_index = address % 4;
        let mut unpublished = self.page(length_page)?;
        unpublished[length_index] = 0;

        let available = self
            .remaining
            .saturating_sub(2)
            .max(self.remaining.min(254));
        if message.len() > available {
            return Err(Error::Capacity {
                requested: message.len(),
                available,
            });
        }
        let length = if message.len() <= 254 {
            message.len() as u8
        } else {
            0xff
        };
        let mut data = BTreeMap::new();
        if length == 0xff {
            for byte in (message.len() as u16).to_be_bytes() {
                self.patch_byte(&mut data, byte, 0)?;
            }
        }
        for &byte in message {
            self.patch_byte(&mut data, byte, 1)?;
        }
        if self.remaining != 0 {
            self.patch_byte(&mut data, 0xfe, 0)?;
        }
        // The length page can also hold payload or the rest of the extended
        // length. Keep the leading length byte zero throughout staging.
        let mut published = unpublished;
        if let Some(page) = data.get_mut(&length_page) {
            page.bytes[length_index] = 0;
            published = page.bytes;
        }
        published[length_index] = length;
        Ok(Type2Write {
            length_page,
            unpublished,
            data,
            published,
        })
    }

    fn patch_byte(
        &mut self,
        pages: &mut BTreeMap<Type2Page, PagePatch>,
        value: u8,
        message_bytes: usize,
    ) -> Result<(), Type2Error<T::Error>> {
        let address = self.next_address()?;
        let page = Type2Page::containing(address)?;
        use alloc::collections::btree_map::Entry;
        let patch = match pages.entry(page) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(PagePatch {
                bytes: self.page(page)?,
                message_bytes: 0,
            }),
        };
        patch.bytes[address % 4] = value;
        patch.message_bytes += message_bytes;
        Ok(())
    }

    fn page(&mut self, page: Type2Page) -> Result<[u8; 4], Type2Error<T::Error>> {
        let offset = page.offset();
        let start = offset % 16;
        let window = self.window(offset)?;
        Ok(core::array::from_fn(|index| window[start + index]))
    }

    fn write_page(&mut self, page: Type2Page, data: [u8; 4]) -> Result<(), Type2Error<T::Error>> {
        let [a, b, c, d] = data;
        let (sector, address) = page.wire_address();
        select_sector(self.card, sector)?;
        match type2_exchange(self.card, &[0xa2, address, a, b, c, d])?.as_slice() {
            [0x0a] => Ok(()),
            [] => {
                // A status-only completion carries no card ACK to inspect.
                let window = type2_read_window(self.card, page)?;
                if window[..4] != data {
                    return Err(Error::Layout("Type 2 WRITE readback"));
                }
                Ok(())
            }
            [nak @ (0 | 1 | 4 | 5)] => Err(Error::Type2Nak(*nak)),
            _ => Err(Error::Layout("Type 2 WRITE response")),
        }
    }
}

fn type2_read_window<T: Transport>(
    card: &mut TypeACard<'_, T>,
    page: Type2Page,
) -> Result<[u8; 16], Type2Error<T::Error>> {
    let (sector, address) = page.wire_address();
    select_sector(card, sector)?;
    type2_exchange(card, &[0x30, address])?
        .try_into()
        .map_err(|_| Error::Layout("Type 2 READ length"))
}

fn select_sector<T: Transport>(
    card: &mut TypeACard<'_, T>,
    sector: u8,
) -> Result<(), Type2Error<T::Error>> {
    if card.type2_sector() == sector {
        return Ok(());
    }
    let selected = (|| {
        match type2_exchange(card, &[0xc2, 0xff])?.as_slice() {
            [0x0a] => {}
            [nak @ (0 | 1 | 4 | 5)] => return Err(Error::Type2Nak(*nak)),
            _ => return Err(Error::Layout("Type 2 SECTOR SELECT first response")),
        }
        // The second packet succeeds with a passive ACK. Only a reader RF
        // timeout demonstrates silence; a lost USB response leaves it unknown.
        match card.exchange(&[sector, 0, 0, 0]) {
            Err(TypeAExchangeError::Exchange(reader::Error::RfStatus(1))) => Ok(()),
            Ok(reply) if reply.status == 0 => match reply.data.as_slice() {
                [nak @ (0 | 1 | 4 | 5)] => Err(Error::Type2Nak(*nak)),
                _ => Err(Error::Layout("Type 2 SECTOR SELECT second response")),
            },
            Ok(reply) => Err(Error::Type2ReaderStatus(reply.status)),
            Err(error) => Err(Error::Exchange(error)),
        }
    })();
    if selected.is_ok() {
        card.record_type2_sector(sector);
    } else {
        card.invalidate();
    }
    selected
}

fn type2_exchange<T: Transport>(
    card: &mut TypeACard<'_, T>,
    command: &[u8],
) -> Result<Vec<u8>, Type2Error<T::Error>> {
    let response = card.exchange(command).map_err(Error::Exchange)?;
    if response.status != 0 {
        return Err(Error::Type2ReaderStatus(response.status));
    }
    Ok(response.data)
}
