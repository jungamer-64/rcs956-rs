use super::{Error, UpdateStage, WriteError};
use crate::{
    felica::{BitRate, BlockWrite, MAX_READ_BLOCKS, MAX_WRITE_BLOCKS, PollRequest},
    reader::{self, FelicaCard, Reader, RfTimeout},
    transport::Transport,
};
use alloc::vec::Vec;

const SYSTEM: u16 = 0x12fc;
const READ_SERVICE: u16 = 0x000b;
const WRITE_SERVICE: u16 = 0x0009;
const BLOCK_BYTES: usize = 16;

/// A selected NFC Forum Type 3 system. Its IDm comes from polling system 12FC.
#[derive(Debug)]
pub struct Type3Tag<'a, T: Transport>(FelicaCard<'a, T>);

impl<T: Transport> Reader<T> {
    /// Poll for one NFC Forum Type 3 system at the selected FeliCa rate.
    /// The NDEF mapping is checked when a message is accessed.
    pub fn poll_type3(
        &mut self,
        rate: BitRate,
        timeout: RfTimeout,
    ) -> Result<Option<Type3Tag<'_, T>>, reader::Error<T::Error>> {
        let request = PollRequest::new(SYSTEM, 0, 0).map_err(reader::Error::FelicaRequest)?;
        self.poll_felica(rate, request, timeout)
            .map(|card| card.map(Type3Tag))
    }
}

impl<T: Transport> Type3Tag<'_, T> {
    /// Read the message from an initialized Type 3 mapping. An empty mapping
    /// returns an empty vector. An interrupted update is reported separately.
    pub fn read_ndef(&mut self) -> Result<Vec<u8>, Error<reader::Error<T::Error>>> {
        let attribute = self.attribute()?;
        let length = attribute.length();
        let mut data = Vec::with_capacity(length);
        let mut blocks = BlockRange::for_bytes(length)?;
        let limit = usize::from(attribute.0[1]).min(MAX_READ_BLOCKS);
        while !blocks.is_empty() {
            let batch: Vec<_> = blocks.take(limit).collect();
            let response = self
                .0
                .read_without_encryption(READ_SERVICE, &batch)
                .map_err(Error::Exchange)?;
            for block in response.blocks() {
                data.extend_from_slice(&block[..(length - data.len()).min(BLOCK_BYTES)]);
            }
        }
        Ok(data)
    }

    /// Replace the message in a writable Type 3 mapping. An empty slice
    /// clears it. The tag's write flag stays set until publication succeeds.
    pub fn write_ndef(
        &mut self,
        message: &[u8],
    ) -> Result<(), WriteError<reader::Error<T::Error>>> {
        let attribute = self.attribute().map_err(WriteError::Preparation)?;
        let capacity = attribute.capacity();
        let limit = usize::from(attribute.0[2]).min(MAX_WRITE_BLOCKS);
        if attribute.0[10] != 1 || limit == 0 {
            return Err(WriteError::Preparation(Error::WriteAccess));
        }
        let capacity_error = || {
            WriteError::Preparation(Error::Capacity {
                requested: message.len(),
                available: capacity,
            })
        };
        if message.len() > capacity {
            return Err(capacity_error());
        }
        let encoded_length = Attribute::encode_length(message.len()).ok_or_else(capacity_error)?;
        let mut blocks = BlockRange::for_bytes(message.len()).map_err(WriteError::Preparation)?;
        self.write_attribute(attribute.update_started())
            .map_err(|cause| WriteError::update(UpdateStage::Begin, 0, cause))?;
        let mut written = 0;
        while !blocks.is_empty() {
            // A long block address uses one extra packet byte. Thirteen
            // long-addressed blocks would exceed the FeliCa length field.
            let count = if blocks
                .next()
                .is_some_and(|next| usize::from(next) + limit <= 256)
            {
                limit
            } else {
                limit.min(12)
            };
            let mut end = written;
            let batch: Vec<_> = blocks
                .take(count)
                .map(|block| {
                    let mut data = [0; BLOCK_BYTES];
                    let len = (message.len() - end).min(BLOCK_BYTES);
                    data[..len].copy_from_slice(&message[end..end + len]);
                    end += len;
                    BlockWrite { block, data }
                })
                .collect();
            self.0
                .write_without_encryption(WRITE_SERVICE, &batch)
                .map_err(|error| {
                    WriteError::update(UpdateStage::Data, written, Error::Exchange(error))
                })?;
            written = end;
        }
        self.write_attribute(attribute.published(encoded_length))
            .map_err(|cause| WriteError::update(UpdateStage::Publish, written, cause))
    }

    fn attribute(&mut self) -> Result<Attribute, Error<reader::Error<T::Error>>> {
        let response = self
            .0
            .read_without_encryption(READ_SERVICE, &[0])
            .map_err(Error::Exchange)?;
        let [block] = response.blocks() else {
            return Err(Error::Layout("Type 3 attribute block count"));
        };
        Attribute::parse(*block)
    }

    fn write_attribute(&mut self, data: [u8; 16]) -> Result<(), Error<reader::Error<T::Error>>> {
        self.0
            .write_without_encryption(WRITE_SERVICE, &[BlockWrite { block: 0, data }])
            .map_err(Error::Exchange)
    }
}

struct Attribute([u8; 16]);

impl Attribute {
    fn parse<E>(block: [u8; 16]) -> Result<Self, Error<E>> {
        if checksum(&block).to_be_bytes() != block[14..] {
            return Err(Error::Layout("Type 3 attribute checksum"));
        }
        if block[0] >> 4 != 1 {
            return Err(Error::UnsupportedMapping);
        }
        if block[9] == 0x0f {
            return Err(Error::WriteInProgress);
        }
        let attribute = Self(block);
        if block[1] == 0
            || block[5..9] != [0; 4]
            || block[9] != 0
            || block[10] > 1
            || attribute.length() > attribute.capacity()
        {
            return Err(Error::Layout("Type 3 attribute fields"));
        }
        Ok(attribute)
    }

    fn length(&self) -> usize {
        (usize::from(self.0[11]) << 16) | usize::from(u16::from_be_bytes([self.0[12], self.0[13]]))
    }

    fn capacity(&self) -> usize {
        usize::from(u16::from_be_bytes([self.0[3], self.0[4]])) * BLOCK_BYTES
    }

    fn update_started(&self) -> [u8; 16] {
        let mut block = self.0;
        block[9] = 0x0f;
        let checksum = checksum(&block);
        block[14..].copy_from_slice(&checksum.to_be_bytes());
        block
    }

    /// The attribute's 24-bit big-endian length field.
    fn encode_length(length: usize) -> Option<[u8; 3]> {
        match u32::try_from(length).map(u32::to_be_bytes) {
            Ok([0, a, b, c]) => Some([a, b, c]),
            _ => None,
        }
    }

    fn published(self, length: [u8; 3]) -> [u8; 16] {
        let mut block = self.0;
        block[11..14].copy_from_slice(&length);
        let checksum = checksum(&block);
        block[14..].copy_from_slice(&checksum.to_be_bytes());
        block
    }
}

fn checksum(block: &[u8; 16]) -> u16 {
    block[..14].iter().copied().map(u16::from).sum()
}

/// Data blocks 1 through the last block holding the message.
struct BlockRange(core::ops::RangeInclusive<u16>);

impl BlockRange {
    fn for_bytes<E>(length: usize) -> Result<Self, Error<E>> {
        let last = u16::try_from(length.div_ceil(BLOCK_BYTES))
            .map_err(|_| Error::Layout("Type 3 block number"))?;
        Ok(Self(1..=last))
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn next(&self) -> Option<u16> {
        self.0.clone().next()
    }

    fn take(&mut self, limit: usize) -> impl Iterator<Item = u16> {
        self.0.by_ref().take(limit)
    }
}
