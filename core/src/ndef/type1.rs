use super::{Error, UpdateStage, WriteError, control_range};
use crate::{
    reader::{Type1Tag, TypeAExchangeError},
    transport::Transport,
};
use alloc::vec::Vec;

/// Failure while retrieving an NDEF message from a Type 1 tag.
pub type Type1Error<E> = Error<TypeAExchangeError<E>>;

/// Failure while replacing an NDEF message on a Type 1 tag.
pub type Type1WriteError<E> = WriteError<TypeAExchangeError<E>>;

impl<T: Transport> Type1Tag<'_, T> {
    /// Read the first NDEF TLV on a legacy Type 1 tag with 120 bytes of
    /// physical memory. A tag with dynamic memory is outside this profile.
    pub fn read_ndef(&mut self) -> Result<Option<Vec<u8>>, Type1Error<T::Error>> {
        let memory = self.read_mapping()?;
        let Some(message) = StaticMessage::locate(&memory)? else {
            return Ok(None);
        };
        let data = message.positions[1..1 + message.length]
            .iter()
            .map(|address| memory[usize::from(*address)])
            .collect();
        Ok(Some(data))
    }

    /// Replace the first NDEF TLV in a writable static Type 1 mapping.
    /// The tag's block locks are checked for every affected address.
    pub fn write_ndef(&mut self, data: &[u8]) -> Result<(), Type1WriteError<T::Error>> {
        let memory = self.read_mapping().map_err(WriteError::Preparation)?;
        let message = StaticMessage::locate(&memory)
            .map_err(WriteError::Preparation)?
            .ok_or(WriteError::Preparation(Error::MissingMessageTlv))?;
        if memory[11] & 0x0f != 0 {
            return Err(WriteError::Preparation(Error::WriteAccess));
        }
        let [length_address, slots @ ..] = message.positions.as_slice() else {
            return Err(WriteError::Preparation(Error::Layout(
                "Type 1 TLV length address",
            )));
        };
        // The static mapping has fewer TLV slots than a one-byte length can count.
        let encoded_length = u8::try_from(data.len())
            .ok()
            .filter(|_| data.len() <= slots.len())
            .ok_or(WriteError::Preparation(Error::Capacity {
                requested: data.len(),
                available: slots.len(),
            }))?;
        let terminator = slots.get(data.len()).copied();
        let locks = u16::from_le_bytes([memory[112], memory[113]]);
        let touched = core::iter::once(*length_address)
            .chain(slots[..data.len()].iter().copied())
            .chain(terminator);
        if touched
            .into_iter()
            .any(|address| locks & (1 << (address / 8)) != 0)
        {
            return Err(WriteError::Preparation(Error::WriteAccess));
        }
        self.write_byte(*length_address, 0)
            .map_err(|error| WriteError::update(UpdateStage::Begin, 0, Error::Exchange(error)))?;
        for (written, (&address, &byte)) in slots.iter().zip(data).enumerate() {
            self.write_byte(address, byte).map_err(|error| {
                WriteError::update(UpdateStage::Data, written, Error::Exchange(error))
            })?;
        }
        if let Some(address) = terminator {
            self.write_byte(address, 0xfe).map_err(|error| {
                WriteError::update(UpdateStage::Data, data.len(), Error::Exchange(error))
            })?;
        }
        if !data.is_empty() {
            self.write_byte(*length_address, encoded_length)
                .map_err(|error| {
                    WriteError::update(UpdateStage::Publish, data.len(), Error::Exchange(error))
                })?;
        }
        Ok(())
    }

    fn read_mapping(&mut self) -> Result<[u8; 120], Type1Error<T::Error>> {
        if self.header_rom()[0] != 0x11 {
            return Err(Error::UnsupportedMapping);
        }
        let memory = self.read_static().map_err(Error::Exchange)?;
        if memory[8] != 0xe1 || memory[9] >> 4 != 1 || memory[10] != 0x0e {
            return Err(Error::UnsupportedMapping);
        }
        if memory[11] >> 4 != 0 {
            return Err(Error::ReadAccess);
        }
        Ok(memory)
    }
}

struct StaticMessage {
    positions: Vec<u8>,
    length: usize,
}

impl StaticMessage {
    fn locate<E>(memory: &[u8; 120]) -> Result<Option<Self>, Error<E>> {
        // Static blocks D and E contain reserved bytes, locks and OTP bits.
        let mut positions: Vec<u8> = (12..104).collect();
        let mut offset = 0;
        while let Some(&address) = positions.get(offset) {
            offset += 1;
            let tag = memory[usize::from(address)];
            if tag == 0 {
                continue;
            }
            if tag == 0xfe {
                break;
            }
            let Some(&length_address) = positions.get(offset) else {
                return Err(Error::Layout("Type 1 TLV length"));
            };
            let length = usize::from(memory[usize::from(length_address)]);
            let value = offset + 1;
            let end = value + length;
            if end > positions.len() {
                return Err(Error::Layout("Type 1 TLV exceeds data area"));
            }
            if tag == 3 {
                positions.drain(..offset);
                return Ok(Some(Self { positions, length }));
            }
            if matches!(tag, 1 | 2) {
                let [a, b, c] = positions[value..end] else {
                    return Err(Error::Layout("Type 1 control TLV length"));
                };
                let next_address = usize::from(c) + 1;
                let range = control_range(
                    tag,
                    [
                        memory[usize::from(a)],
                        memory[usize::from(b)],
                        memory[usize::from(c)],
                    ],
                )?;
                if range.start < next_address {
                    return Err(Error::Layout("Type 1 control TLV overlaps mapped bytes"));
                }
                positions.retain(|address| !range.contains(&usize::from(*address)));
            }
            offset = end;
        }
        Ok(None)
    }
}
