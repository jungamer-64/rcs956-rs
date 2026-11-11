//! MIFARE Classic block access over the reader's target command interface.

use crate::{
    reader::{TypeACard, TypeAExchangeError},
    transport::Transport,
};
use core::{fmt, ops::RangeInclusive};

/// Key slot to use for Classic sector authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// Authenticate using the sector's key A.
    A,
    /// Authenticate using the sector's key B.
    B,
}

/// Authentication or block access did not complete.
#[derive(Debug)]
pub enum Error<E> {
    /// The selection does not expose a supported Classic layout.
    UnsupportedCard,
    /// The block is not in the selected card or authenticated sector.
    Block(u8),
    /// A previous exchange revoked authentication for this handle.
    AuthenticationLost,
    /// The reader did not return the required status and response length.
    Response {
        /// Raw reader status.
        status: u8,
        /// Length of the returned card data.
        length: usize,
    },
    /// Failure at the reader command boundary.
    Exchange(TypeAExchangeError<E>),
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCard => f.write_str("card has no supported MIFARE Classic layout"),
            Self::Block(block) => write!(f, "block {block} is outside the authenticated sector"),
            Self::AuthenticationLost => f.write_str("sector authentication was revoked"),
            Self::Response { status, length } => {
                write!(f, "reader status {status:02X} with {length} response bytes")
            }
            Self::Exchange(_) => f.write_str("MIFARE Classic exchange failed"),
        }
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

/// Exclusive authority for one authenticated Classic sector. A failed block
/// exchange revokes this handle. Obtain a new authentication to continue.
#[derive(Debug)]
pub struct Sector<'card, 'reader, T: Transport> {
    card: &'card mut TypeACard<'reader, T>,
    blocks: Option<RangeInclusive<u8>>,
}

impl<'reader, T: Transport> TypeACard<'reader, T> {
    /// Authenticate the sector containing `block` using a caller-supplied key.
    /// The selected UID supplies the four-byte authentication input. The
    /// reader performs Crypto1. A successful reply grants access to that sector.
    pub fn authenticate_mifare_classic(
        &mut self,
        block: u8,
        kind: KeyKind,
        key: &[u8; 6],
    ) -> Result<Sector<'_, 'reader, T>, Error<T::Error>> {
        let observation = self.observation();
        let maximum = match observation.sel_res() {
            0x09 => 19,
            0x08 => 63,
            0x18 => 255,
            _ => return Err(Error::UnsupportedCard),
        };
        let uid = match observation.uid() {
            uid if matches!(uid.len(), 4 | 7) => &uid[uid.len() - 4..],
            _ => return Err(Error::UnsupportedCard),
        };
        if block > maximum {
            return Err(Error::Block(block));
        }
        let mut command = [0; 12];
        command[0] = match kind {
            KeyKind::A => 0x60,
            KeyKind::B => 0x61,
        };
        command[1] = block;
        command[2..8].copy_from_slice(key);
        command[8..].copy_from_slice(uid);
        let response = self.exchange(&command).map_err(Error::Exchange)?;
        if response.status != 0 || !response.data.is_empty() {
            return Err(Error::Response {
                status: response.status,
                length: response.data.len(),
            });
        }
        let sector_mask = if block >= 128 { 15 } else { 3 };
        Ok(Sector {
            card: self,
            blocks: Some((block & !sector_mask)..=(block | sector_mask)),
        })
    }
}

impl<T: Transport> Sector<'_, '_, T> {
    /// Read a block within this authenticated sector.
    pub fn read_block(&mut self, block: u8) -> Result<[u8; 16], Error<T::Error>> {
        self.exchange(&[0x30, block])
    }

    /// Write a block within this sector. The caller chooses the address,
    /// including whether to replace a sector trailer. Failure after sending
    /// may leave the write outcome uncertain.
    pub fn write_block(&mut self, block: u8, data: &[u8; 16]) -> Result<(), Error<T::Error>> {
        let mut command = [0; 18];
        command[..2].copy_from_slice(&[0xa0, block]);
        command[2..].copy_from_slice(data);
        let _: [u8; 0] = self.exchange(&command)?;
        Ok(())
    }

    fn exchange<const N: usize>(&mut self, command: &[u8]) -> Result<[u8; N], Error<T::Error>> {
        let block = command[1];
        let blocks = self.blocks.as_ref().ok_or(Error::AuthenticationLost)?;
        if !blocks.contains(&block) {
            return Err(Error::Block(block));
        }
        let blocks = self.blocks.take();
        let response = self.card.exchange(command).map_err(Error::Exchange)?;
        if response.status != 0 || response.data.len() != N {
            return Err(Error::Response {
                status: response.status,
                length: response.data.len(),
            });
        }
        let mut bytes = [0; N];
        bytes.copy_from_slice(&response.data);
        self.blocks = blocks;
        Ok(bytes)
    }
}
