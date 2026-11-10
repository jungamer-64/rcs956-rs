//! FeliCa Lite-S mutual authentication and MAC_A-protected block access.
//!
//! A fresh, unpredictable challenge is required for each authentication.
//! The session authenticates blocks and block numbers. Payloads remain in
//! cleartext, and a read MAC does not provide per-command replay protection.
//! The TDES backend is intended for this legacy card protocol and may have
//! key-dependent memory access.

use super::BlockWrite;
use crate::{
    reader::{Error as ReaderError, FelicaCard},
    transport::Transport,
};
use core::fmt;
use des::{
    TdesEde2,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const READ_SERVICE: u16 = 0x000b;
const WRITE_SERVICE: u16 = 0x0009;
const CHALLENGE: u16 = 0x80;
const IDENTITY: u16 = 0x82;
const WRITE_COUNTER: u16 = 0x90;
const MAC_A: u16 = 0x91;
const STATE: u16 = 0x92;

/// A Lite-S application block. System and issuance blocks have no public
/// write authority through the authenticated session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserBlock(u8);

impl UserBlock {
    /// Accept the scratchpad blocks and the subtraction register (00–0E).
    pub fn new(number: u8) -> Option<Self> {
        (number <= 0x0e).then_some(Self(number))
    }
}

/// The operation during which a card or transport exchange failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Set the volatile challenge on the card.
    Challenge,
    /// Read and authenticate the selected identity and initial counter.
    CardProof,
    /// Write the MAC that proves knowledge of the card key.
    HostProof,
    /// Confirm the card's authenticated state.
    ConfirmAuthentication,
    /// Retrieve and authenticate a user block.
    Read,
    /// Retrieve and authenticate the counter before a write.
    ReadCounter,
    /// Submit the protected write. Its effect may be uncertain on failure.
    Write,
}

/// Failure to authenticate or operate on a Lite-S session.
#[derive(Debug)]
pub enum Error<E> {
    /// The polling response does not identify a FeliCa Lite-S IC (F1).
    UnsupportedCard(u8),
    /// A failed exchange or proof revoked this authenticated session.
    SessionUnavailable,
    /// An underlying request, transport, or card response failure.
    Exchange {
        /// Operation that was in progress.
        stage: Stage,
        /// Original exchange failure, including command progress.
        cause: ReaderError<E>,
    },
    /// The returned block data and addresses did not authenticate.
    MacMismatch(Stage),
    /// The authenticated ID block does not begin with the selected IDm.
    IdentityMismatch,
    /// The counter block has nonzero reserved bytes.
    CounterLayout,
    /// The card has not entered the authenticated state.
    AuthenticationState(u8),
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Exchange { cause, .. } => Some(cause),
            _ => None,
        }
    }
}

/// One mutually authenticated card selection and its session keys. A failed
/// operation revokes these keys. The next reader selection clears RF state.
#[derive(Debug)]
pub struct AuthenticatedCard<'a, T: Transport> {
    card: FelicaCard<'a, T>,
    keys: Option<SessionKeys>,
}

impl<'a, T: Transport> FelicaCard<'a, T> {
    /// Authenticate a Lite-S card selected in system 88B4. Supply the card
    /// key in card byte order and a new 16-byte challenge from a CSPRNG.
    /// Authentication consumes the ordinary selection and never retries.
    pub fn authenticate_lite_s(
        mut self,
        card_key: &[u8; 16],
        challenge: [u8; 16],
    ) -> Result<AuthenticatedCard<'a, T>, Error<T::Error>> {
        let identity = *self.observation();
        if identity.pmm[1] != 0xf1 {
            return Err(Error::UnsupportedCard(identity.pmm[1]));
        }
        let keys = SessionKeys::derive(card_key, challenge);
        self.begin_felica_authentication();
        write(
            &mut self,
            Stage::Challenge,
            &[BlockWrite {
                block: CHALLENGE,
                data: challenge,
            }],
        )?;
        let [id, counter] = keys.read(&mut self, Stage::CardProof, [IDENTITY, WRITE_COUNTER])?;
        // The ID block holds IDm, DFC and an issuer-defined value; PMm is not part of it.
        if &id[..8] != identity.idm.as_bytes() {
            return Err(Error::IdentityMismatch);
        }
        let mut state = [0; 16];
        state[0] = 1;
        keys.write(
            &mut self,
            Stage::HostProof,
            STATE,
            state,
            counter_bytes(counter)?,
        )?;
        let [state] = keys.read(&mut self, Stage::ConfirmAuthentication, [STATE])?;
        if state[0] != 1 {
            return Err(Error::AuthenticationState(state[0]));
        }
        Ok(AuthenticatedCard {
            card: self,
            keys: Some(keys),
        })
    }
}

impl<T: Transport> AuthenticatedCard<'_, T> {
    /// Read a user block and verify its MAC before returning the data.
    pub fn read_block(&mut self, block: UserBlock) -> Result<[u8; 16], Error<T::Error>> {
        self.with_keys(|keys, card| {
            let [data] = keys.read(card, Stage::Read, [u16::from(block.0)])?;
            Ok(data)
        })
    }

    /// Submit a write using the current authenticated write counter. Success
    /// reports the card's write status. A failure at `Stage::Write` may leave
    /// the write applied. Reauthenticate and inspect the card to reconcile it.
    pub fn write_block(&mut self, block: UserBlock, data: [u8; 16]) -> Result<(), Error<T::Error>> {
        self.with_keys(|keys, card| {
            let [counter] = keys.read(card, Stage::ReadCounter, [WRITE_COUNTER])?;
            keys.write(
                card,
                Stage::Write,
                u16::from(block.0),
                data,
                counter_bytes(counter)?,
            )
        })
    }

    fn with_keys<U>(
        &mut self,
        operation: impl FnOnce(&SessionKeys, &mut FelicaCard<'_, T>) -> Result<U, Error<T::Error>>,
    ) -> Result<U, Error<T::Error>> {
        let keys = self.keys.take().ok_or(Error::SessionUnavailable)?;
        let result = operation(&keys, &mut self.card)?;
        self.keys = Some(keys);
        Ok(result)
    }
}

fn counter_bytes<E>(data: [u8; 16]) -> Result<[u8; 3], Error<E>> {
    let [a, b, c, tail @ ..] = data;
    if tail != [0; 13] {
        return Err(Error::CounterLayout);
    }
    Ok([a, b, c])
}

fn write<T: Transport>(
    card: &mut FelicaCard<'_, T>,
    stage: Stage,
    blocks: &[BlockWrite],
) -> Result<(), Error<T::Error>> {
    card.write_without_encryption(WRITE_SERVICE, blocks)
        .map_err(|cause| Error::Exchange { stage, cause })
}

#[derive(Debug)]
struct SessionKeys {
    read: TdesEde2,
    write: TdesEde2,
    iv: [u8; 8],
}

impl SessionKeys {
    fn derive(card_key: &[u8; 16], [rc1 @ .., a, b, c, d, e, f, g, h]: [u8; 16]) -> Self {
        let rc2 = [a, b, c, d, e, f, g, h];
        let mut key = Zeroizing::new(*card_key);
        key[..8].reverse();
        key[8..].reverse();
        let cipher = TdesEde2::new((&*key).into());
        let mut chain = Zeroizing::new([0; 8]);
        cbc_step(&cipher, &mut chain, &rc1);
        key[..8].copy_from_slice(&*chain);
        cbc_step(&cipher, &mut chain, &rc2);
        key[8..].copy_from_slice(&*chain);
        let read = TdesEde2::new((&*key).into());
        key.rotate_left(8);
        let write = TdesEde2::new((&*key).into());
        Self {
            read,
            write,
            iv: rc1,
        }
    }

    fn read<T: Transport, const N: usize>(
        &self,
        card: &mut FelicaCard<'_, T>,
        stage: Stage,
        blocks: [u16; N],
    ) -> Result<[[u8; 16]; N], Error<T::Error>> {
        // One MAC_A block follows at most three data blocks in a four-block read.
        const { assert!(N >= 1 && N <= 3) };
        let mut request = [MAC_A; 4];
        request[..N].copy_from_slice(&blocks);
        let request = &request[..=N];
        let response = card
            .read_without_encryption(READ_SERVICE, request)
            .map_err(|cause| Error::Exchange { stage, cause })?;
        // read_without_encryption checks the exact requested block count.
        let data = &response.blocks()[..N];
        let actual = &response.blocks()[N][..8];
        if !bool::from(self.read_mac(request, data).ct_eq(actual)) {
            return Err(Error::MacMismatch(stage));
        }
        Ok(core::array::from_fn(|index| data[index]))
    }

    fn read_mac(&self, blocks: &[u16], data: &[[u8; 16]]) -> [u8; 8] {
        let mut addresses = [0xff; 8];
        for (field, address) in addresses.as_chunks_mut::<2>().0.iter_mut().zip(blocks) {
            *field = address.to_le_bytes();
        }
        self.mac(&self.read, addresses, data)
    }

    fn write<T: Transport>(
        &self,
        card: &mut FelicaCard<'_, T>,
        stage: Stage,
        block: u16,
        data: [u8; 16],
        counter: [u8; 3],
    ) -> Result<(), Error<T::Error>> {
        write(
            card,
            stage,
            &[
                BlockWrite { block, data },
                BlockWrite {
                    block: MAC_A,
                    data: self.write_proof(block, &data, counter),
                },
            ],
        )
    }

    fn write_proof(&self, block: u16, data: &[u8; 16], counter: [u8; 3]) -> [u8; 16] {
        let [a, b, c] = counter;
        let [low, high] = block.to_le_bytes();
        let header = [a, b, c, 0, low, high, MAC_A as u8, 0];
        let mut proof = [0; 16];
        proof[..8].copy_from_slice(&self.mac(&self.write, header, core::slice::from_ref(data)));
        proof[8..11].copy_from_slice(&counter);
        proof
    }

    fn mac(&self, cipher: &TdesEde2, header: [u8; 8], data: &[[u8; 16]]) -> [u8; 8] {
        let mut chain = self.iv;
        chain.reverse();
        cbc_step(cipher, &mut chain, &header);
        for block in data.as_flattened().as_chunks::<8>().0 {
            cbc_step(cipher, &mut chain, block);
        }
        chain.reverse();
        chain
    }
}

fn cbc_step(cipher: &TdesEde2, chain: &mut [u8; 8], little_endian: &[u8; 8]) {
    for (out, byte) in chain.iter_mut().zip(little_endian.iter().rev()) {
        *out ^= byte;
    }
    cipher.encrypt_block(chain.into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sony_lite_s_mac_a_known_answers() {
        // FeliCa Lite-S User's Manual v1.4, Table 6-12, steps 4–6.
        let keys = SessionKeys::derive(
            &[0xff; 16],
            [
                0xf1, 0x87, 0x5a, 0x01, 0xf9, 0xb2, 0x9e, 0x4c, 0x06, 0xa1, 0xce, 0xc4, 0x16, 0x55,
                0x85, 0xcf,
            ],
        );
        let data = [
            0x29, 0x9f, 0xfa, 0x53, 0xab, 0x75, 0x87, 0x6e, 0x57, 0x4e, 0x10, 0x2a, 0x94, 0x16,
            0xbc, 0x8e,
        ];
        assert_eq!(
            keys.read_mac(&[IDENTITY, MAC_A], &[data]),
            [0xee, 0xf4, 0xb0, 0xbb, 0x5e, 0x3b, 0x6c, 0x8b]
        );
        assert_eq!(
            keys.read_mac(&[IDENTITY, IDENTITY, MAC_A], &[data, data]),
            [0x4e, 0xc7, 0xc5, 0x5a, 0x17, 0x29, 0xca, 0xae]
        );
    }
}
