//! FeliCa Standard AES-128 authentication and encrypted block access.
//!
//! The selected card, ordered node keys, and individualization code must
//! belong to the same system. A new CSPRNG challenge is required for every
//! authentication. After sending a command the session can advance only
//! from an authenticated response with a strictly newer transaction number.

use crate::{
    reader::{Error as ReaderError, FelicaCard, RawFelicaCard},
    transport::Transport,
};
use aes::{
    Aes128,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use alloc::vec::Vec;
use cmac::{Cmac, Mac};
use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const SECURE_OVERHEAD: usize = 12;
const MAX_PAYLOAD: usize = u8::MAX as usize - SECURE_OVERHEAD;
const MAX_READ_BLOCKS: usize = (MAX_PAYLOAD - 3) / 16;
const MAX_WRITE_BLOCKS: usize = (MAX_PAYLOAD - 1) / 18;

/// An entry in the authentication node list, paired with its AES key.
pub struct NodeKey<'a> {
    /// Card node code.
    pub code: u16,
    /// AES-128 node key.
    pub key: &'a [u8; 16],
}

impl fmt::Debug for NodeKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeKey")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

/// A block in a service included in the authenticated node list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Block {
    /// Zero-based position of the service in the authentication node list.
    pub service_index: u8,
    /// Block number within the service.
    pub number: u16,
}

/// Issue information authenticated by the card's second proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Issue {
    /// Issue ID in card byte order.
    pub id: [u8; 8],
    /// Issue parameters in card byte order.
    pub parameters: [u8; 8],
}

/// Failure to authenticate or use a FeliCa Standard AES session.
#[derive(Debug)]
pub enum Error<E> {
    /// The authentication needs one to sixteen nodes.
    Nodes(usize),
    /// A read or write request exceeds the secure packet budget.
    BlockCount(usize),
    /// The block refers outside the authenticated node list.
    ServiceIndex(u8),
    /// Authentication, read or write failed at the exchange boundary.
    Exchange {
        /// Card command code identifying the failed step.
        command: u8,
        /// Underlying failure with the reader transaction's progress.
        cause: ReaderError<E>,
    },
    /// The first authentication response did not prove the shared key.
    CardProof,
    /// The response failed layout validation.
    Layout,
    /// The second authentication response or secure message failed its MAC.
    Mac,
    /// The authenticated response did not advance past the sent counter.
    TransactionNumber {
        /// Counter in the command.
        sent: u16,
        /// Counter authenticated in the response.
        received: u16,
    },
    /// The remaining counter space cannot accommodate a command and response.
    CounterExhausted,
    /// The card reported both status flags in an authenticated response.
    Status {
        /// First status flag.
        first: u8,
        /// Second status flag.
        second: u8,
    },
    /// The previous secure exchange failed, revoking the session.
    SessionUnavailable,
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

/// Exclusive FeliCa Standard AES session. Releasing it requires a new card
/// selection before further operations, which clears the card's RF state.
#[derive(Debug)]
pub struct Session<'a, T: Transport> {
    card: RawFelicaCard<'a, T>,
    secure: Option<Secure>,
    issue: Issue,
    nodes: usize,
}

impl<'a, T: Transport> FelicaCard<'a, T> {
    /// Consume the ordinary card selection and authenticate using AES-128.
    /// Nodes appear in the same order in the key derivation and authentication
    /// command. Supply the system's individualization code, its operation
    /// parameter, and a fresh 16-byte CSPRNG challenge.
    pub fn authenticate_standard_aes(
        mut self,
        nodes: &[NodeKey<'_>],
        individualization: &[u8; 16],
        operation_parameter: u8,
        challenge: [u8; 16],
    ) -> Result<Session<'a, T>, Error<T::Error>> {
        if !(1..=16).contains(&nodes.len()) {
            return Err(Error::Nodes(nodes.len()));
        }
        let mut group = Zeroizing::new([0; 16]);
        group[..2].copy_from_slice(&[1, 1]);
        group[15] = 0x80;
        for node in nodes {
            Aes128::new(node.key.into()).encrypt_block((&mut *group).into());
        }
        xor(&mut group[..], individualization);
        let derivation = Aes128::new((&*group).into());
        let mut context = [0; 16];
        context[1] = 2;
        context[6..14].copy_from_slice(self.observation().idm.as_bytes());
        context[14] = 1;
        let alpha = Zeroizing::new(derive(&derivation, context, 1));
        let mut beta = Zeroizing::new(derive(&derivation, context, 2));
        let alpha = Aes128::new((&*alpha).into());

        let challenge = Zeroizing::new(challenge);
        let mut proof = *challenge;
        alpha.encrypt_block((&mut proof).into());
        let mut parameters = Vec::with_capacity(18 + 2 * nodes.len());
        parameters.extend([operation_parameter, nodes.len() as u8]);
        for node in nodes {
            parameters.extend(node.code.to_le_bytes());
        }
        parameters.extend(proof);
        self.begin_felica_authentication();
        let first = self
            .exchange_command(0x40, &parameters, 0x41)
            .map_err(|cause| Error::Exchange {
                command: 0x40,
                cause,
            })?;
        let Some((proof, tail)) = first.split_first_chunk::<16>() else {
            return Err(Error::Layout);
        };
        let Some((encrypted_random, context_bytes)) = tail.split_first_chunk::<16>() else {
            return Err(Error::Layout);
        };
        let [salt, a, b, c] = context_bytes else {
            return Err(Error::Layout);
        };
        xor(&mut beta[..4], &[*salt, *a, *b, *c]);
        let beta = Aes128::new((&*beta).into());
        let mut expected = Zeroizing::new(*challenge);
        beta.encrypt_block((&mut *expected).into());
        if !bool::from(expected.ct_eq(proof)) {
            return Err(Error::CardProof);
        }
        let mut random = Zeroizing::new(*encrypted_random);
        beta.decrypt_block((&mut *random).into());
        let mut host_proof = *random;
        alpha.encrypt_block((&mut host_proof).into());
        let mut request = [0; 26];
        request[..2].copy_from_slice(&[26, 0x42]);
        request[2..10].copy_from_slice(self.observation().idm.as_bytes());
        request[10..].copy_from_slice(&host_proof);
        let mut card = self.into_raw();
        let reply = exchange(&mut card, &request)?;

        let mut key_block = [0; 16];
        key_block[1] = 3;
        key_block[14] = 1;
        let derivation = Aes128::new((&*random).into());
        let encryption = Zeroizing::new(derive(&derivation, key_block, 1));
        let authentication = Zeroizing::new(derive(&derivation, key_block, 2));
        let mut secure = Secure {
            encryption: Aes128::new((&*encryption).into()),
            authentication,
            identifier: core::array::from_fn(|index| challenge[index + 2]),
            salt: [*a, *b, *c],
            counter: 0,
        };
        let (counter, issue) = secure.open(0x43, reply)?;
        let Some((id, parameters)) = issue.split_first_chunk::<8>() else {
            return Err(Error::Layout);
        };
        let parameters = parameters.try_into().map_err(|_| Error::Layout)?;
        secure.counter = counter;
        Ok(Session {
            card,
            secure: Some(secure),
            issue: Issue {
                id: *id,
                parameters,
            },
            nodes: nodes.len(),
        })
    }
}

impl<T: Transport> Session<'_, T> {
    /// Authenticated issue data returned when establishing this session.
    pub fn issue(&self) -> Issue {
        self.issue
    }

    /// Read blocks in request order and verify the response before releasing data.
    pub fn read_blocks(&mut self, blocks: &[Block]) -> Result<Vec<[u8; 16]>, Error<T::Error>> {
        let request = self.block_list(blocks.len(), MAX_READ_BLOCKS, blocks.iter().copied())?;
        self.transact(0x44, request, |reply| {
            let [0, 0, count, data @ ..] = status(reply)? else {
                return Err(Error::Layout);
            };
            if usize::from(*count) != blocks.len() || data.len() != blocks.len() * 16 {
                return Err(Error::Layout);
            }
            Ok(data.as_chunks::<16>().0.to_vec())
        })
    }

    /// Write blocks through the authenticated session. A failure after command
    /// submission may leave the write applied. Reauthenticate to reconcile it.
    pub fn write_blocks(&mut self, blocks: &[(Block, [u8; 16])]) -> Result<(), Error<T::Error>> {
        let mut request = self.block_list(
            blocks.len(),
            MAX_WRITE_BLOCKS,
            blocks.iter().map(|(block, _)| *block),
        )?;
        if request.len() + blocks.len() * 16 > MAX_PAYLOAD {
            return Err(Error::BlockCount(blocks.len()));
        }
        for (_, data) in blocks {
            request.extend(data);
        }
        self.transact(0x46, request, |reply| {
            if status(reply)? != [0, 0] {
                return Err(Error::Layout);
            }
            Ok(())
        })
    }

    fn block_list(
        &self,
        count: usize,
        maximum: usize,
        blocks: impl Iterator<Item = Block>,
    ) -> Result<Zeroizing<Vec<u8>>, Error<T::Error>> {
        if !(1..=maximum).contains(&count) {
            return Err(Error::BlockCount(count));
        }
        let mut request = Zeroizing::new(Vec::with_capacity(1 + count * 19));
        request.push(count as u8);
        for block in blocks {
            if usize::from(block.service_index) >= self.nodes {
                return Err(Error::ServiceIndex(block.service_index));
            }
            let [low, high] = block.number.to_le_bytes();
            if high == 0 {
                request.extend([0x80 | block.service_index, low]);
            } else {
                request.extend([block.service_index, low, high]);
            }
        }
        Ok(request)
    }

    fn transact<U>(
        &mut self,
        command: u8,
        mut payload: Zeroizing<Vec<u8>>,
        decode: impl FnOnce(&[u8]) -> Result<U, Error<T::Error>>,
    ) -> Result<U, Error<T::Error>> {
        let mut secure = self.secure.take().ok_or(Error::SessionUnavailable)?;
        let sent = secure
            .counter
            .checked_add(1)
            .filter(|counter| *counter < u16::MAX)
            .ok_or(Error::CounterExhausted)?;
        let request = secure.seal(command, sent, &mut payload);
        let reply = exchange(&mut self.card, &request)?;
        let (received, plaintext) = secure.open(command + 1, reply)?;
        if received <= sent {
            return Err(Error::TransactionNumber { sent, received });
        }
        let result = decode(&plaintext)?;
        secure.counter = received;
        self.secure = Some(secure);
        Ok(result)
    }
}

fn exchange<T: Transport>(
    card: &mut RawFelicaCard<'_, T>,
    packet: &[u8],
) -> Result<Vec<u8>, Error<T::Error>> {
    card.exchange_packet(packet)
        .map_err(|cause| Error::Exchange {
            command: packet[1],
            cause,
        })
}

fn status<E>(payload: &[u8]) -> Result<&[u8], Error<E>> {
    match payload {
        [0, 0, ..] => Ok(payload),
        [first, second, ..] => Err(Error::Status {
            first: *first,
            second: *second,
        }),
        _ => Err(Error::Layout),
    }
}

#[derive(Debug)]
struct Secure {
    encryption: Aes128,
    authentication: Zeroizing<[u8; 16]>,
    identifier: [u8; 6],
    salt: [u8; 3],
    counter: u16,
}

impl Secure {
    fn iv(&self, length: u8, code: u8, counter: [u8; 2]) -> [u8; 16] {
        let mut iv = [0; 16];
        iv[..5].copy_from_slice(&[1, length, code, counter[0], counter[1]]);
        iv[5..11].copy_from_slice(&self.identifier);
        iv[11..14].copy_from_slice(&self.salt);
        iv
    }

    fn seal(&self, code: u8, counter: u16, payload: &mut [u8]) -> Vec<u8> {
        let length = (SECURE_OVERHEAD + payload.len()) as u8;
        let counter = counter.to_le_bytes();
        let iv = self.iv(length, code, counter);
        let mut mac = self.mac(iv, payload);
        self.crypt(iv, payload, &mut mac);
        let mut packet = Vec::with_capacity(usize::from(length));
        packet.extend([length, code, counter[0], counter[1]]);
        packet.extend_from_slice(payload);
        packet.extend(mac);
        packet
    }

    fn open<E>(&self, code: u8, packet: Vec<u8>) -> Result<(u16, Zeroizing<Vec<u8>>), Error<E>> {
        let [length, response_code, low, high, tail @ ..] = packet.as_slice() else {
            return Err(Error::Layout);
        };
        if *response_code != code || usize::from(*length) != packet.len() || tail.len() < 8 {
            return Err(Error::Layout);
        }
        let mut plaintext = Zeroizing::new(tail.to_vec());
        let payload_len = plaintext.len() - 8;
        let (payload, mac) = plaintext.split_at_mut(payload_len);
        let iv = self.iv(*length, code, [*low, *high]);
        self.crypt(iv, payload, mac);
        if !bool::from(self.mac(iv, payload).ct_eq(mac)) {
            return Err(Error::Mac);
        }
        plaintext.truncate(payload_len);
        Ok((u16::from_le_bytes([*low, *high]), plaintext))
    }

    fn crypt(&self, iv: [u8; 16], payload: &mut [u8], mac: &mut [u8]) {
        // The FeliCa OFB stream starts the tag on its own block boundary.
        let mut stream = Zeroizing::new(iv);
        for part in payload.chunks_mut(16).chain(core::iter::once(mac)) {
            self.encryption.encrypt_block((&mut *stream).into());
            xor(part, &*stream);
        }
    }

    fn mac(&self, mut header: [u8; 16], payload: &[u8]) -> [u8; 8] {
        header[0] = 0x19;
        header[14..].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let mut mac = <Cmac<Aes128> as cmac::KeyInit>::new((&*self.authentication).into());
        mac.update(&header);
        mac.update(payload);
        let tag = mac.finalize().into_bytes();
        core::array::from_fn(|index| tag[index])
    }
}

fn derive(cipher: &Aes128, mut block: [u8; 16], prefix: u8) -> [u8; 16] {
    block[0] = prefix;
    cipher.encrypt_block((&mut block).into());
    block
}

fn xor(data: &mut [u8], mask: &[u8]) {
    for (byte, mask) in data.iter_mut().zip(mask) {
        *byte ^= mask;
    }
}
