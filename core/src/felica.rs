//! FeliCa card packets, without RC-S956 command or USB frame envelopes.
//!
//! Identity is session data, not a universally unique or authenticated credential.
//! Service and block numbers are encoded little-endian; polling system codes are
//! encoded big-endian.

use alloc::vec::Vec;
use core::fmt;

/// RF rate selected for FeliCa polling and subsequent exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitRate {
    /// 212 kbps.
    Kbps212,
    /// 424 kbps.
    Kbps424,
}

impl BitRate {
    pub(crate) fn selector(self) -> u8 {
        match self {
            Self::Kbps212 => 1,
            Self::Kbps424 => 2,
        }
    }
}

/// Maximum blocks in one supported Read Without Encryption command.
pub const MAX_READ_BLOCKS: usize = 12;

/// Maximum write blocks that fit a single-service packet with short addresses.
pub const MAX_WRITE_BLOCKS: usize = 13;

/// Eight-byte card identity returned by the selected system's polling response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Idm([u8; 8]);

impl Idm {
    /// Preserve the identity's wire byte order.
    pub const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Borrow the identity bytes in their wire order.
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Display for Idm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// Card packet validation or card-reported status failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CardError {
    /// Polling request code is outside `00/01/02`.
    RequestCode(u8),
    /// Polling slot selector is outside `00/01/03/07/0F`.
    TimeSlots(u8),
    /// Actual bytes do not match the packet's declared or required length.
    Length {
        /// Required packet length.
        expected: usize,
        /// Actual packet length.
        actual: usize,
    },
    /// Unexpected card response command.
    ResponseCode {
        /// Required response command.
        expected: u8,
        /// Actual response command.
        actual: u8,
    },
    /// Read block count is outside the supported baseline range `1..=12`.
    BlockCount(usize),
    /// Write block count is outside `1..=13`.
    WriteBlockCount(usize),
    /// A response belongs to a different selected identity.
    IdentityMismatch {
        /// Identity selected by the caller.
        expected: Idm,
        /// Identity received from the card.
        actual: Idm,
    },
    /// Card-reported operation failure; both status flags are preserved.
    Status {
        /// First status flag.
        flag1: u8,
        /// Second status flag.
        flag2: u8,
    },
    /// A successful response contains a different number of blocks.
    ResponseBlockCount {
        /// Number of requested blocks.
        expected: usize,
        /// Number returned in the response.
        actual: usize,
    },
}

impl fmt::Display for CardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestCode(value) => write!(f, "unsupported polling request {value:02X}"),
            Self::TimeSlots(value) => write!(f, "invalid polling slot selector {value:02X}"),
            Self::Length { expected, actual } => {
                write!(f, "card packet length {actual}, expected {expected}")
            }
            Self::ResponseCode { expected, actual } => {
                write!(f, "card response {actual:02X}, expected {expected:02X}")
            }
            Self::BlockCount(count) => {
                write!(f, "block count {count} is outside 1..={MAX_READ_BLOCKS}")
            }
            Self::WriteBlockCount(count) => {
                write!(
                    f,
                    "write block count {count} is outside 1..={MAX_WRITE_BLOCKS}"
                )
            }
            Self::IdentityMismatch { expected, actual } => {
                write!(f, "card identity {actual}, expected {expected}")
            }
            Self::Status { flag1, flag2 } => write!(f, "card status {flag1:02X} {flag2:02X}"),
            Self::ResponseBlockCount { expected, actual } => {
                write!(f, "response has {actual} blocks, expected {expected}")
            }
        }
    }
}

impl core::error::Error for CardError {}

/// Validated six-byte polling command, including its FeliCa length byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollRequest {
    system: u16,
    request: u8,
    slots: u8,
}

impl PollRequest {
    /// Construct polling parameters. `FF` is a wildcard in each system-code byte.
    ///
    /// # Errors
    ///
    /// Rejects request codes outside `0..=2` and invalid slot selectors.
    pub fn new(system: u16, request: u8, slots: u8) -> Result<Self, CardError> {
        if request > 2 {
            return Err(CardError::RequestCode(request));
        }
        if !matches!(slots, 0 | 1 | 3 | 7 | 15) {
            return Err(CardError::TimeSlots(slots));
        }
        Ok(Self {
            system,
            request,
            slots,
        })
    }

    /// Encode the six-byte card command, without CRC or reader timeout fields.
    pub fn encode(self) -> [u8; 6] {
        let [high, low] = self.system.to_be_bytes();
        [6, 0, high, low, self.request, self.slots]
    }
}

/// Validated polling response; optional bytes depend on the polling request code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollResponse {
    /// Selected system's manufacturing identity, in wire order.
    pub idm: Idm,
    /// Manufacturing parameters, preserved without inferring a product model.
    pub pmm: [u8; 8],
    /// Optional two-byte request data, kept in wire order.
    pub request_data: Option<[u8; 2]>,
}

impl PollResponse {
    /// Decode an 18- or 20-byte polling response, including its card length byte.
    ///
    /// # Errors
    ///
    /// Rejects malformed length, a response command other than `01`, or a packet
    /// shape that cannot contain complete identity and manufacturing parameters.
    pub fn parse(input: &[u8]) -> Result<Self, CardError> {
        validate_packet(input, 0x01, 18)?;
        if input.len() != 18 && input.len() != 20 {
            return Err(CardError::Length {
                expected: 18,
                actual: input.len(),
            });
        }
        let mut idm = [0; 8];
        let mut pmm = [0; 8];
        idm.copy_from_slice(&input[2..10]);
        pmm.copy_from_slice(&input[10..18]);
        let request_data = input.get(18..20).map(|bytes| [bytes[0], bytes[1]]);
        Ok(Self {
            idm: Idm::new(idm),
            pmm,
            request_data,
        })
    }
}

/// Build a one-service Read Without Encryption packet for at most 12 blocks.
///
/// The service code is little-endian. Block numbers through 255 use the two-byte
/// list element; larger numbers use the three-byte form. No CRC is appended.
///
/// # Errors
///
/// Rejects an empty block list or more than 12 blocks. Individual card products
/// can have additional restrictions beyond this baseline packet format.
pub fn read_without_encryption(
    idm: Idm,
    service_code: u16,
    blocks: &[u16],
) -> Result<Vec<u8>, CardError> {
    if !(1..=MAX_READ_BLOCKS).contains(&blocks.len()) {
        return Err(CardError::BlockCount(blocks.len()));
    }
    let mut packet = block_list(0x06, idm, service_code, blocks.iter().copied());
    set_length(&mut packet)?;
    Ok(packet)
}

/// A block address and the 16 bytes to replace at that address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockWrite {
    /// Block number within the selected service.
    pub block: u16,
    /// Replacement bytes in wire order.
    pub data: [u8; 16],
}

pub(crate) fn write_without_encryption(
    idm: Idm,
    service: u16,
    blocks: &[BlockWrite],
) -> Result<Vec<u8>, CardError> {
    if !(1..=MAX_WRITE_BLOCKS).contains(&blocks.len()) {
        return Err(CardError::WriteBlockCount(blocks.len()));
    }
    let mut packet = block_list(0x08, idm, service, blocks.iter().map(|entry| entry.block));
    for entry in blocks {
        packet.extend_from_slice(&entry.data);
    }
    set_length(&mut packet)?;
    Ok(packet)
}

fn block_list(
    command: u8,
    idm: Idm,
    service: u16,
    blocks: impl ExactSizeIterator<Item = u16>,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14 + blocks.len() * 3);
    packet.extend_from_slice(&[0, command]);
    packet.extend_from_slice(idm.as_bytes());
    packet.push(1);
    packet.extend_from_slice(&service.to_le_bytes());
    packet.push(blocks.len() as u8);
    for block in blocks {
        let [low, high] = block.to_le_bytes();
        if high == 0 {
            packet.extend_from_slice(&[0x80, low]);
        } else {
            packet.extend_from_slice(&[0, low, high]);
        }
    }
    packet
}

fn set_length(packet: &mut [u8]) -> Result<(), CardError> {
    packet[0] = u8::try_from(packet.len()).map_err(|_| CardError::Length {
        expected: 255,
        actual: packet.len(),
    })?;
    Ok(())
}

/// A service or area registered at the requested search index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceEntry {
    /// A service code.
    Service(u16),
    /// An area and the inclusive upper end of its code range.
    Area {
        /// Area code.
        code: u16,
        /// Last code in the area.
        end: u16,
    },
}

pub(crate) fn addressed_command(idm: Idm, command: u8, data: &[u8]) -> Result<Vec<u8>, CardError> {
    if data.len() > 245 {
        return Err(CardError::Length {
            expected: 255,
            actual: data.len().saturating_add(10),
        });
    }
    let mut packet = Vec::with_capacity(10 + data.len());
    packet.extend_from_slice(&[0, command]);
    packet.extend_from_slice(idm.as_bytes());
    packet.extend_from_slice(data);
    set_length(&mut packet)?;
    Ok(packet)
}

pub(crate) fn addressed_response(input: &[u8], idm: Idm, code: u8) -> Result<&[u8], CardError> {
    validate_packet(input, code, 10)?;
    let mut actual = [0; 8];
    actual.copy_from_slice(&input[2..10]);
    let actual = Idm::new(actual);
    if actual != idm {
        return Err(CardError::IdentityMismatch {
            expected: idm,
            actual,
        });
    }
    Ok(&input[10..])
}

pub(crate) fn write_response(input: &[u8], idm: Idm) -> Result<(), CardError> {
    let status = addressed_response(input, idm, 0x09)?;
    match status {
        [0, 0] => Ok(()),
        [flag1, flag2] => Err(CardError::Status {
            flag1: *flag1,
            flag2: *flag2,
        }),
        _ => Err(CardError::Length {
            expected: 12,
            actual: input.len(),
        }),
    }
}

pub(crate) fn system_codes(input: &[u8], idm: Idm) -> Result<Vec<u16>, CardError> {
    let body = addressed_response(input, idm, 0x0d)?;
    let count = body.first().copied().unwrap_or(0);
    let expected = 11 + usize::from(count) * 2;
    if input.len() != expected {
        return Err(CardError::Length {
            expected,
            actual: input.len(),
        });
    }
    Ok(body[1..]
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_be_bytes)
        .collect())
}

pub(crate) fn service_entry(input: &[u8], idm: Idm) -> Result<Option<ServiceEntry>, CardError> {
    let body = addressed_response(input, idm, 0x0b)?;
    Ok(match body {
        [0xff, 0xff] => None,
        [a, b] => Some(ServiceEntry::Service(u16::from_le_bytes([*a, *b]))),
        [a, b, c, d] => Some(ServiceEntry::Area {
            code: u16::from_le_bytes([*a, *b]),
            end: u16::from_le_bytes([*c, *d]),
        }),
        _ => {
            return Err(CardError::Length {
                expected: 12,
                actual: input.len(),
            });
        }
    })
}

/// Successful read response whose identities, status and block count are checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadResponse {
    blocks: Vec<[u8; 16]>,
}

impl ReadResponse {
    /// Decode the card response for a particular identity and requested count.
    ///
    /// # Errors
    ///
    /// Returns card status with both flags intact. Rejects another identity,
    /// malformed byte lengths and a block count different from the request.
    pub fn parse(input: &[u8], idm: Idm, expected_blocks: usize) -> Result<Self, CardError> {
        if !(1..=MAX_READ_BLOCKS).contains(&expected_blocks) {
            return Err(CardError::BlockCount(expected_blocks));
        }
        let body = addressed_response(input, idm, 0x07)?;
        match body {
            [0, 0, ..] => {}
            [flag1, flag2, ..] => {
                return Err(CardError::Status {
                    flag1: *flag1,
                    flag2: *flag2,
                });
            }
            _ => {
                return Err(CardError::Length {
                    expected: 12,
                    actual: input.len(),
                });
            }
        }
        let actual_blocks = input.get(12).copied().ok_or(CardError::Length {
            expected: 13,
            actual: input.len(),
        })?;
        let actual_blocks = usize::from(actual_blocks);
        if actual_blocks != expected_blocks {
            return Err(CardError::ResponseBlockCount {
                expected: expected_blocks,
                actual: actual_blocks,
            });
        }
        let length = 13 + actual_blocks * 16;
        if input.len() != length {
            return Err(CardError::Length {
                expected: length,
                actual: input.len(),
            });
        }
        let blocks = input[13..]
            .as_chunks::<16>()
            .0
            .iter()
            .map(|bytes| {
                let mut block = [0; 16];
                block.copy_from_slice(bytes);
                block
            })
            .collect();
        Ok(Self { blocks })
    }

    /// Read blocks in the same order as the request's block list.
    pub fn blocks(&self) -> &[[u8; 16]] {
        &self.blocks
    }
}

pub(crate) fn validate_length(input: &[u8], minimum: usize) -> Result<(), CardError> {
    if input.len() < minimum {
        return Err(CardError::Length {
            expected: minimum,
            actual: input.len(),
        });
    }
    let declared = usize::from(input[0]);
    if declared != input.len() {
        return Err(CardError::Length {
            expected: declared,
            actual: input.len(),
        });
    }
    Ok(())
}

fn validate_packet(input: &[u8], command: u8, minimum: usize) -> Result<(), CardError> {
    validate_length(input, minimum)?;
    if input[1] != command {
        return Err(CardError::ResponseCode {
            expected: command,
            actual: input[1],
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn polling_known_answer() -> Result<(), CardError> {
        assert_eq!(
            PollRequest::new(0xffff, 0, 0)?.encode(),
            [6, 0, 0xff, 0xff, 0, 0]
        );
        assert_eq!(
            PollRequest::new(0x1234, 1, 15)?.encode(),
            [6, 0, 0x12, 0x34, 1, 15]
        );
        let response = [
            20, 1, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x12,
            0x34,
        ];
        let card = PollResponse::parse(&response)?;
        assert_eq!(card.idm, Idm::new([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(card.request_data, Some([0x12, 0x34]));
        assert!(matches!(
            PollRequest::new(0xffff, 0, 2),
            Err(CardError::TimeSlots(2))
        ));
        Ok(())
    }

    #[test]
    fn service_and_large_block_byte_order() -> Result<(), CardError> {
        let idm = Idm::new([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            read_without_encryption(idm, 0x000b, &[0, 255, 256])?,
            [
                21, 6, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0x0b, 0, 3, 0x80, 0, 0x80, 0xff, 0, 0, 1
            ]
        );
        assert!(matches!(
            read_without_encryption(idm, 0x000b, &[]),
            Err(CardError::BlockCount(0))
        ));
        assert!(matches!(
            read_without_encryption(idm, 0x000b, &[0; 13]),
            Err(CardError::BlockCount(13))
        ));
        Ok(())
    }

    #[test]
    fn read_response_validates_identity_status_count_and_bytes() -> Result<(), CardError> {
        let idm = Idm::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let mut response = vec![29, 7, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 1];
        response.extend_from_slice(&[0xab; 16]);
        assert_eq!(
            ReadResponse::parse(&response, idm, 1)?.blocks(),
            &[[0xab; 16]]
        );
        assert!(matches!(
            ReadResponse::parse(&response, idm, 2),
            Err(CardError::ResponseBlockCount {
                expected: 2,
                actual: 1
            })
        ));
        response[2] = 0;
        assert!(matches!(
            ReadResponse::parse(&response, idm, 1),
            Err(CardError::IdentityMismatch { .. })
        ));
        let failure = [12, 7, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0xa2];
        assert_eq!(
            ReadResponse::parse(&failure, idm, 1),
            Err(CardError::Status {
                flag1: 1,
                flag2: 0xa2
            })
        );
        response[2] = 1;
        response.pop();
        response[0] = 28;
        assert!(matches!(
            ReadResponse::parse(&response, idm, 1),
            Err(CardError::Length {
                expected: 29,
                actual: 28
            })
        ));
        Ok(())
    }
}
