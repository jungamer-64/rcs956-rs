use core::mem::size_of;

use rcs956::{nfca, nfcb, reader::MAX_TYPE_A_COMMAND_BYTES};
use windows_sys::Win32::Security::Credentials::{
    SCARD_IO_REQUEST, SCARD_PROTOCOL_DEFAULT, SCARD_PROTOCOL_RAW, SCARD_PROTOCOL_T0,
    SCARD_PROTOCOL_T1,
};

use super::status::{self, Status};

const DEVICE_TYPE: u32 = 0x31;

const fn ioctl(function: u32) -> u32 {
    // winsmcrd.h: FILE_DEVICE_SMARTCARD, METHOD_BUFFERED, FILE_ANY_ACCESS.
    (DEVICE_TYPE << 16) | (function << 2)
}

const POWER: u32 = ioctl(1);
const GET_ATTRIBUTE: u32 = ioctl(2);
const SET_ATTRIBUTE: u32 = ioctl(3);
const TRANSMIT: u32 = ioctl(5);
const SWALLOW: u32 = ioctl(7);
const IS_PRESENT: u32 = ioctl(10);
const IS_ABSENT: u32 = ioctl(11);
const SET_PROTOCOL: u32 = ioctl(12);
const GET_STATE: u32 = ioctl(14);
const GET_FEATURES: u32 = ioctl(3400);
pub(crate) const PCI_BYTES: usize = size_of::<SCARD_IO_REQUEST>();
pub(crate) const MAX_INPUT: usize = PCI_BYTES + MAX_TYPE_A_COMMAND_BYTES;

const fn attribute(class: u32, tag: u32) -> u32 {
    (class << 16) | tag
}

const VENDOR_NAME: u32 = attribute(1, 0x100);
const IFD_TYPE: u32 = attribute(1, 0x101);
const CHANNEL_ID: u32 = attribute(2, 0x110);
const PROTOCOL_TYPES: u32 = attribute(3, 0x120);
const POWER_MGMT_SUPPORT: u32 = attribute(4, 0x131);
const CHARACTERISTICS: u32 = attribute(6, 0x150);
const CURRENT_PROTOCOL: u32 = attribute(8, 0x201);
const ICC_PRESENCE: u32 = attribute(9, 0x300);
const ICC_INTERFACE_STATUS: u32 = attribute(9, 0x301);
const ATR_STRING: u32 = attribute(9, 0x303);
const MAXINPUT: u32 = attribute(7, 0xa007);
const DEVICE_UNIT: u32 = attribute(0x7fff, 1);
const DEVICE_IN_USE: u32 = attribute(0x7fff, 2);
const SUPPRESS_T1_IFS: u32 = attribute(0x7fff, 7);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum State {
    Absent,
    Detected,
    Negotiable,
    Specific,
}

impl State {
    pub(crate) fn value(self) -> u32 {
        match self {
            Self::Absent => 1,
            Self::Detected => 3,
            Self::Negotiable => 5,
            Self::Specific => 6,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Command<'a> {
    GetState,
    Presence(bool),
    Attribute(u32),
    DeviceInUse,
    Swallow,
    Reset,
    PowerDown,
    SelectT1,
    Transmit(&'a [u8]),
    Features,
}

pub(crate) fn parse(code: u32, data: &[u8]) -> Result<Command<'_>, Status> {
    Ok(match code {
        GET_STATE if data.is_empty() => Command::GetState,
        IS_PRESENT if data.is_empty() => Command::Presence(true),
        IS_ABSENT if data.is_empty() => Command::Presence(false),
        GET_ATTRIBUTE => Command::Attribute(dword(data)?),
        SET_ATTRIBUTE => {
            let tag = data.get(..4).ok_or(Status(status::INVALID_PARAMETER))?;
            if dword(tag)? != DEVICE_IN_USE {
                return Err(Status(status::NOT_SUPPORTED));
            }
            Command::DeviceInUse
        }
        SWALLOW if data.is_empty() => Command::Swallow,
        POWER => match dword(data)? {
            0 => Command::PowerDown,
            1 | 2 => Command::Reset,
            _ => return Err(Status(status::INVALID_PARAMETER)),
        },
        SET_PROTOCOL => {
            let mask = dword(data)?;
            if mask
                & !(SCARD_PROTOCOL_T0
                    | SCARD_PROTOCOL_T1
                    | SCARD_PROTOCOL_RAW
                    | SCARD_PROTOCOL_DEFAULT)
                != 0
            {
                return Err(Status(status::INVALID_DEVICE_REQUEST));
            }
            if mask != 0 && mask & SCARD_PROTOCOL_T1 == 0 && mask != SCARD_PROTOCOL_DEFAULT {
                return Err(Status(status::NOT_SUPPORTED));
            }
            Command::SelectT1
        }
        TRANSMIT => {
            let pci = data
                .get(..PCI_BYTES)
                .ok_or(Status(status::INVALID_PARAMETER))?;
            if dword(&pci[..4])? != SCARD_PROTOCOL_T1 {
                return Err(Status(status::INVALID_DEVICE_STATE));
            }
            if dword(&pci[4..])? as usize != PCI_BYTES {
                return Err(Status(status::INVALID_PARAMETER));
            }
            let apdu = &data[PCI_BYTES..];
            if !(4..=MAX_TYPE_A_COMMAND_BYTES).contains(&apdu.len()) {
                return Err(Status(status::INVALID_PARAMETER));
            }
            Command::Transmit(apdu)
        }
        GET_FEATURES if data.is_empty() => Command::Features,
        GET_STATE | IS_PRESENT | IS_ABSENT | SWALLOW | GET_FEATURES => {
            return Err(Status(status::INVALID_PARAMETER));
        }
        _ => return Err(Status(status::NOT_SUPPORTED)),
    })
}

fn dword(bytes: &[u8]) -> Result<u32, Status> {
    bytes
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| Status(status::INVALID_PARAMETER))
}

pub(crate) fn t1() -> [u8; 4] {
    SCARD_PROTOCOL_T1.to_le_bytes()
}

pub(crate) fn transmit_reply(apdu: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PCI_BYTES + apdu.len());
    bytes.extend_from_slice(&t1());
    bytes.extend_from_slice(&(PCI_BYTES as u32).to_le_bytes());
    bytes.extend_from_slice(apdu);
    bytes
}

pub(crate) fn read_attribute(
    tag: u32,
    state: State,
    atr: Option<&[u8]>,
    unit: u32,
) -> Result<Vec<u8>, Status> {
    Ok(match tag {
        VENDOR_NAME => b"rcs956-rs\0".to_vec(),
        IFD_TYPE => b"RC-S956\0".to_vec(),
        CHANNEL_ID => (0x0020_0000 | (unit & 0xffff)).to_le_bytes().to_vec(),
        DEVICE_UNIT => unit.to_le_bytes().to_vec(),
        CHARACTERISTICS => 0u32.to_le_bytes().to_vec(),
        POWER_MGMT_SUPPORT | SUPPRESS_T1_IFS => 1u32.to_le_bytes().to_vec(),
        PROTOCOL_TYPES => t1().to_vec(),
        CURRENT_PROTOCOL if state == State::Specific => t1().to_vec(),
        CURRENT_PROTOCOL => 0u32.to_le_bytes().to_vec(),
        ICC_PRESENCE => vec![u8::from(state != State::Absent)],
        ICC_INTERFACE_STATUS => vec![u8::from(matches!(
            state,
            State::Negotiable | State::Specific
        ))],
        MAXINPUT => (MAX_TYPE_A_COMMAND_BYTES as u32).to_le_bytes().to_vec(),
        ATR_STRING => atr.ok_or(Status(status::NO_MEDIA))?.to_vec(),
        _ => return Err(Status(status::NOT_SUPPORTED)),
    })
}

pub(crate) fn atr_a(ats: &nfca::Ats) -> Option<Vec<u8>> {
    let history = ats.historical_bytes();
    (history.len() <= 15).then(|| atr(history))
}

pub(crate) fn atr_b(activation: &nfcb::Observation) -> Vec<u8> {
    let mut history = [0; 8];
    history[..4].copy_from_slice(&activation.application_data());
    history[4..7].copy_from_slice(&activation.protocol_info());
    history[7] = activation.mbli() << 4;
    atr(&history)
}

fn atr(history: &[u8]) -> Vec<u8> {
    // PC/SC Part 3 Table 3-5, direct convention, T=1.
    let mut bytes = vec![0x3b, 0x80 | history.len() as u8, 0x80, 1];
    bytes.extend_from_slice(history);
    bytes.push(bytes[1..].iter().fold(0, |tck, &byte| tck ^ byte));
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcsc_transmit_has_an_eight_byte_pci_and_a_distinct_apdu() {
        let data = [2, 0, 0, 0, 8, 0, 0, 0, 0, 0xa4, 4, 0];
        assert_eq!(parse(0x31_0014, &data), Ok(Command::Transmit(&data[8..])));
        assert_eq!(
            transmit_reply(&[0x90, 0]),
            [2, 0, 0, 0, 8, 0, 0, 0, 0x90, 0]
        );
        let mut malformed = data;
        malformed[4] = 7;
        assert_eq!(
            parse(TRANSMIT, &malformed),
            Err(Status(status::INVALID_PARAMETER))
        );
        assert_eq!(
            parse(TRANSMIT, &data[..8]),
            Err(Status(status::INVALID_PARAMETER))
        );
        malformed[0] = 1;
        assert_eq!(
            parse(TRANSMIT, &malformed),
            Err(Status(status::INVALID_DEVICE_STATE))
        );
    }

    #[test]
    fn contactless_atr_has_t1_history_and_checksum() {
        assert_eq!(atr(&[]), [0x3b, 0x80, 0x80, 1, 1]);
        assert_eq!(atr(&[0x80, 0x73]), [0x3b, 0x82, 0x80, 1, 0x80, 0x73, 0xf0]);
    }

    #[test]
    fn power_operations_have_the_winsmcrd_values() {
        assert_eq!(parse(0x31_0004, &[0, 0, 0, 0]), Ok(Command::PowerDown));
        assert_eq!(parse(0x31_0004, &[1, 0, 0, 0]), Ok(Command::Reset));
        assert_eq!(parse(0x31_0004, &[2, 0, 0, 0]), Ok(Command::Reset));
        assert_eq!(
            parse(0x31_0004, &[3, 0, 0, 0]),
            Err(Status(status::INVALID_PARAMETER))
        );
    }

    #[test]
    fn resource_manager_sees_a_single_t1_protocol() {
        assert_eq!(parse(0x31_0030, &[3, 0, 0, 0]), Ok(Command::SelectT1));
        assert_eq!(
            parse(0x31_0030, &[1, 0, 0, 0]),
            Err(Status(status::NOT_SUPPORTED))
        );
        assert_eq!(
            read_attribute(ICC_PRESENCE, State::Absent, None, 0),
            Ok(vec![0])
        );
        assert_eq!(
            read_attribute(CURRENT_PROTOCOL, State::Negotiable, None, 0),
            Ok(vec![0; 4])
        );
        assert_eq!(
            read_attribute(CURRENT_PROTOCOL, State::Specific, None, 0),
            Ok(vec![2, 0, 0, 0])
        );
    }
}
