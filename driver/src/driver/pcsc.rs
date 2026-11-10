use core::mem::size_of;

use rcs956::{isodep::MAX_APDU_BYTES, nfca, nfcb};
use windows_sys::Win32::Security::Credentials::{
    SCARD_ABSENT, SCARD_CLASS_COMMUNICATIONS, SCARD_CLASS_ICC_STATE, SCARD_CLASS_IFD_PROTOCOL,
    SCARD_CLASS_MECHANICAL, SCARD_CLASS_POWER_MGMT, SCARD_CLASS_PROTOCOL, SCARD_CLASS_SYSTEM,
    SCARD_CLASS_VENDOR_DEFINED, SCARD_CLASS_VENDOR_INFO, SCARD_COLD_RESET, SCARD_IO_REQUEST,
    SCARD_NEGOTIABLE, SCARD_POWER_DOWN, SCARD_PROTOCOL_DEFAULT, SCARD_PROTOCOL_OPTIMAL,
    SCARD_PROTOCOL_RAW, SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1, SCARD_READER_CONTACTLESS,
    SCARD_SPECIFIC, SCARD_SWALLOWED, SCARD_WARM_RESET,
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
/// Largest accepted IOCTL input: a transmit header and the largest APDU that
/// any selection can admit. Each selection applies its own smaller limit.
pub(crate) const MAX_INPUT: usize = PCI_BYTES + MAX_APDU_BYTES;
/// PC/SC carries at most 15 historical bytes in the T0 nibble of the ATR.
const MAX_HISTORICAL_BYTES: usize = 15;

const fn attribute(class: u32, tag: u32) -> u32 {
    (class << 16) | tag
}

const VENDOR_NAME: u32 = attribute(SCARD_CLASS_VENDOR_INFO, 0x100);
const IFD_TYPE: u32 = attribute(SCARD_CLASS_VENDOR_INFO, 0x101);
const CHANNEL_ID: u32 = attribute(SCARD_CLASS_COMMUNICATIONS, 0x110);
const PROTOCOL_TYPES: u32 = attribute(SCARD_CLASS_PROTOCOL, 0x120);
const POWER_MGMT_SUPPORT: u32 = attribute(SCARD_CLASS_POWER_MGMT, 0x131);
const CHARACTERISTICS: u32 = attribute(SCARD_CLASS_MECHANICAL, 0x150);
const CURRENT_PROTOCOL: u32 = attribute(SCARD_CLASS_IFD_PROTOCOL, 0x201);
const ICC_PRESENCE: u32 = attribute(SCARD_CLASS_ICC_STATE, 0x300);
const ICC_INTERFACE_STATUS: u32 = attribute(SCARD_CLASS_ICC_STATE, 0x301);
const ATR_STRING: u32 = attribute(SCARD_CLASS_ICC_STATE, 0x303);
const ICC_TYPE_PER_ATR: u32 = attribute(SCARD_CLASS_ICC_STATE, 0x304);
const MAXINPUT: u32 = attribute(SCARD_CLASS_VENDOR_DEFINED, 0xa007);
const DEVICE_UNIT: u32 = attribute(SCARD_CLASS_SYSTEM, 1);
const DEVICE_IN_USE: u32 = attribute(SCARD_CLASS_SYSTEM, 2);
const SUPPRESS_T1_IFS: u32 = attribute(SCARD_CLASS_SYSTEM, 7);

/// The contactless interface that activated an [`Icc`], as reported by
/// `SCARD_ATTR_ICC_TYPE_PER_ATR`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Interface {
    Iso14443A,
    Iso14443B,
}

/// What PC/SC observes of one ISO-DEP selection.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Icc {
    atr: Vec<u8>,
    interface: Interface,
    maximum_apdu_bytes: usize,
}

impl Icc {
    /// PC/SC Part 3 contactless ATR with the ATS historical bytes. Bytes
    /// beyond the ATR's 15-byte capacity are omitted.
    pub(crate) fn type_a(ats: &nfca::Ats, maximum_apdu_bytes: usize) -> Self {
        let history = ats.historical_bytes();
        Self {
            atr: atr(&history[..history.len().min(MAX_HISTORICAL_BYTES)]),
            interface: Interface::Iso14443A,
            maximum_apdu_bytes,
        }
    }

    /// PC/SC Part 3 contactless ATR for ISO/IEC 14443-B: ATQB application data
    /// and protocol info, then the ATTRIB MBLI in the upper nibble.
    pub(crate) fn type_b(activation: &nfcb::Observation, maximum_apdu_bytes: usize) -> Self {
        let mut history = [0; 8];
        history[..4].copy_from_slice(&activation.application_data());
        history[4..7].copy_from_slice(&activation.protocol_info());
        history[7] = activation.mbli() << 4;
        Self {
            atr: atr(&history),
            interface: Interface::Iso14443B,
            maximum_apdu_bytes,
        }
    }

    pub(crate) fn atr(&self) -> &[u8] {
        &self.atr
    }
}

fn atr(history: &[u8]) -> Vec<u8> {
    // Direct convention, TD1 announcing T=1, TD2 T=1, then TCK.
    let mut bytes = vec![0x3b, 0x80 | history.len() as u8, 0x80, 1];
    bytes.extend_from_slice(history);
    bytes.push(bytes[1..].iter().fold(0, |tck, &byte| tck ^ byte));
    bytes
}

/// Card power as negotiated with the resource manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Power {
    /// Selected but not reset by the resource manager.
    Unpowered,
    /// The ATR was returned; no protocol has been selected.
    Negotiable,
    /// T=1 was selected; APDUs are admitted.
    Specific,
}

/// The reader slot as reported to the resource manager.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Slot<'a> {
    Empty,
    Occupied { icc: &'a Icc, power: Power },
}

impl Slot<'_> {
    fn state(self) -> u32 {
        match self {
            Self::Empty => SCARD_ABSENT,
            Self::Occupied { power, .. } => match power {
                Power::Unpowered => SCARD_SWALLOWED,
                Power::Negotiable => SCARD_NEGOTIABLE,
                Power::Specific => SCARD_SPECIFIC,
            },
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
            SCARD_POWER_DOWN => Command::PowerDown,
            SCARD_COLD_RESET | SCARD_WARM_RESET => Command::Reset,
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
            // OPTIMAL (no protocol bit) and DEFAULT leave the choice to the
            // reader; otherwise the caller must permit T=1.
            let requested = mask & !SCARD_PROTOCOL_DEFAULT;
            if requested != SCARD_PROTOCOL_OPTIMAL && requested & SCARD_PROTOCOL_T1 == 0 {
                return Err(Status(status::NOT_SUPPORTED));
            }
            Command::SelectT1
        }
        TRANSMIT => {
            let header = data
                .get(..PCI_BYTES)
                .ok_or(Status(status::INVALID_PARAMETER))?;
            if dword(&header[..4])? != SCARD_PROTOCOL_T1 {
                return Err(Status(status::INVALID_DEVICE_STATE));
            }
            // cbPciLength includes any protocol information after the header.
            let pci = dword(&header[4..])? as usize;
            if pci < PCI_BYTES {
                return Err(Status(status::INVALID_PARAMETER));
            }
            let apdu = data.get(pci..).ok_or(Status(status::INVALID_PARAMETER))?;
            if apdu.len() < 4 {
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

pub(crate) fn get_state(slot: Slot<'_>) -> Vec<u8> {
    slot.state().to_le_bytes().to_vec()
}

pub(crate) fn transmit_reply(apdu: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PCI_BYTES + apdu.len());
    bytes.extend_from_slice(&t1());
    bytes.extend_from_slice(&(PCI_BYTES as u32).to_le_bytes());
    bytes.extend_from_slice(apdu);
    bytes
}

pub(crate) fn read_attribute(tag: u32, slot: Slot<'_>, unit: u32) -> Result<Vec<u8>, Status> {
    let dword = |value: u32| value.to_le_bytes().to_vec();
    let icc = match slot {
        Slot::Empty => None,
        Slot::Occupied { icc, .. } => Some(icc),
    };
    let present = || icc.ok_or(Status(status::NO_MEDIA));
    Ok(match tag {
        VENDOR_NAME => b"rcs956-rs\0".to_vec(),
        IFD_TYPE => b"RC-S956\0".to_vec(),
        // DDDD = 0x0020 (USB), CCCC = device number.
        CHANNEL_ID => dword(0x0020_0000 | (unit & 0xffff)),
        DEVICE_UNIT => dword(unit),
        CHARACTERISTICS => dword(SCARD_READER_CONTACTLESS),
        POWER_MGMT_SUPPORT | SUPPRESS_T1_IFS => dword(1),
        PROTOCOL_TYPES => t1().to_vec(),
        CURRENT_PROTOCOL => match slot {
            Slot::Occupied {
                power: Power::Specific,
                ..
            } => t1().to_vec(),
            _ => dword(0),
        },
        ICC_PRESENCE => vec![u8::from(icc.is_some())],
        ICC_INTERFACE_STATUS => vec![u8::from(matches!(
            slot,
            Slot::Occupied {
                power: Power::Negotiable | Power::Specific,
                ..
            }
        ))],
        ATR_STRING => present()?.atr.clone(),
        ICC_TYPE_PER_ATR => vec![match present()?.interface {
            Interface::Iso14443A => 5,
            Interface::Iso14443B => 6,
        }],
        MAXINPUT => dword(icc.map_or(MAX_APDU_BYTES, |icc| icc.maximum_apdu_bytes) as u32),
        _ => return Err(Status(status::NOT_SUPPORTED)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_a(history: usize) -> Result<Icc, Box<dyn std::error::Error>> {
        let mut record = vec![0, 4, 0x20, 4, 1, 2, 3, 4, 2 + history as u8, 0];
        record.extend((0..history).map(|byte| byte as u8));
        let observation = nfca::Observation::parse(&record)?;
        let ats = observation.ats().ok_or("expected ATS")?;
        Ok(Icc::type_a(ats, 262))
    }

    #[test]
    fn transmit_apdu_starts_after_the_declared_pci() {
        let data = [2, 0, 0, 0, 8, 0, 0, 0, 0, 0xa4, 4, 0];
        assert_eq!(parse(0x31_0014, &data), Ok(Command::Transmit(&data[8..])));
        assert_eq!(
            transmit_reply(&[0x90, 0]),
            [2, 0, 0, 0, 8, 0, 0, 0, 0x90, 0]
        );
        let extended = [2, 0, 0, 0, 10, 0, 0, 0, 0xee, 0xee, 0, 0xa4, 4, 0];
        assert_eq!(
            parse(TRANSMIT, &extended),
            Ok(Command::Transmit(&extended[10..]))
        );
        for pci in [7, 13] {
            let mut malformed = extended;
            malformed[4] = pci;
            assert_eq!(
                parse(TRANSMIT, &malformed),
                Err(Status(status::INVALID_PARAMETER))
            );
        }
        assert_eq!(
            parse(TRANSMIT, &data[..8]),
            Err(Status(status::INVALID_PARAMETER))
        );
        let mut t0 = data;
        t0[0] = 1;
        assert_eq!(
            parse(TRANSMIT, &t0),
            Err(Status(status::INVALID_DEVICE_STATE))
        );
    }

    #[test]
    fn contactless_atr_has_t1_history_and_checksum() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(atr(&[]), [0x3b, 0x80, 0x80, 1, 1]);
        assert_eq!(atr(&[0x80, 0x73]), [0x3b, 0x82, 0x80, 1, 0x80, 0x73, 0xf0]);
        let long = type_a(20)?;
        assert_eq!(long.atr()[1], 0x8f);
        assert_eq!(long.atr()[4..19], (0..15).collect::<Vec<u8>>()[..]);
        assert_eq!(long.atr().len(), 4 + 15 + 1);
        assert_eq!(long.atr()[1..].iter().fold(0, |tck, &byte| tck ^ byte), 0);
        Ok(())
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
        for mask in [0, 2, 3, 0x8000_0000, 0x8000_0002] {
            assert_eq!(
                parse(0x31_0030, &u32::to_le_bytes(mask)),
                Ok(Command::SelectT1)
            );
        }
        for mask in [1, 0x1_0000, 0x8000_0001] {
            assert_eq!(
                parse(0x31_0030, &u32::to_le_bytes(mask)),
                Err(Status(status::NOT_SUPPORTED))
            );
        }
    }

    #[test]
    fn attributes_follow_the_slot() -> Result<(), Box<dyn std::error::Error>> {
        let icc = type_a(2)?;
        let empty = Slot::Empty;
        let unpowered = Slot::Occupied {
            icc: &icc,
            power: Power::Unpowered,
        };
        let specific = Slot::Occupied {
            icc: &icc,
            power: Power::Specific,
        };
        assert_eq!(get_state(empty), [1, 0, 0, 0]);
        assert_eq!(get_state(unpowered), [3, 0, 0, 0]);
        assert_eq!(get_state(specific), [6, 0, 0, 0]);
        assert_eq!(
            read_attribute(CHARACTERISTICS, empty, 0),
            Ok(vec![8, 0, 0, 0])
        );
        assert_eq!(read_attribute(ICC_PRESENCE, empty, 0), Ok(vec![0]));
        assert_eq!(
            read_attribute(ATR_STRING, empty, 0),
            Err(Status(status::NO_MEDIA))
        );
        assert_eq!(
            read_attribute(MAXINPUT, empty, 0),
            Ok(u32::to_le_bytes(65_535).to_vec())
        );
        assert_eq!(read_attribute(ICC_PRESENCE, unpowered, 0), Ok(vec![1]));
        assert_eq!(
            read_attribute(ICC_INTERFACE_STATUS, unpowered, 0),
            Ok(vec![0])
        );
        assert_eq!(
            read_attribute(CURRENT_PROTOCOL, unpowered, 0),
            Ok(vec![0; 4])
        );
        assert_eq!(read_attribute(ATR_STRING, specific, 0), Ok(icc.atr.clone()));
        assert_eq!(read_attribute(ICC_TYPE_PER_ATR, specific, 0), Ok(vec![5]));
        assert_eq!(
            read_attribute(CURRENT_PROTOCOL, specific, 0),
            Ok(vec![2, 0, 0, 0])
        );
        assert_eq!(
            read_attribute(MAXINPUT, specific, 0),
            Ok(u32::to_le_bytes(262).to_vec())
        );
        assert_eq!(read_attribute(DEVICE_UNIT, empty, 3), Ok(vec![3, 0, 0, 0]));
        Ok(())
    }
}
