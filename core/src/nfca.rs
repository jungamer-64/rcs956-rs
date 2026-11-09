//! NFC-A activation observations from an RC-S956 `4A` response.
//!
//! Parsing begins after the reader's target number. UID bytes remain in wire
//! order, and ATS retains its own inclusive length byte without RF CRC bytes.
use alloc::vec::Vec;
use core::{fmt, time::Duration};

/// Invalid NFC-A selection data or unsupported ISO-DEP timing parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The response cannot contain the required field.
    Truncated {
        /// Field whose bytes are missing.
        field: &'static str,
        /// Minimum bytes needed for that field.
        minimum: usize,
        /// Bytes available in the containing response.
        actual: usize,
    },
    /// UID length is not one of the single, double, or triple cascade lengths.
    UidLength(u8),
    /// ATS has a zero, oversized, or mismatched inclusive length.
    AtsLength {
        /// Inclusive length declared by TL.
        declared: usize,
        /// Actual ATS bytes, including TL.
        actual: usize,
    },
    /// The format byte contains an unsupported format bit.
    AtsFormat(u8),
    /// FSCI lies outside the supported standard-frame range `0..=8`.
    FrameSizeIndex(u8),
    /// FWI contains the reserved value 15.
    FrameWaitIndex(u8),
    /// SFGI contains the reserved value 15.
    GuardTimeIndex(u8),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for Error {}

/// A complete ATS with checked interface-byte boundaries and timing fields.
///
/// The raw bytes are immutable after construction; cached offsets and decoded
/// parameters are established together with those bytes by [`Self::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ats {
    bytes: Vec<u8>,
    frame_size: u16,
    fwi: u8,
    sfgi: u8,
    tc: Option<u8>,
    historical_start: usize,
}
impl Ats {
    /// Validate TL, optional TA/TB/TC bytes, and standard-frame timing indices.
    ///
    /// RC-S956 selection accepts at most 62 ATS bytes. RF CRC bytes are absent.
    /// FWI/SFGI value 15 and FSCI above 8 are rejected rather than reinterpreted.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let declared = bytes.first().copied().map_or(0, usize::from);
        if bytes.is_empty() || bytes.len() > 62 || declared != bytes.len() {
            return Err(Error::AtsLength {
                declared,
                actual: bytes.len(),
            });
        }
        let format = bytes.get(1).copied().unwrap_or(2);
        if format & 0x80 != 0 {
            return Err(Error::AtsFormat(format));
        }
        let fsci = format & 0x0f;
        let frame_size = crate::isodep::frame_size(fsci).ok_or(Error::FrameSizeIndex(fsci))?;
        let mut cursor = bytes.len().min(2);
        let mut interfaces = [None; 3];
        for (index, mask) in [0x10, 0x20, 0x40].into_iter().enumerate() {
            if format & mask != 0 {
                let value = bytes.get(cursor).copied().ok_or(Error::Truncated {
                    field: "ATS interface byte",
                    minimum: cursor + 1,
                    actual: bytes.len(),
                })?;
                interfaces[index] = Some(value);
                cursor += 1;
            }
        }
        let timing = interfaces[1].unwrap_or(0x40);
        let fwi = timing >> 4;
        let sfgi = timing & 0x0f;
        if fwi == 15 {
            return Err(Error::FrameWaitIndex(fwi));
        }
        if sfgi == 15 {
            return Err(Error::GuardTimeIndex(sfgi));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            frame_size,
            fwi,
            sfgi,
            tc: interfaces[2],
            historical_start: cursor,
        })
    }

    /// ATS including TL, without CRC.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Maximum standard frame size the card advertises, including protocol overhead.
    pub fn frame_size(&self) -> u16 {
        self.frame_size
    }
    /// Standard frame-size code; 2 is the default when T0 is absent.
    pub fn fsci(&self) -> u8 {
        self.bytes.get(1).copied().unwrap_or(2) & 0x0f
    }
    /// Frame waiting integer; 4 is the default when TB is absent.
    pub fn fwi(&self) -> u8 {
        self.fwi
    }
    /// Card frame waiting time rounded upward by the shared ISO-DEP time conversion.
    pub fn frame_wait(&self) -> Duration {
        crate::isodep::frame_wait(self.fwi)
    }
    /// Startup frame guard integer; 0 means no additional startup guard time.
    pub fn sfgi(&self) -> u8 {
        self.sfgi
    }
    /// Whether TC advertises optional card-identifier fields.
    pub fn cid_supported(&self) -> bool {
        self.tc.is_some_and(|byte| byte & 2 != 0)
    }
    /// Whether TC advertises optional node-address fields.
    pub fn nad_supported(&self) -> bool {
        self.tc.is_some_and(|byte| byte & 1 != 0)
    }
    /// Historical bytes after all present interface bytes.
    pub fn historical_bytes(&self) -> &[u8] {
        &self.bytes[self.historical_start..]
    }
}

/// A complete NFC-A `4A` target record, excluding target count and target number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    sens_res: [u8; 2],
    sel_res: u8,
    uid: Vec<u8>,
    ats: Option<Ats>,
}
impl Observation {
    /// Parse SENS_RES, SEL_RES, a 4/7/10-byte UID, and an optional complete ATS.
    ///
    /// ISO-DEP support in SEL_RES is an advertised capability. An absent ATS
    /// does not establish ISO-DEP activation and remains explicit as `None`.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 4 {
            return Err(Error::Truncated {
                field: "NFC-A selection header",
                minimum: 4,
                actual: data.len(),
            });
        }
        let uid_len = data[3];
        if !matches!(uid_len, 4 | 7 | 10) {
            return Err(Error::UidLength(uid_len));
        }
        let end = 4 + usize::from(uid_len);
        if data.len() < end {
            return Err(Error::Truncated {
                field: "NFC-A UID",
                minimum: end,
                actual: data.len(),
            });
        }
        let ats = if data.len() == end {
            None
        } else {
            Some(Ats::parse(&data[end..])?)
        };
        Ok(Self {
            sens_res: [data[0], data[1]],
            sel_res: data[2],
            uid: data[4..end].to_vec(),
            ats,
        })
    }
    /// SENS_RES in the reader's MSB-first byte order.
    pub fn sens_res(&self) -> [u8; 2] {
        self.sens_res
    }
    /// Raw select acknowledgment byte.
    pub fn sel_res(&self) -> u8 {
        self.sel_res
    }
    /// Complete UID with cascade tags removed by activation, in wire byte order.
    pub fn uid(&self) -> &[u8] {
        &self.uid
    }
    /// ATS when activation returned one; its length byte is retained.
    pub fn ats(&self) -> Option<&Ats> {
        self.ats.as_ref()
    }
    /// SEL_RES advertises ISO-DEP without an unfinished UID cascade.
    pub fn supports_iso_dep(&self) -> bool {
        self.sel_res & 0x24 == 0x20
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_preserves_uid_and_parses_complete_ats() -> Result<(), Error> {
        let observation = Observation::parse(&[
            0x04, 0x07, 0x28, 4, 0x00, 0xd4, 0x1e, 0x92, 6, 0x75, 0x80, 0x60, 2, 0x42,
        ])?;
        assert_eq!(observation.sens_res(), [4, 7]);
        assert_eq!(observation.uid(), [0, 0xd4, 0x1e, 0x92]);
        assert!(observation.supports_iso_dep());
        let ats = observation.ats().ok_or(Error::AtsLength {
            declared: 0,
            actual: 0,
        })?;
        assert_eq!(ats.frame_size(), 64);
        assert_eq!(ats.fwi(), 6);
        assert_eq!(ats.sfgi(), 0);
        assert!(ats.cid_supported());
        assert!(!ats.nad_supported());
        assert_eq!(ats.historical_bytes(), [0x42]);
        Ok(())
    }

    #[test]
    fn optional_ats_and_omitted_interface_defaults_are_preserved() -> Result<(), Error> {
        let observation = Observation::parse(&[0, 0x44, 0, 7, 1, 2, 3, 4, 5, 6, 7])?;
        assert!(observation.ats().is_none());
        assert!(!observation.supports_iso_dep());
        let ats = Ats::parse(&[1])?;
        assert_eq!(ats.fsci(), 2);
        assert_eq!(ats.frame_size(), 32);
        assert_eq!(ats.fwi(), 4);
        assert!(!ats.cid_supported());
        assert_eq!(Ats::parse(&[3, 0x25, 0x80])?.fwi(), 8);
        Ok(())
    }

    #[test]
    fn selection_and_interface_boundaries_are_checked() {
        assert!(matches!(
            Observation::parse(&[0, 4, 0, 5]),
            Err(Error::UidLength(5))
        ));
        assert!(matches!(
            Observation::parse(&[0, 4, 0, 10, 1]),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(
            Ats::parse(&[2, 0x25]),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(
            Ats::parse(&[3, 0x05]),
            Err(Error::AtsLength { .. })
        ));
        assert!(matches!(
            Ats::parse(&[2, 0x09]),
            Err(Error::FrameSizeIndex(9))
        ));
        assert!(matches!(
            Ats::parse(&[3, 0x25, 0xf0]),
            Err(Error::FrameWaitIndex(15))
        ));
        assert!(matches!(
            Ats::parse(&[3, 0x25, 0x4f]),
            Err(Error::GuardTimeIndex(15))
        ));
    }
}
