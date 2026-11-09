//! NFC-B activation observations from an RC-S956 `4A` response.
//!
//! Parsing begins after the target number and requires the 12-byte ATQB without
//! CRC, followed by the ATTRIB response length and complete ATTRIB response.
#![forbid(unsafe_code)]

use std::{fmt, time::Duration};

/// Invalid NFC-B activation data or unsupported standard-frame parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The record cannot contain ATQB and its ATTRIB response length.
    Truncated {
        /// Minimum record size.
        minimum: usize,
        /// Bytes supplied.
        actual: usize,
    },
    /// ATTRIB's declared response length does not match the record tail.
    AttribLength {
        /// Response bytes declared by the reader.
        declared: usize,
        /// Response bytes actually supplied.
        actual: usize,
    },
    /// ATQB does not start with its required response byte 50h.
    AtqbResponseCode(u8),
    /// A selected card did not return the mandatory MBLI/CID response byte.
    MissingAttrib,
    /// FSCI lies outside the supported standard-frame range `0..=8`.
    FrameSizeIndex(u8),
    /// RC-S956's optional activation extension has an unsupported reader FSDI.
    ReaderFrameSizeIndex(u8),
    /// FWI contains the reserved value 15.
    FrameWaitIndex(u8),
    /// ATTRIB assigns reserved CID 15.
    ReservedCid,
    /// A nonzero CID was assigned although ATQB does not advertise CID support.
    UnsupportedCid(u8),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Complete ATQB and ATTRIB data for one selected NFC-B target.
///
/// The immutable ATQB is the authority for advertised capabilities. An observed
/// proprietary protocol type remains detectable and is not promoted to ISO-DEP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    atqb: [u8; 12],
    attrib: Vec<u8>,
    frame_size: u16,
    reader_frame_size: u16,
}
impl Observation {
    /// Parse ATQB, the reader's length byte, and its exact ATTRIB response tail.
    ///
    /// CRC bytes are absent. A completed ATTRIB needs its MBLI/CID byte; a
    /// nonzero CID additionally requires advertised CID support. FWI15 and
    /// FSCI above8 are outside this standard-frame profile and are rejected.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 13 {
            return Err(Error::Truncated {
                minimum: 13,
                actual: data.len(),
            });
        }
        if data[0] != 0x50 {
            return Err(Error::AtqbResponseCode(data[0]));
        }
        let declared = usize::from(data[12]);
        if data.len() - 13 != declared {
            return Err(Error::AttribLength {
                declared,
                actual: data.len() - 13,
            });
        }
        if declared == 0 {
            return Err(Error::MissingAttrib);
        }
        let fsci = data[10] >> 4;
        let frame_size = crate::isodep::frame_size(fsci).ok_or(Error::FrameSizeIndex(fsci))?;
        // The RC-S956 extended activation tail encodes reader FSDI in the
        // second ATTRIB byte; absent that extension, the driver uses FSDI5.
        let reader_fsdi = data.get(14).copied().unwrap_or(5) & 0x0f;
        let reader_frame_size = crate::isodep::frame_size(reader_fsdi)
            .ok_or(Error::ReaderFrameSizeIndex(reader_fsdi))?;
        let fwi = data[11] >> 4;
        if fwi == 15 {
            return Err(Error::FrameWaitIndex(fwi));
        }
        let cid = data[13] & 0x0f;
        if cid == 15 {
            return Err(Error::ReservedCid);
        }
        if cid != 0 && data[11] & 1 == 0 {
            return Err(Error::UnsupportedCid(cid));
        }
        let mut atqb = [0; 12];
        atqb.copy_from_slice(&data[..12]);
        Ok(Self {
            atqb,
            attrib: data[13..].to_vec(),
            frame_size,
            reader_frame_size,
        })
    }
    /// Original 12-byte ATQB without CRC.
    pub fn atqb(&self) -> &[u8; 12] {
        &self.atqb
    }
    /// Session PUPI in wire order; this value is not an authenticated identity.
    pub fn pupi(&self) -> [u8; 4] {
        [self.atqb[1], self.atqb[2], self.atqb[3], self.atqb[4]]
    }
    /// Four application bytes, whose interpretation depends on application coding.
    pub fn application_data(&self) -> [u8; 4] {
        [self.atqb[5], self.atqb[6], self.atqb[7], self.atqb[8]]
    }
    /// Bit-rate, frame-size/protocol-type, and timing/options bytes.
    pub fn protocol_info(&self) -> [u8; 3] {
        [self.atqb[9], self.atqb[10], self.atqb[11]]
    }
    /// Reader-returned ATTRIB tail, including MBLI/CID and any reader extension.
    pub fn attrib_response(&self) -> &[u8] {
        &self.attrib
    }
    /// ATQB advertises protocol type1, the ISO-DEP block protocol.
    pub fn supports_iso_dep(&self) -> bool {
        self.atqb[10] & 0x0f == 1
    }
    /// Maximum card frame size including protocol overhead and CRC.
    pub fn frame_size(&self) -> u16 {
        self.frame_size
    }
    /// Standard maximum-card-frame-size code from ATQB.
    pub fn fsci(&self) -> u8 {
        self.atqb[10] >> 4
    }
    /// Frame waiting integer from ATQB.
    pub fn fwi(&self) -> u8 {
        self.atqb[11] >> 4
    }
    /// Card frame waiting time rounded upward by the shared ISO-DEP conversion.
    pub fn frame_wait(&self) -> Duration {
        crate::isodep::frame_wait(self.fwi())
    }
    /// Whether ATQB advertises optional card-identifier fields.
    pub fn cid_supported(&self) -> bool {
        self.atqb[11] & 1 != 0
    }
    /// Whether ATQB advertises optional node-address fields.
    pub fn nad_supported(&self) -> bool {
        self.atqb[11] & 2 != 0
    }
    /// CID assigned during ATTRIB. Zero permits communication without CID fields.
    pub fn cid(&self) -> u8 {
        self.attrib[0] & 0x0f
    }
    /// Raw maximum-buffer-length index from the ATTRIB response.
    pub fn mbli(&self) -> u8 {
        self.attrib[0] >> 4
    }
    /// Reader receive frame capacity from its activation extension, including CRC.
    /// Without that extension this RC-S956 profile uses 64 bytes.
    pub fn reader_frame_size(&self) -> u16 {
        self.reader_frame_size
    }
    /// Advertised command buffer limit, or unknown when MBLI is zero.
    /// The RC-S956 driver interprets nonzero MBLI as `FSC * 2^MBLI`.
    pub fn maximum_command_bytes(&self) -> Option<usize> {
        match self.mbli() {
            0 => None,
            mbli => Some(usize::from(self.frame_size) << mbli),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARD: [u8; 14] = [
        0x50, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0, 0x51, 0x41, 1, 1,
    ];

    #[test]
    fn selected_card_preserves_identity_capabilities_and_attrib() -> Result<(), Error> {
        let observation = Observation::parse(&CARD)?;
        assert_eq!(observation.pupi(), [1, 2, 3, 4]);
        assert_eq!(observation.application_data(), [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(observation.protocol_info(), [0, 0x51, 0x41]);
        assert_eq!(observation.frame_size(), 64);
        assert_eq!(observation.fwi(), 4);
        assert!(observation.supports_iso_dep());
        assert!(observation.cid_supported());
        assert_eq!(observation.cid(), 1);
        assert_eq!(observation.attrib_response(), [1]);
        Ok(())
    }

    #[test]
    fn proprietary_card_and_zero_cid_are_observable() -> Result<(), Error> {
        let mut data = CARD;
        data[10] = 0;
        data[11] = 0x40;
        data[13] = 0;
        let observation = Observation::parse(&data)?;
        assert!(!observation.supports_iso_dep());
        assert!(!observation.cid_supported());
        assert_eq!(observation.cid(), 0);
        Ok(())
    }

    #[test]
    fn activation_extension_and_mbli_bound_different_directions() -> Result<(), Error> {
        let mut data = CARD.to_vec();
        data[12] = 2;
        data[13] = 0x21;
        data.push(2);
        let observation = Observation::parse(&data)?;
        assert_eq!(observation.frame_size(), 64);
        assert_eq!(observation.reader_frame_size(), 32);
        assert_eq!(observation.maximum_command_bytes(), Some(256));
        data[14] = 9;
        assert!(matches!(
            Observation::parse(&data),
            Err(Error::ReaderFrameSizeIndex(9))
        ));
        Ok(())
    }

    #[test]
    fn attrib_and_protocol_boundaries_are_checked() {
        assert!(matches!(
            Observation::parse(&CARD[..13]),
            Err(Error::AttribLength { .. })
        ));
        let mut bad = CARD;
        bad[12] = 0;
        assert!(matches!(
            Observation::parse(&bad[..13]),
            Err(Error::MissingAttrib)
        ));
        bad = CARD;
        bad[11] = 0xf1;
        assert!(matches!(
            Observation::parse(&bad),
            Err(Error::FrameWaitIndex(15))
        ));
        bad = CARD;
        bad[10] = 0x91;
        assert!(matches!(
            Observation::parse(&bad),
            Err(Error::FrameSizeIndex(9))
        ));
        bad = CARD;
        bad[13] = 0x1f;
        assert!(matches!(Observation::parse(&bad), Err(Error::ReservedCid)));
        bad = CARD;
        bad[11] = 0x40;
        assert!(matches!(
            Observation::parse(&bad),
            Err(Error::UnsupportedCid(1))
        ));
    }
}
