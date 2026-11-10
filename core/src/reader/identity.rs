//! Reader identity recorded in the configuration image.

use alloc::string::String;
use core::{error, fmt};

/// Model word `E[FD] << 8 | E[FE]`, distinct from the USB product ID.
///
/// `E[FD]` is the model class accepted by [`super::ConfigImage::parse`] (1 or 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Model(u16);

impl Model {
    pub(super) fn new(word: u16) -> Self {
        Self(word)
    }

    /// Raw model word.
    pub fn word(self) -> u16 {
        self.0
    }

    /// Product named by Sony's reader diagnostics for this model word.
    /// Other accepted model words have no product name.
    pub fn product(self) -> Option<Product> {
        Some(match self.0 {
            0x0211 => Product::RcS330P,
            0x0212 => Product::RcS330S,
            0x0131 => Product::RcS620,
            0x0132 => Product::RcS621,
            0x0133 => Product::RcS625,
            0x0134 => Product::RcS628,
            0x0241 => Product::RcS620Uc,
            _ => return None,
        })
    }
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04X}", self.0)
    }
}

/// Reader product identified from a [`Model`] word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Product {
    /// RC-S330/P.
    RcS330P,
    /// RC-S330/S.
    RcS330S,
    /// RC-S620.
    RcS620,
    /// RC-S621.
    RcS621,
    /// RC-S625.
    RcS625,
    /// RC-S628.
    RcS628,
    /// RC-S620/UC.
    RcS620Uc,
}

impl Product {
    /// Product designation.
    pub fn name(self) -> &'static str {
        match self {
            Self::RcS330P => "RC-S330/P",
            Self::RcS330S => "RC-S330/S",
            Self::RcS620 => "RC-S620",
            Self::RcS621 => "RC-S621",
            Self::RcS625 => "RC-S625",
            Self::RcS628 => "RC-S628",
            Self::RcS620Uc => "RC-S620/UC",
        }
    }
}

impl fmt::Display for Product {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The configuration image announces a device name that cannot be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceNameError {
    /// `E[04]` lies outside `0x72..=0xBA`.
    Offset(u8),
    /// The descriptor type byte is not 3.
    DescriptorType(u8),
    /// `bLength` is not an even value above 3 ending before `E[BF]`.
    Length(u8),
    /// The descriptor body is not well-formed UTF-16LE.
    Utf16,
}

impl fmt::Display for DeviceNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl error::Error for DeviceNameError {}

const NAME_PRESENT: u8 = 0x20;
const NAME_OFFSETS: core::ops::RangeInclusive<u8> = 0x72..=0xba;
// The descriptor must end before E[BF], inside the E[40..C0] checksum range.
const NAME_END: usize = 0xbf;
const STRING_DESCRIPTOR: u8 = 3;

/// Decode the device name that `E[03]` bit 5 announces at offset `E[04]`.
///
/// The name is stored as a USB string descriptor: `bLength`, type 3, then
/// UTF-16LE code units.
pub(super) fn device_name(image: &[u8; 256]) -> Result<Option<String>, DeviceNameError> {
    if image[3] & NAME_PRESENT == 0 {
        return Ok(None);
    }
    let offset = image[4];
    if !NAME_OFFSETS.contains(&offset) {
        return Err(DeviceNameError::Offset(offset));
    }
    let begin = usize::from(offset);
    let length = image[begin];
    let end = begin + usize::from(length);
    if length <= 3 || !length.is_multiple_of(2) || end >= NAME_END {
        return Err(DeviceNameError::Length(length));
    }
    if image[begin + 1] != STRING_DESCRIPTOR {
        return Err(DeviceNameError::DescriptorType(image[begin + 1]));
    }
    let units = image[begin + 2..end]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes(*unit));
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map(Some)
        .map_err(|_| DeviceNameError::Utf16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::{ConfigImage, ConfigurationError};

    fn image_with_name(offset: u8, descriptor: &[u8]) -> [u8; 256] {
        let mut e = [0u8; 256];
        e[0] = 0x55;
        e[1] = 0xaa;
        e[3] = NAME_PRESENT;
        e[4] = offset;
        let begin = usize::from(offset);
        e[begin..begin + descriptor.len()].copy_from_slice(descriptor);
        e[253] = 2;
        e[254] = 0x11;
        for (range, fix) in [(0..16, 2), (64..192, 0x41)] {
            let sum = e[range].iter().fold(0u8, |s, b| s.wrapping_add(*b));
            e[fix] = e[fix].wrapping_sub(sum);
        }
        e
    }

    #[test]
    fn config_image_exposes_announced_name_and_product() -> Result<(), ConfigurationError> {
        let image = image_with_name(0x80, &[8, 3, b'R', 0, b'C', 0, 0x3a, 0x30]);
        let config = ConfigImage::parse(image)?;
        assert_eq!(config.device_name(), Ok(Some(String::from("RC\u{303a}"))));
        assert_eq!(config.model().word(), 0x0211);
        assert_eq!(config.model().product(), Some(Product::RcS330P));
        Ok(())
    }

    #[test]
    fn name_is_absent_without_announcement() {
        let mut image = image_with_name(0x80, &[4, 3, b'A', 0]);
        image[3] = 0;
        assert_eq!(device_name(&image), Ok(None));
    }

    #[test]
    fn descriptor_bounds() {
        let accepted: [(u8, &[u8], &str); 2] =
            [(0x72, &[4, 3, b'A', 0], "A"), (0xba, &[4, 3, b'Z', 0], "Z")];
        for (offset, descriptor, name) in accepted {
            assert_eq!(
                device_name(&image_with_name(offset, descriptor)),
                Ok(Some(String::from(name)))
            );
        }
        let rejected: [(u8, &[u8], DeviceNameError); 7] = [
            (0x71, &[4, 3, b'A', 0], DeviceNameError::Offset(0x71)),
            (0xbb, &[4, 3, b'A', 0], DeviceNameError::Offset(0xbb)),
            (
                0xb8,
                &[8, 3, b'A', 0, b'B', 0, b'C', 0],
                DeviceNameError::Length(8),
            ),
            (0x80, &[2, 3], DeviceNameError::Length(2)),
            (0x80, &[5, 3, b'A', 0, 0], DeviceNameError::Length(5)),
            (0x80, &[4, 1, b'A', 0], DeviceNameError::DescriptorType(1)),
            (0x80, &[4, 3, 0x00, 0xdc], DeviceNameError::Utf16),
        ];
        for (offset, descriptor, error) in rejected {
            assert_eq!(
                device_name(&image_with_name(offset, descriptor)),
                Err(error)
            );
        }
    }

    #[test]
    fn malformed_name_does_not_invalidate_image() -> Result<(), ConfigurationError> {
        let config = ConfigImage::parse(image_with_name(0x80, &[4, 1, b'A', 0]))?;
        assert_eq!(
            config.device_name(),
            Err(DeviceNameError::DescriptorType(1))
        );
        Ok(())
    }

    #[test]
    fn products_follow_model_words() {
        for (word, product) in [
            (0x0211, Some(Product::RcS330P)),
            (0x0212, Some(Product::RcS330S)),
            (0x0131, Some(Product::RcS620)),
            (0x0132, Some(Product::RcS621)),
            (0x0133, Some(Product::RcS625)),
            (0x0134, Some(Product::RcS628)),
            (0x0241, Some(Product::RcS620Uc)),
            (0x0213, None),
            (0x0242, None),
        ] {
            assert_eq!(Model::new(word).product(), product);
        }
        assert_eq!(Product::RcS330S.name(), "RC-S330/S");
    }
}
