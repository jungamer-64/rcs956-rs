//! NFC Forum tag access for NDEF messages.
//!
//! Mapping and access checks are separate from RF exchange and record encoding.

mod message;
mod type1;
mod type2;
mod type3;
mod type4;

pub use message::{Message, MessageError, MessageErrorKind, Record, RecordType};
pub use type1::{Type1Error, Type1WriteError};
pub use type2::{Type2Error, Type2WriteError};
pub use type3::Type3Tag;
pub use type4::{Type4Error, Type4WriteError};

use core::fmt;

/// NDEF mapping, card status, or underlying exchange failure.
#[derive(Debug)]
pub enum Error<E> {
    /// RF or reader exchange failed.
    Exchange(E),
    /// The tag or its mapping version is outside this operation's profile.
    UnsupportedMapping,
    /// This operation requires read access without authentication.
    ReadAccess,
    /// This operation requires write access without authentication.
    WriteAccess,
    /// The tag reports a write in progress or interrupted before publication.
    WriteInProgress,
    /// The message cannot fit the tag's addressable NDEF storage.
    Capacity {
        /// Requested message size in bytes.
        requested: usize,
        /// Available message bytes, excluding mapping metadata.
        available: usize,
    },
    /// A mapping field or response length is inconsistent.
    Layout(&'static str),
    /// Reading requires an address outside the supported range.
    Address(usize),
    /// A Type 4 tag returned an unsuccessful status word.
    Status(u16),
    /// A Type 2 tag returned a negative acknowledgement nibble.
    Type2Nak(u8),
    /// A Type 2 command returned an unexpected successful reader status.
    Type2ReaderStatus(u8),
    /// The first NDEF TLV must exist before it can be replaced.
    MissingMessageTlv,
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
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

/// The persistent operation being attempted when an NDEF update failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateStage {
    /// Invalidate the previous message or mark the tag as being updated.
    Begin,
    /// Write data while the message is unpublished.
    Data,
    /// Publish the new message.
    Publish,
}

/// Failure to replace an NDEF message.
#[derive(Debug)]
pub enum WriteError<E> {
    /// No persistent write was attempted.
    Preparation(Error<E>),
    /// An update command failed. Its effect may be unknown. Re-select and
    /// inspect the tag before deciding whether to issue another write.
    Update {
        /// Stage of the command that failed.
        stage: UpdateStage,
        /// Prefix of message bytes acknowledged by prior write commands.
        acknowledged_bytes: usize,
        /// Cause reported by the mapping or transport.
        cause: Error<E>,
    },
}

impl<E> WriteError<E> {
    fn update(stage: UpdateStage, acknowledged_bytes: usize, cause: Error<E>) -> Self {
        Self::Update {
            stage,
            acknowledged_bytes,
            cause,
        }
    }
}

impl<E: fmt::Debug> fmt::Display for WriteError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<E: core::error::Error + 'static> core::error::Error for WriteError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Preparation(error) | Self::Update { cause: error, .. } => Some(error),
        }
    }
}

fn control_range<E>(
    tag: u8,
    [position, size, control]: [u8; 3],
) -> Result<core::ops::Range<usize>, Error<E>> {
    let page_size = 1usize << (control & 0x0f);
    let offset = usize::from(position & 0x0f);
    if offset >= page_size {
        return Err(Error::Layout("control TLV address"));
    }
    let start = usize::from(position >> 4) * page_size + offset;
    let size = if size == 0 { 256 } else { usize::from(size) };
    let bytes = if tag == 1 { size.div_ceil(8) } else { size };
    Ok(start..start + bytes)
}
