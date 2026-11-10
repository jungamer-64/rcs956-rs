use super::{Error, Reader, RfTimeout, State};
use crate::transport::Transport;
use alloc::vec::Vec;
use core::{fmt, time::Duration};

const SETUP_WAIT: Duration = Duration::from_secs(1);
const RESPONSE_WAIT_INDEX: u8 = 8;
const MAX_RESPONSE_BYTES: usize = 60;

/// Passive NFC-DEP RF technology and rate selected by the initiator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepRate {
    /// NFC-A at 106 kbps.
    Kbps106,
    /// NFC-F at 212 kbps.
    Kbps212,
    /// NFC-F at 424 kbps.
    Kbps424,
}

/// Initiator attributes observed in the NFC-DEP activation request.
#[derive(Debug)]
pub struct DepInitiator {
    /// Active RF technology and rate.
    pub rate: DepRate,
    /// Initiator's NFCID3 in wire order.
    pub nfcid3: [u8; 10],
    /// General bytes advertised by the initiator, in wire order.
    pub general_bytes: Vec<u8>,
}

/// Passive target activation or data exchange failure.
#[derive(Debug)]
pub enum DepError<E> {
    /// Reader initialization, register, or transaction failure.
    Reader(Error<E>),
    /// The firmware did not complete the listen command. A timeout after
    /// acknowledgement does not establish whether an initiator was present.
    Listen(Error<E>),
    /// More than 47 target general bytes were supplied.
    GeneralBytes(usize),
    /// The response exceeded the single-frame payload budget.
    ResponseLength(usize),
    /// The session has an unanswered request or was revoked after a failure.
    SessionUnavailable,
    /// The initiator requested active mode or the activation was malformed.
    Activation,
    /// The firmware returned a malformed response.
    Layout,
    /// The firmware reported an error, preserving the complete status byte.
    Status(u8),
    /// The firmware reported NAD or an incomplete request. The returned
    /// bytes are the prefix already received, and the session must close.
    UnsupportedRequest {
        /// Complete firmware status byte.
        status: u8,
        /// Received bytes including any addressing field.
        prefix: Vec<u8>,
    },
}

impl<E: fmt::Debug> fmt::Display for DepError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<E: core::error::Error + 'static> core::error::Error for DepError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Reader(error) | Self::Listen(error) => Some(error),
            _ => None,
        }
    }
}

impl<E> From<Error<E>> for DepError<E> {
    fn from(error: Error<E>) -> Self {
        Self::Reader(error)
    }
}

/// An exclusive passive NFC-DEP target session. The reader firmware handles
/// the NFC-DEP data frames. Call [Self::finish] to leave listen mode.
#[derive(Debug)]
pub struct PassiveDepTarget<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    initiator: DepInitiator,
    state: TargetState,
}

#[derive(Debug)]
enum TargetState {
    Waiting,
    Responding,
    Revoked,
}

/// The current initiator request and authority to answer it once.
#[derive(Debug)]
pub struct DepRequest<'a, 'reader, T: Transport> {
    target: &'a mut PassiveDepTarget<'reader, T>,
    payload: Vec<u8>,
}

impl<T: Transport> Reader<T> {
    /// Listen for a passive NFC-DEP initiator. The caller supplies a six-byte
    /// identity suffix for this activation and any application general bytes.
    /// The operation resets the reader before enabling target mode. On any
    /// failure after initialization begins, call [Self::initialize] before
    /// using the reader again.
    pub fn listen_passive_dep(
        &mut self,
        identity: [u8; 6],
        general_bytes: &[u8],
        timeout: RfTimeout,
    ) -> Result<PassiveDepTarget<'_, T>, DepError<T::Error>> {
        if general_bytes.len() > 47 {
            return Err(DepError::GeneralBytes(general_bytes.len()));
        }
        self.initialize()?;
        // Target registers and the firmware's selected mode are independent
        // of initiator RF configuration. Only a reset restores readiness.
        self.state = State::NeedsInitialization;
        self.write_register(0x630b, 0x80)?;
        expect_empty(self.command(
            0x32,
            &[0x82, RESPONSE_WAIT_INDEX, 2, RESPONSE_WAIT_INDEX],
            SETUP_WAIT,
        )?)?;
        expect_empty(self.command(0x12, &[0x08], SETUP_WAIT)?)?;
        self.write_register(0x6301, 0x7b)?;
        self.write_register(0x6302, 0xb0)?;
        self.write_register(0x6303, 0xb0)?;

        let [a, b, c, d, e, f] = identity;
        let nfcid2 = [1, 0xfe, a, b, c, d, e, f];
        let mut parameters = [0; 35];
        parameters[..7].copy_from_slice(&[2, 1, 1, a, b, c, 0x40]);
        parameters[7..15].copy_from_slice(&nfcid2);
        parameters[23..25].copy_from_slice(&[0xff, 0xff]);
        parameters[25..33].copy_from_slice(&nfcid2);
        let response = self
            .command(0x8c, &parameters, timeout.host_wait())
            .map_err(DepError::Listen)?;
        let initiator = parse_activation(&response)?;
        expect_status(self.command(0x92, general_bytes, SETUP_WAIT)?)?;
        Ok(PassiveDepTarget {
            reader: self,
            initiator,
            state: TargetState::Waiting,
        })
    }
}

impl<'reader, T: Transport> PassiveDepTarget<'reader, T> {
    /// Read the peer's NFC-DEP activation attributes.
    pub fn initiator(&self) -> &DepInitiator {
        &self.initiator
    }

    /// Wait for one request. This profile accepts one complete firmware
    /// fragment without NAD. Finish or reset after an incomplete exchange.
    pub fn receive(
        &mut self,
        timeout: RfTimeout,
    ) -> Result<DepRequest<'_, 'reader, T>, DepError<T::Error>> {
        if !matches!(self.state, TargetState::Waiting) {
            return Err(DepError::SessionUnavailable);
        }
        self.state = TargetState::Revoked;
        let mut reply = self.reader.command(0x86, &[], timeout.host_wait())?;
        let status = reply.first().copied().ok_or(DepError::Layout)?;
        if status & 0x3f != 0 {
            return Err(DepError::Status(status));
        }
        let payload = reply.split_off(1);
        if status != 0 {
            return Err(DepError::UnsupportedRequest {
                status,
                prefix: payload,
            });
        }
        self.state = TargetState::Responding;
        Ok(DepRequest {
            target: self,
            payload,
        })
    }

    /// Leave listen mode and recover the reader to RF-off readiness. This
    /// does not acknowledge or replay any pending application exchange.
    pub fn finish(self) -> Result<(), Error<T::Error>> {
        self.reader.initialize().map(|_| ())
    }
}

impl<T: Transport> DepRequest<'_, '_, T> {
    /// Payload delivered by the reader firmware.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Respond with up to 60 payload bytes, which fit in one NFC-DEP frame
    /// even with DID. An oversized reply can be corrected. A firmware or
    /// transport error revokes the session and may leave delivery uncertain.
    pub fn respond(&mut self, payload: &[u8]) -> Result<(), DepError<T::Error>> {
        if !matches!(self.target.state, TargetState::Responding) {
            return Err(DepError::SessionUnavailable);
        }
        if payload.len() > MAX_RESPONSE_BYTES {
            return Err(DepError::ResponseLength(payload.len()));
        }
        self.target.state = TargetState::Revoked;
        expect_status(self.target.reader.command(0x8e, payload, SETUP_WAIT)?)?;
        self.target.state = TargetState::Waiting;
        Ok(())
    }
}

fn parse_activation<E>(response: &[u8]) -> Result<DepInitiator, DepError<E>> {
    let [
        mode,
        length,
        0xd4,
        0,
        a,
        b,
        c,
        d,
        e,
        f,
        g,
        h,
        i,
        j,
        did,
        _,
        _,
        pp,
        general @ ..,
    ] = response
    else {
        return Err(DepError::Activation);
    };
    if mode & 1 != 0
        || usize::from(*length) != response.len() - 1
        || *did > 14
        || general.len() > 48
        || (pp & 2 != 0) == general.is_empty()
    {
        return Err(DepError::Activation);
    }
    let rate = match mode & 0x70 {
        0 => DepRate::Kbps106,
        0x10 => DepRate::Kbps212,
        0x20 => DepRate::Kbps424,
        _ => return Err(DepError::Activation),
    };
    Ok(DepInitiator {
        rate,
        nfcid3: [*a, *b, *c, *d, *e, *f, *g, *h, *i, *j],
        general_bytes: general.to_vec(),
    })
}

fn expect_status<E>(response: Vec<u8>) -> Result<(), DepError<E>> {
    match response.as_slice() {
        [0] => Ok(()),
        [status] => Err(DepError::Status(*status)),
        _ => Err(DepError::Layout),
    }
}

fn expect_empty<E>(response: Vec<u8>) -> Result<(), DepError<E>> {
    if response.is_empty() {
        Ok(())
    } else {
        Err(DepError::Layout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_activation_rejects_active_mode_and_inconsistent_atr() {
        let mut reply = [0x20, 17, 0xd4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0];
        assert!(parse_activation::<()>(&reply).is_ok());
        reply[0] = 0x21;
        assert!(matches!(
            parse_activation::<()>(&reply),
            Err(DepError::Activation)
        ));
        reply[0] = 0x20;
        reply[17] = 2;
        assert!(matches!(
            parse_activation::<()>(&reply),
            Err(DepError::Activation)
        ));
        reply[17] = 0;
        reply[1] -= 1;
        assert!(matches!(
            parse_activation::<()>(&reply),
            Err(DepError::Activation)
        ));
    }
}
