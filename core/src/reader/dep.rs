use super::{Error, Reader, ResponseTimeout, RfTimeout, State};
use crate::transport::Transport;
use alloc::vec::Vec;
use core::{fmt, time::Duration};

const SETUP_WAIT: Duration = Duration::from_secs(1);
const RESPONSE_WAIT_INDEX: u8 = 8;
const DEP_CHUNK_BYTES: usize = 60;
const MORE_INFORMATION: u8 = 0x40;
const NAD_PRESENT: u8 = 0x80;
const MAX_FRAGMENTS: usize = 256;

/// Maximum application bytes in one chained request or response.
pub const MAX_DEP_MESSAGE_BYTES: usize = (DEP_CHUNK_BYTES - 1) * MAX_FRAGMENTS;

/// NFC-DEP activation rate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepRate {
    /// NFC-A at 106 kbps.
    Kbps106,
    /// NFC-F at 212 kbps.
    Kbps212,
    /// NFC-F at 424 kbps.
    Kbps424,
}

/// Which participant generates the RF field during NFC-DEP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepMode {
    /// Only the initiator generates the RF field.
    Passive,
    /// Both participants generate an RF field when transmitting.
    Active,
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

/// NFC-DEP activation or data exchange failure.
#[derive(Debug)]
pub enum DepError<E> {
    /// Reader initialization, register, or transaction failure.
    Reader(Error<E>),
    /// The firmware did not complete the listen command. A timeout after
    /// acknowledgement does not establish whether an initiator was present.
    Listen(Error<E>),
    /// More general bytes were supplied than fit the selected role's ATR.
    GeneralBytes(usize),
    /// The message exceeded [MAX_DEP_MESSAGE_BYTES].
    MessageLength(usize),
    /// The session has an unanswered request or was revoked after a failure.
    SessionUnavailable,
    /// Activation used an unsupported mode or returned malformed attributes.
    Activation,
    /// The firmware returned a malformed response.
    Layout,
    /// The firmware reported an error, preserving the complete status byte.
    Status(u8),
    /// The peer did not accept use of a node address.
    NodeAddressUnavailable,
    /// Failure after the message transfer began. The session is revoked.
    Transfer {
        /// Application bytes submitted to firmware, including a failing fragment.
        attempted: usize,
        /// Application bytes accepted by completed firmware commands.
        accepted: usize,
        /// Application bytes collected before failure.
        received: DepMessage,
        /// Reason the message did not complete.
        cause: DepTransferCause<E>,
    },
}

/// Failure while sending or collecting an NFC-DEP message.
#[derive(Debug)]
pub enum DepTransferCause<E> {
    /// Host/reader command failed.
    Reader(Error<E>),
    /// RF exchange failed; preserves all reader status bits.
    Status(u8),
    /// Firmware output violated the command's response layout.
    Layout,
    /// A node address was missing, unexpected, repeated or different.
    NodeAddress,
    /// The reader exceeded the message byte or fragment budget.
    Limit,
}

impl<E: fmt::Debug> fmt::Display for DepError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reader(_) => f.write_str("NFC-DEP reader command failed"),
            Self::Listen(_) => f.write_str("NFC-DEP listen did not complete"),
            Self::GeneralBytes(length) => {
                write!(f, "{length} general bytes do not fit the ATR")
            }
            Self::MessageLength(length) => write!(
                f,
                "NFC-DEP message of {length} bytes exceeds {MAX_DEP_MESSAGE_BYTES}"
            ),
            Self::SessionUnavailable => f.write_str("NFC-DEP session is unavailable"),
            Self::Activation => f.write_str("NFC-DEP activation is unsupported or malformed"),
            Self::Layout => f.write_str("malformed NFC-DEP firmware response"),
            Self::Status(status) => write!(f, "NFC-DEP status {status:02X}"),
            Self::NodeAddressUnavailable => f.write_str("peer did not accept a node address"),
            Self::Transfer {
                attempted,
                accepted,
                received,
                cause,
            } => {
                f.write_str(match cause {
                    DepTransferCause::Reader(_) => "NFC-DEP reader command failed",
                    DepTransferCause::Status(_) => "NFC-DEP RF exchange failed",
                    DepTransferCause::Layout => "malformed NFC-DEP firmware response",
                    DepTransferCause::NodeAddress => "inconsistent NFC-DEP node address",
                    DepTransferCause::Limit => "NFC-DEP message or fragment limit exceeded",
                })?;
                if let DepTransferCause::Status(status) = cause {
                    write!(f, " with status {status:02X}")?;
                }
                write!(
                    f,
                    " after {attempted} bytes submitted, {accepted} accepted, {} received",
                    received.payload.len()
                )
            }
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for DepError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Reader(error) | Self::Listen(error) => Some(error),
            Self::Transfer {
                cause: DepTransferCause::Reader(error),
                ..
            } => Some(error),
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
    message: DepMessage,
}

/// One complete NFC-DEP application message and its optional node address.
#[derive(Debug, Default)]
pub struct DepMessage {
    /// Address byte in wire order, with the initiator in the high nibble.
    pub node_address: Option<u8>,
    /// Reassembled application data without the address byte.
    pub payload: Vec<u8>,
}

/// Target attributes reported by the NFC-DEP activation command.
#[derive(Debug)]
pub struct DepPeer {
    /// Target identifier (NFCID3t).
    pub nfcid3: [u8; 10],
    /// General bytes advertised in ATR_RES.
    pub general_bytes: Vec<u8>,
}

/// Exclusive NFC-DEP initiator session. The firmware owns RF framing and
/// link-level acknowledgements. [Self::finish] restores reader readiness.
#[derive(Debug)]
pub struct DepLink<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    peer: DepPeer,
    target: Option<u8>,
    node_address: Option<u8>,
    timeout: RfTimeout,
}

/// Parameters for initiating NFC-DEP.
#[derive(Clone, Copy, Debug)]
pub struct DepActivation<'a> {
    /// RF field ownership during transmission.
    pub mode: DepMode,
    /// Rate used during discovery and data exchange.
    pub rate: DepRate,
    /// Explicit initiator identifier, or let firmware generate it.
    /// Passive NFC-F requires `None` because the peer's identity supplies it.
    pub nfcid3: Option<[u8; 10]>,
    /// General bytes to include in ATR_REQ.
    pub general_bytes: &'a [u8],
    /// Optional NAD, with the initiator in the high nibble.
    pub node_address: Option<u8>,
}

impl<T: Transport> Reader<T> {
    /// Activate one NFC-DEP target. The reader must be reset before changing
    /// roles, so this operation performs initialization even on a ready reader.
    /// A failed activation leaves the reader requiring initialization.
    pub fn activate_dep(
        &mut self,
        activation: DepActivation<'_>,
        timeout: RfTimeout,
    ) -> Result<DepLink<'_, T>, DepError<T::Error>> {
        let args = initiator_arguments(activation)?;
        self.initialize()?;
        self.state = State::NeedsInitialization;
        expect_empty(self.command(
            0x12,
            &[u8::from(activation.node_address.is_some())],
            SETUP_WAIT,
        )?)?;
        let timing = ResponseTimeout::for_request(timeout);
        expect_empty(self.command(0x32, &timing.args(), SETUP_WAIT)?)?;
        expect_empty(self.command(0x32, &[5, 0, 0, 0], SETUP_WAIT)?)?;
        let response = self.command(0x56, &args, timing.host_wait())?;
        let (target, peer) = parse_peer(&response, activation.node_address.is_some())?;
        Ok(DepLink {
            reader: self,
            peer,
            target: Some(target),
            node_address: activation.node_address,
            timeout,
        })
    }

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

    /// Wait for one complete request, collecting continuation fragments.
    /// A failed transfer revokes the session and retains the received prefix.
    pub fn receive(
        &mut self,
        timeout: RfTimeout,
    ) -> Result<DepRequest<'_, 'reader, T>, DepError<T::Error>> {
        if !matches!(self.state, TargetState::Waiting) {
            return Err(DepError::SessionUnavailable);
        }
        self.state = TargetState::Revoked;
        let mut transfer = Transfer::default();
        let result = transfer.receive(|| self.reader.command(0x86, &[], timeout.host_wait()));
        if let Err(cause) = result {
            return Err(transfer.error(cause));
        }
        self.state = TargetState::Responding;
        Ok(DepRequest {
            target: self,
            message: transfer.message,
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
        &self.message.payload
    }

    /// Node address in the first received fragment, if present.
    pub fn node_address(&self) -> Option<u8> {
        self.message.node_address
    }

    /// Respond with a bounded message, using the request's node address.
    /// An oversized reply can be corrected. An exchange failure revokes the
    /// session and may leave delivery uncertain.
    pub fn respond(&mut self, payload: &[u8]) -> Result<(), DepError<T::Error>> {
        if !matches!(self.target.state, TargetState::Responding) {
            return Err(DepError::SessionUnavailable);
        }
        if payload.len() > MAX_DEP_MESSAGE_BYTES {
            return Err(DepError::MessageLength(payload.len()));
        }
        self.target.state = TargetState::Revoked;
        let mut transfer = Transfer::default();
        let result = transfer.send(payload, self.message.node_address, |more, data| {
            let command = if more { 0x94 } else { 0x8e };
            self.target.reader.command(command, data, SETUP_WAIT)
        });
        match result {
            Ok(reply) if reply == [0] => {}
            Ok(_) => return Err(transfer.error(DepTransferCause::Layout)),
            Err(cause) => return Err(transfer.error(cause)),
        }
        self.target.state = TargetState::Waiting;
        Ok(())
    }
}

impl<T: Transport> DepLink<'_, T> {
    /// Attributes obtained during activation.
    pub fn peer(&self) -> &DepPeer {
        &self.peer
    }

    /// Send one message and collect its complete response. The timeout applies
    /// per host fragment. An oversized request does not consume the session.
    pub fn exchange(&mut self, payload: &[u8]) -> Result<DepMessage, DepError<T::Error>> {
        if payload.len() > MAX_DEP_MESSAGE_BYTES {
            return Err(DepError::MessageLength(payload.len()));
        }
        let target = self.target.take().ok_or(DepError::SessionUnavailable)?;
        let mut transfer = Transfer::default();
        let result = (|| {
            let reply = transfer.send(payload, self.node_address, |more, data| {
                let mut args = Vec::with_capacity(1 + data.len());
                args.push(target | if more { MORE_INFORMATION } else { 0 });
                args.extend_from_slice(data);
                self.reader.command(0x40, &args, self.timeout.host_wait())
            })?;
            let mut first = Some(reply);
            transfer.receive(|| match first.take() {
                Some(reply) => Ok(reply),
                None => self
                    .reader
                    .command(0x40, &[target], self.timeout.host_wait()),
            })?;
            if transfer.message.node_address != self.node_address {
                return Err(DepTransferCause::NodeAddress);
            }
            Ok(())
        })();
        if let Err(cause) = result {
            return Err(transfer.error(cause));
        }
        self.target = Some(target);
        Ok(transfer.message)
    }

    /// End the link and restore RF-off readiness by reinitializing the reader.
    pub fn finish(self) -> Result<(), Error<T::Error>> {
        self.reader.initialize().map(|_| ())
    }
}

#[derive(Default)]
struct Transfer {
    attempted: usize,
    accepted: usize,
    message: DepMessage,
}

impl Transfer {
    fn send<E>(
        &mut self,
        mut payload: &[u8],
        mut node_address: Option<u8>,
        mut command: impl FnMut(bool, &[u8]) -> Result<Vec<u8>, Error<E>>,
    ) -> Result<Vec<u8>, DepTransferCause<E>> {
        loop {
            let address = node_address.take();
            let count = payload
                .len()
                .min(DEP_CHUNK_BYTES - usize::from(address.is_some()));
            let (chunk, rest) = payload.split_at(count);
            let mut data = Vec::with_capacity(DEP_CHUNK_BYTES);
            data.extend(address);
            data.extend_from_slice(chunk);
            self.attempted += count;
            let reply = command(!rest.is_empty(), &data).map_err(DepTransferCause::Reader)?;
            let (status, _) = fragment(&reply)?;
            self.accepted += count;
            if rest.is_empty() {
                return Ok(reply);
            }
            if status != 0 || reply.len() != 1 {
                return Err(DepTransferCause::Layout);
            }
            payload = rest;
        }
    }

    fn receive<E>(
        &mut self,
        mut command: impl FnMut() -> Result<Vec<u8>, Error<E>>,
    ) -> Result<(), DepTransferCause<E>> {
        for index in 0..MAX_FRAGMENTS {
            let response = command().map_err(DepTransferCause::Reader)?;
            let (status, mut data) = fragment(&response)?;
            if status & NAD_PRESENT != 0 {
                let (&address, rest) = data.split_first().ok_or(DepTransferCause::Layout)?;
                if index != 0 {
                    return Err(DepTransferCause::NodeAddress);
                }
                self.message.node_address = Some(address);
                data = rest;
            }
            if self.message.payload.len() + data.len() > MAX_DEP_MESSAGE_BYTES {
                return Err(DepTransferCause::Limit);
            }
            self.message.payload.extend_from_slice(data);
            if status & MORE_INFORMATION == 0 {
                return Ok(());
            }
        }
        Err(DepTransferCause::Limit)
    }

    fn error<E>(self, cause: DepTransferCause<E>) -> DepError<E> {
        DepError::Transfer {
            attempted: self.attempted,
            accepted: self.accepted,
            received: self.message,
            cause,
        }
    }
}

fn fragment<E>(response: &[u8]) -> Result<(u8, &[u8]), DepTransferCause<E>> {
    let (&status, data) = response.split_first().ok_or(DepTransferCause::Layout)?;
    if status & 0x3f != 0 {
        return Err(DepTransferCause::Status(status));
    }
    Ok((status, data))
}

fn initiator_arguments<E>(activation: DepActivation<'_>) -> Result<Vec<u8>, DepError<E>> {
    if activation.general_bytes.len() > 48 {
        return Err(DepError::GeneralBytes(activation.general_bytes.len()));
    }
    let rate = match activation.rate {
        DepRate::Kbps106 => 0,
        DepRate::Kbps212 => 1,
        DepRate::Kbps424 => 2,
    };
    let passive_f = activation.mode == DepMode::Passive && rate != 0;
    if passive_f && activation.nfcid3.is_some() {
        return Err(DepError::Activation);
    }
    let mut args = Vec::with_capacity(3 + 10 + activation.general_bytes.len());
    let flags = u8::from(passive_f)
        | (u8::from(activation.nfcid3.is_some()) << 1)
        | (u8::from(!activation.general_bytes.is_empty()) << 2);
    args.extend([u8::from(activation.mode == DepMode::Active), rate, flags]);
    if passive_f {
        args.extend([0, 0xff, 0xff, 0, 0]);
    } else if let Some(nfcid3) = activation.nfcid3 {
        args.extend(nfcid3);
    }
    args.extend_from_slice(activation.general_bytes);
    Ok(args)
}

fn parse_peer<E>(response: &[u8], addressed: bool) -> Result<(u8, DepPeer), DepError<E>> {
    if let Some(&status) = response.first()
        && status != 0
    {
        return Err(DepError::Status(status));
    }
    let [0, target @ 1, atr @ ..] = response else {
        return Err(DepError::Activation);
    };
    let Some((nfcid3, [did, _, _, to, pp, general @ ..])) = atr.split_first_chunk::<10>() else {
        return Err(DepError::Activation);
    };
    if *did != 0 || *to > 14 || general.len() > 47 || (pp & 2 != 0) == general.is_empty() {
        return Err(DepError::Activation);
    }
    if addressed && pp & 1 == 0 {
        return Err(DepError::NodeAddressUnavailable);
    }
    Ok((
        *target,
        DepPeer {
            nfcid3: *nfcid3,
            general_bytes: general.to_vec(),
        },
    ))
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
