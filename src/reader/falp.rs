use super::{Error, FelicaCard, Reader, RfTimeout, State};
use crate::{
    falp::{
        self, Gaps, Kind, LocalParameters, MAX_APPLICATION_ID_BYTES, Message, Parameters, Pdu,
        Profile, RF_212, RF_424, Reason, ReceiveWindow, SendWindow,
    },
    felica::{self, BitRate, Idm},
    transport::Transport,
};
use alloc::vec::Vec;
use core::{fmt, time::Duration};

/// Host wait of one-way frames, matching the Sony driver's reader wait.
const READER_WAIT: Duration = Duration::from_secs(1);
/// Wait for the next block while the peer holds the turn.
const DATA_WAIT: Duration = Duration::from_millis(3000);
/// Largest single RF wait of the Propose and handshake steps.
const STEP_WAIT: Duration = Duration::from_millis(3000);
/// Shortest remaining wait the Propose and handshake steps use.
const STEP_MINIMUM: Duration = Duration::from_millis(100);
/// Receive attempts after a burst or a resend request.
const ATTEMPTS: u8 = 3;
/// Unexpected replies tolerated while one missing block is requested.
const STRIKES: u8 = 3;
/// Registers whose four bytes the Sony driver adds, little-endian, to its
/// frame processing time in microseconds.
const PROCESSING_REGISTERS: [u8; 8] = [0, 0x10, 0, 5, 0, 6, 0, 7];
/// System code the listening target advertises.
const SYSTEM_CODE: [u8; 2] = [0xfe, 0xe2];

/// Parameters of [`FelicaCard::connect_falp`].
#[derive(Clone, Copy, Debug)]
pub struct FalpConnect<'a> {
    /// Local parameter set.
    pub profile: Profile,
    /// Identifier the target must accept, at most
    /// [`MAX_APPLICATION_ID_BYTES`] bytes.
    pub application: &'a [u8],
    /// Connection value carried in every frame of the session.
    pub port: u16,
    /// Total wait for the Propose answer, 255 to 32768 ms.
    pub propose_timeout: Duration,
    /// Total wait for the handshake response; must be nonzero.
    pub handshake_timeout: Duration,
}

/// Parameters of [`Reader::listen_falp`].
#[derive(Clone, Copy, Debug)]
pub struct FalpListen<'a> {
    /// Local parameter set.
    pub profile: Profile,
    /// Suffix of the advertised IDm, which starts with `02 FE`.
    pub identity: [u8; 6],
    /// Identifiers this target accepts.
    pub applications: &'a [&'a [u8]],
    /// Total wait for the initiator's handshake after answering Propose.
    pub handshake_timeout: Duration,
}

/// Session establishment or transfer failure.
#[derive(Debug)]
pub enum FalpError<E> {
    /// A reader command failed outside a data turn. The session is revoked;
    /// call [`Reader::initialize`] before using the reader.
    Reader(Error<E>),
    /// The application identifier is longer than [`MAX_APPLICATION_ID_BYTES`].
    /// Nothing was sent.
    ApplicationLength(usize),
    /// A timeout parameter is outside its accepted range. Nothing was sent.
    TimeoutRange,
    /// The session ended or was revoked by a failure.
    Unavailable,
    /// The Propose request received no answer within its timeout.
    NoAnswer,
    /// The target rejected the Propose request.
    Rejected {
        /// Answer status byte.
        status: u8,
        /// Answer reason byte.
        reason: u8,
    },
    /// The Propose answer had an unexpected layout.
    Answer,
    /// Target activation was not a passive FeliCa Propose request.
    Activation,
    /// The handshake did not complete within its timeout.
    HandshakeTimeout,
    /// The handshake violated the protocol; a farewell with this reason was sent.
    Violation(Reason),
    /// The peer ended the session during the handshake, with its reason if
    /// the farewell message was well formed.
    Closed(Option<Reason>),
    /// A data turn failed after its first frame was sent.
    Transfer {
        /// Data bytes carried by this side's burst.
        sent: usize,
        /// The peer's burst started, so it received every block of ours.
        delivered: bool,
        /// Contiguous data of the peer's burst received before the failure.
        received: Vec<u8>,
        /// Reason the turn did not complete.
        cause: TransferCause<E>,
    },
}

/// Failure of a data turn.
#[derive(Debug)]
pub enum TransferCause<E> {
    /// A reader command failed; call [`Reader::initialize`].
    Reader(Error<E>),
    /// The peer stopped answering.
    Timeout,
    /// The peer violated the protocol; a farewell with this reason was sent.
    Violation(Reason),
}

impl<E: fmt::Debug> fmt::Display for FalpError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reader(_) => f.write_str("FALP reader command failed"),
            Self::ApplicationLength(length) => write!(
                f,
                "application identifier of {length} bytes exceeds {MAX_APPLICATION_ID_BYTES}"
            ),
            Self::TimeoutRange => f.write_str("FALP timeout is outside its range"),
            Self::Unavailable => f.write_str("FALP session is unavailable"),
            Self::NoAnswer => f.write_str("FALP Propose received no answer"),
            Self::Rejected { status, reason } => {
                write!(f, "FALP Propose rejected with {status:02X} {reason:02X}")
            }
            Self::Answer => f.write_str("malformed FALP Propose answer"),
            Self::Activation => f.write_str("target activation is not a FALP Propose"),
            Self::HandshakeTimeout => f.write_str("FALP handshake timed out"),
            Self::Violation(reason) => write!(f, "FALP handshake violation, {reason}"),
            Self::Closed(_) => f.write_str("peer ended the FALP session"),
            Self::Transfer {
                sent,
                delivered,
                cause,
                ..
            } => {
                f.write_str(match cause {
                    TransferCause::Reader(_) => "FALP reader command failed",
                    TransferCause::Timeout => "FALP peer stopped answering",
                    TransferCause::Violation(_) => "FALP peer violated the protocol",
                })?;
                write!(f, " after sending {sent} bytes")?;
                if !delivered {
                    f.write_str(", delivery unconfirmed")?;
                }
                Ok(())
            }
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for FalpError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Reader(error)
            | Self::Transfer {
                cause: TransferCause::Reader(error),
                ..
            } => Some(error),
            _ => None,
        }
    }
}

impl<E> From<Error<E>> for FalpError<E> {
    fn from(error: Error<E>) -> Self {
        Self::Reader(error)
    }
}

/// Result of one data turn.
#[derive(Debug, Eq, PartialEq)]
pub enum FalpTurn {
    /// This side's burst was received and the peer's burst completed.
    Exchanged {
        /// Data bytes carried by this side's burst.
        sent: usize,
        /// Data of the peer's burst, in order.
        received: Vec<u8>,
    },
    /// The peer sent a farewell. Call [`FalpLink::finish`].
    Closed {
        /// Data bytes carried by this side's burst.
        sent: usize,
        /// The peer's burst started before the farewell.
        delivered: bool,
        /// Contiguous data of the peer's burst received before the farewell.
        received: Vec<u8>,
        /// The peer's reason, if its farewell message was well formed.
        reason: Option<Reason>,
    },
}

/// A target session after the initiator's first burst.
#[derive(Debug)]
pub struct FalpAccepted<'a, T: Transport> {
    /// Session, holding the sending turn unless the turn closed it.
    pub link: FalpLink<'a, T>,
    /// The initiator's first burst; its `sent` is zero.
    pub turn: FalpTurn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Initiator,
    Target,
}

/// Exclusive FALP session. Between [`Self::exchange`] calls this side holds
/// the sending turn, and the peer waits about three seconds for its next
/// burst; call again with empty data to keep the session alive.
#[derive(Debug)]
pub struct FalpLink<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    role: Role,
    /// This side's IDm on a target, the peer's on an initiator.
    idm: Idm,
    port: u16,
    local: LocalParameters,
    peer: Parameters,
    send: SendWindow,
    receive: ReceiveWindow,
    /// The peer's last switch reported short receive space.
    peer_busy: bool,
    /// The peer's last burst carried no data.
    peer_empty: bool,
    /// Frame bytes of the last received data packet.
    last_received: u32,
    open: bool,
}

/// One received packet after envelope handling.
enum Incoming {
    Timeout,
    Message(Vec<u8>),
    Farewell(Option<Reason>),
}

/// How a data turn ended inside this module.
enum TurnEnd<E> {
    Closed(Option<Reason>),
    Failed(TransferCause<E>),
}

impl<E> From<Error<E>> for TurnEnd<E> {
    fn from(error: Error<E>) -> Self {
        Self::Failed(TransferCause::Reader(error))
    }
}

fn rf_rate(rate: BitRate) -> u32 {
    match rate {
        BitRate::Kbps212 => RF_212,
        BitRate::Kbps424 => RF_424,
    }
}

/// Clamp a protocol wait to the reader's half-ms range.
fn rf_wait(wait: Duration) -> RfTimeout {
    let bounded = wait.clamp(Duration::from_millis(1), Duration::from_millis(32_767));
    RfTimeout::new(bounded).unwrap_or(RfTimeout { ticks: u16::MAX })
}

fn farewell_reason(message: &[u8]) -> Option<Reason> {
    match Message::parse(message, u16::MAX) {
        Ok(m) if m.kind == Kind::Farewell => match m.body() {
            [high, low] => Some(Reason(u16::from_be_bytes([*high, *low]))),
            _ => None,
        },
        _ => None,
    }
}

impl<T: Transport> Reader<T> {
    /// Frame processing allowance the Sony driver reads from the reader.
    fn processing_allowance(&mut self) -> Result<u32, Error<T::Error>> {
        let bytes: [u8; 4] = self
            .command(6, &PROCESSING_REGISTERS, READER_WAIT)?
            .try_into()
            .map_err(|_| Error::Response("processing register length"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Interpret a reader reply carrying an RF status and optional packet.
    fn falp_packet(&mut self, response: Vec<u8>) -> Result<Option<Vec<u8>>, Error<T::Error>> {
        if matches!(response.first(), Some(status) if status & 0x3f == 1) {
            return Ok(None);
        }
        let packet = self.rf_response(response)?;
        felica::validate_length(&packet, 2).map_err(Error::FelicaResponse)?;
        Ok(Some(packet))
    }

    /// Send one packet without receiving a reply.
    fn falp_send(&mut self, role: Role, packet: &[u8]) -> Result<(), Error<T::Error>> {
        match role {
            Role::Initiator => {
                // A zero wait sends without receiving and reports RF timeout.
                let mut args = Vec::with_capacity(packet.len() + 2);
                args.extend_from_slice(&[0, 0]);
                args.extend_from_slice(packet);
                let response = self.command(0xa0, &args, READER_WAIT)?;
                match response.first() {
                    Some(status) if status & 0x3f == 1 => Ok(()),
                    Some(0) => Err(Error::Response("FALP send received a frame")),
                    _ => self.rf_response(response).map(|_| ()),
                }
            }
            Role::Target => match self.command(0x90, packet, READER_WAIT)?.as_slice() {
                [0] => Ok(()),
                [status] => Err(Error::RfStatus(*status)),
                _ => Err(Error::Response("FALP response status length")),
            },
        }
    }

    /// Receive one packet; `None` means the wait ended without a frame.
    fn falp_receive(
        &mut self,
        role: Role,
        wait: Duration,
    ) -> Result<Option<Vec<u8>>, Error<T::Error>> {
        let timeout = rf_wait(wait);
        let response = match role {
            Role::Initiator => {
                self.command(0xa0, &timeout.ticks.to_le_bytes(), timeout.host_wait())?
            }
            Role::Target => self.command(0x88, &[], timeout.host_wait())?,
        };
        self.falp_packet(response)
    }

    /// Send one packet and receive the next one in the same command.
    fn falp_send_receive(
        &mut self,
        packet: &[u8],
        wait: Duration,
    ) -> Result<Option<Vec<u8>>, Error<T::Error>> {
        let timeout = rf_wait(wait);
        let mut args = Vec::with_capacity(packet.len() + 2);
        args.extend_from_slice(&timeout.ticks.to_le_bytes());
        args.extend_from_slice(packet);
        let response = self.command(0xa0, &args, timeout.host_wait())?;
        self.falp_packet(response)
    }

    /// Remaining part of `total` after `start`, or `None` once it elapsed.
    fn falp_remaining(&self, start: Duration, total: Duration) -> Option<Duration> {
        let elapsed = self.link.now().saturating_sub(start);
        total.checked_sub(elapsed).filter(|wait| !wait.is_zero())
    }

    /// Wait for a data packet of the handshake until `total` elapses after
    /// `start`, beginning with `first` if a combined command returned one.
    fn falp_step(
        &mut self,
        role: Role,
        mut reply: Option<Vec<u8>>,
        start: Duration,
        total: Duration,
    ) -> Result<Vec<u8>, FalpError<T::Error>> {
        loop {
            if let Some(packet) = reply.take() {
                match Pdu::parse(&packet) {
                    Pdu::Data { message, .. } => return Ok(message.to_vec()),
                    Pdu::Farewell { message } => {
                        return Err(FalpError::Closed(farewell_reason(message)));
                    }
                    _ => {}
                }
            }
            let remaining = self
                .falp_remaining(start, total)
                .ok_or(FalpError::HandshakeTimeout)?;
            reply = self.falp_receive(role, remaining.clamp(STEP_MINIMUM, STEP_WAIT))?;
        }
    }

    /// Send a farewell and report the violation that caused it.
    fn falp_violation<X>(
        &mut self,
        role: Role,
        port: u16,
        reason: Reason,
    ) -> Result<X, FalpError<T::Error>> {
        self.falp_send(role, &falp::farewell_packet(port, &falp::farewell(reason)))?;
        Err(FalpError::Violation(reason))
    }

    /// Listen as a passive FeliCa target for one FALP initiator, accept its
    /// Propose and handshake, and receive its first burst. The reader is
    /// reset first; `timeout` bounds the wait for an initiator. A timeout of
    /// the activation command fails the reader transaction, so call
    /// [`Self::initialize`] before listening again.
    ///
    /// Each later wait for an initiator frame also fails the reader
    /// transaction when it times out, because the reader's command that
    /// receives the next frame cannot be ended without a reset.
    pub fn listen_falp(
        &mut self,
        config: FalpListen<'_>,
        timeout: RfTimeout,
    ) -> Result<FalpAccepted<'_, T>, FalpError<T::Error>> {
        if config.handshake_timeout.is_zero() {
            return Err(FalpError::TimeoutRange);
        }
        self.initialize()?;
        self.state = State::NeedsInitialization;
        let allowance = self.processing_allowance()?;
        let [a, b, c, d, e, f] = config.identity;
        let idm = Idm::new([2, 0xfe, a, b, c, d, e, f]);
        let mut args = Vec::with_capacity(36);
        args.extend_from_slice(&[0, 0, 1, 1, 2, 3, 0]);
        args.extend_from_slice(idm.as_bytes());
        args.extend_from_slice(&[0, 0x22, 3, 3, 3, 3, 3, 3]);
        args.extend_from_slice(&SYSTEM_CODE);
        args.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x55]);
        let activation = self.command(0x8c, &args, timeout.host_wait())?;
        let (rate, packet) = match activation.as_slice() {
            [0x12, packet @ ..] => (RF_212, packet),
            [0x22, packet @ ..] => (RF_424, packet),
            _ => return Err(FalpError::Activation),
        };
        felica::validate_length(packet, 2).map_err(|_| FalpError::Activation)?;
        let Pdu::Propose { port, .. } = Pdu::parse(packet) else {
            return Err(FalpError::Activation);
        };
        let mut local = LocalParameters::new(config.profile, rate, allowance);

        let start = self.link.now();
        let reply = self.falp_send_receive(
            &falp::accept_packet(idm, port),
            config.handshake_timeout.min(STEP_WAIT),
        )?;
        let message = self.falp_step(Role::Target, reply, start, config.handshake_timeout)?;
        let handshake = match Message::parse(&message, u16::MAX) {
            Ok(m) if m.kind == Kind::Handshake => match falp::parse_handshake(&m, local.wire) {
                Ok(handshake) => handshake,
                Err(reason) => return self.falp_violation(Role::Target, port, reason),
            },
            Ok(m) if m.kind == Kind::Farewell => {
                return self.falp_violation(Role::Target, port, Reason::FORMAT);
            }
            Ok(_) => return self.falp_violation(Role::Target, port, Reason::UNEXPECTED),
            Err(reason) => return self.falp_violation(Role::Target, port, reason),
        };
        if !config.applications.contains(&handshake.application) {
            return self.falp_violation(Role::Target, port, Reason::APPLICATION);
        }
        // The target transmits at the initiator's rate.
        local.wire.rf_bit_rate = handshake.parameters.rf_bit_rate;
        let peer = handshake.parameters;
        let response = falp::handshake_response(&local.wire);
        self.falp_send(Role::Target, &falp::data_packet(port, &response))?;
        let mut link = FalpLink::new(self, Role::Target, idm, port, local, peer);
        let turn = match link.receive_burst(None) {
            Ok(received) => FalpTurn::Exchanged { sent: 0, received },
            Err(TurnEnd::Closed(reason)) => {
                link.open = false;
                FalpTurn::Closed {
                    sent: 0,
                    delivered: true,
                    received: link.receive.prefix(),
                    reason,
                }
            }
            Err(TurnEnd::Failed(cause)) => {
                return Err(FalpError::Transfer {
                    sent: 0,
                    delivered: true,
                    received: link.receive.prefix(),
                    cause,
                });
            }
        };
        Ok(FalpAccepted { link, turn })
    }
}

impl<'a, T: Transport> FelicaCard<'a, T> {
    /// Connect to a FALP target selected by polling, at its polling rate.
    /// Propose is sent once; the answer and the handshake response are then
    /// awaited until their timeouts elapse. The card's typed authority ends
    /// here; [`FalpLink::finish`] or [`FalpLink::close`] restore the reader.
    pub fn connect_falp(
        self,
        config: FalpConnect<'_>,
    ) -> Result<FalpLink<'a, T>, FalpError<T::Error>> {
        if config.application.len() > MAX_APPLICATION_ID_BYTES {
            return Err(FalpError::ApplicationLength(config.application.len()));
        }
        let propose_range = Duration::from_millis(255)..=Duration::from_millis(0x8000);
        if !propose_range.contains(&config.propose_timeout) || config.handshake_timeout.is_zero() {
            return Err(FalpError::TimeoutRange);
        }
        let Self {
            reader,
            observation,
            rate,
            ..
        } = self;
        reader.state = State::NeedsInitialization;
        let allowance = reader.processing_allowance()?;
        let local = LocalParameters::new(config.profile, rf_rate(rate), allowance);
        let idm = observation.idm;

        let start = reader.link.now();
        let mut answer = reader.falp_send_receive(
            &falp::propose_packet(idm, config.port, config.propose_timeout),
            config.propose_timeout.min(STEP_WAIT),
        )?;
        let port = loop {
            if let Some(packet) = answer.take() {
                match Pdu::parse(&packet) {
                    Pdu::Accepted { port } => break port,
                    Pdu::Rejected { status, reason } => {
                        return Err(FalpError::Rejected { status, reason });
                    }
                    _ => return Err(FalpError::Answer),
                }
            }
            let remaining = reader
                .falp_remaining(start, config.propose_timeout)
                .ok_or(FalpError::NoAnswer)?;
            answer =
                reader.falp_receive(Role::Initiator, remaining.clamp(STEP_MINIMUM, STEP_WAIT))?;
        };

        let start = reader.link.now();
        let hello = falp::data_packet(port, &falp::handshake(config.application, &local.wire));
        let reply = reader.falp_send_receive(&hello, config.handshake_timeout.min(STEP_WAIT))?;
        let message = reader.falp_step(Role::Initiator, reply, start, config.handshake_timeout)?;
        let peer = match Message::parse(&message, u16::MAX) {
            Ok(m) if m.kind == Kind::HandshakeResponse => {
                match falp::parse_handshake_response(&m, local.wire) {
                    Ok(peer) => peer,
                    Err(reason) => return reader.falp_violation(Role::Initiator, port, reason),
                }
            }
            Ok(m) if m.kind == Kind::Farewell => {
                return reader.falp_violation(Role::Initiator, port, Reason::FORMAT);
            }
            Ok(_) => return reader.falp_violation(Role::Initiator, port, Reason::UNEXPECTED),
            Err(reason) => return reader.falp_violation(Role::Initiator, port, reason),
        };
        Ok(FalpLink::new(
            reader,
            Role::Initiator,
            idm,
            port,
            local,
            peer,
        ))
    }
}

impl<'a, T: Transport> FalpLink<'a, T> {
    fn new(
        reader: &'a mut Reader<T>,
        role: Role,
        idm: Idm,
        port: u16,
        local: LocalParameters,
        peer: Parameters,
    ) -> Self {
        Self {
            reader,
            role,
            idm,
            port,
            local,
            peer,
            send: SendWindow::default(),
            receive: ReceiveWindow::new(local.wire.blocks),
            peer_busy: false,
            peer_empty: false,
            last_received: 0,
            open: true,
        }
    }

    /// Send one burst carrying the first part of `data`, then collect the
    /// peer's burst. A burst carries at most the peer's block limits, and no
    /// data while the peer reports short receive space; `sent` tells how much
    /// of `data` the burst carried. Lost blocks are requested again and the
    /// last block of a burst is sent again when the peer does not answer,
    /// as the protocol's block numbers make duplicates harmless.
    pub fn exchange(&mut self, data: &[u8]) -> Result<FalpTurn, FalpError<T::Error>> {
        if !self.open {
            return Err(FalpError::Unavailable);
        }
        self.open = false;
        let burst = self.send.build(data, &self.peer, !self.peer_busy);
        let mut delivered = false;
        let result = self
            .send_burst(burst.empty)
            .and_then(|()| self.await_peer(burst.empty, &mut delivered));
        match result {
            Ok(received) => {
                self.open = true;
                Ok(FalpTurn::Exchanged {
                    sent: burst.carried,
                    received,
                })
            }
            Err(TurnEnd::Closed(reason)) => Ok(FalpTurn::Closed {
                sent: burst.carried,
                delivered,
                received: self.receive.prefix(),
                reason,
            }),
            Err(TurnEnd::Failed(cause)) => Err(FalpError::Transfer {
                sent: burst.carried,
                delivered,
                received: self.receive.prefix(),
                cause,
            }),
        }
    }

    /// End the session with an orderly farewell, then reinitialize the reader.
    pub fn close(self) -> Result<(), FalpError<T::Error>> {
        if self.open {
            let wait = falp::send_wait(
                self.last_received,
                falp::frame_bytes(5),
                &self.local,
                &self.peer,
                false,
            );
            self.reader.link.wait(wait);
            let message = falp::farewell(Reason::NORMAL);
            self.reader
                .falp_send(self.role, &falp::farewell_packet(self.port, &message))?;
        }
        self.reader.initialize()?;
        Ok(())
    }

    /// Leave the session without a farewell and reinitialize the reader.
    pub fn finish(self) -> Result<(), Error<T::Error>> {
        self.reader.initialize().map(|_| ())
    }

    fn send_packet(&mut self, message: &[u8]) -> Result<(), Error<T::Error>> {
        self.reader
            .falp_send(self.role, &falp::data_packet(self.port, message))
    }

    fn send_burst(&mut self, empty: bool) -> Result<(), TurnEnd<T::Error>> {
        let messages: Vec<Vec<u8>> = self.send.messages().to_vec();
        let first = messages.first().map_or(0, |m| falp::frame_bytes(m.len()));
        let switching = empty && self.peer_empty;
        let wait = falp::send_wait(
            self.last_received,
            first,
            &self.local,
            &self.peer,
            switching,
        );
        self.reader.link.wait(wait);
        let mut previous: Option<u32> = None;
        for message in &messages {
            let frame = falp::frame_bytes(message.len());
            if let Some(sent) = previous {
                let wait = falp::block_interval(sent, frame, &self.local, &self.peer)
                    + self.local.inter_block_delay;
                self.reader.link.wait(wait);
            }
            self.send_packet(message)?;
            previous = Some(frame);
        }
        Ok(())
    }

    /// Receive one data or farewell packet, answering envelope-level
    /// requests on the way.
    fn next_message(&mut self, wait: Duration) -> Result<Incoming, Error<T::Error>> {
        let start = self.reader.link.now();
        loop {
            let Some(remaining) = self.reader.falp_remaining(start, wait) else {
                return Ok(Incoming::Timeout);
            };
            let Some(packet) = self.reader.falp_receive(self.role, remaining)? else {
                return Ok(Incoming::Timeout);
            };
            match Pdu::parse(&packet) {
                Pdu::Data {
                    acknowledge,
                    message,
                } => {
                    self.last_received = falp::frame_bytes(message.len());
                    if acknowledge {
                        self.reader.falp_send(self.role, &falp::data_ack_packet())?;
                    }
                    return Ok(Incoming::Message(message.to_vec()));
                }
                Pdu::Farewell { message } => {
                    return Ok(Incoming::Farewell(farewell_reason(message)));
                }
                Pdu::StatusQuery { idm } if self.role == Role::Target && idm == self.idm => {
                    let reply = falp::status_reply_packet(idm, true, self.port);
                    self.reader.falp_send(self.role, &reply)?;
                }
                Pdu::Propose { idm, .. } if self.role == Role::Target => {
                    self.reader
                        .falp_send(self.role, &falp::reject_packet(idm))?;
                }
                _ => {}
            }
        }
    }

    fn violation<X>(&mut self, reason: Reason) -> Result<X, TurnEnd<T::Error>> {
        let message = falp::farewell(reason);
        self.reader
            .falp_send(self.role, &falp::farewell_packet(self.port, &message))?;
        Err(TurnEnd::Failed(TransferCause::Violation(reason)))
    }

    fn parse<'m>(&mut self, bytes: &'m [u8]) -> Result<Message<'m>, TurnEnd<T::Error>> {
        match Message::parse(bytes, self.local.wire.block_bytes) {
            Ok(message) => Ok(message),
            Err(reason) => self.violation(reason),
        }
    }

    /// Wait for the peer to take the turn, answering its resend requests and
    /// repeating this side's last block when it does not answer.
    fn await_peer(
        &mut self,
        empty: bool,
        delivered: &mut bool,
    ) -> Result<Vec<u8>, TurnEnd<T::Error>> {
        let mut attempts = ATTEMPTS;
        let mut repeated: Option<Vec<u8>> = None;
        loop {
            let wait = falp::receive_timeout(&self.local, &self.peer, empty);
            let bytes = match self.next_message(wait)? {
                Incoming::Timeout => {
                    attempts -= 1;
                    if attempts == 0 {
                        return Err(TurnEnd::Failed(TransferCause::Timeout));
                    }
                    let last = repeated
                        .clone()
                        .or_else(|| self.send.messages().last().cloned())
                        .unwrap_or_default();
                    self.send_packet(&last)?;
                    continue;
                }
                Incoming::Farewell(reason) => return Err(TurnEnd::Closed(reason)),
                Incoming::Message(bytes) => bytes,
            };
            let message = self.parse(&bytes)?;
            match message.kind {
                Kind::Data | Kind::Switch | Kind::SwitchBusy => {
                    if !self.receive.contains(message.number) {
                        return self.violation(Reason::WINDOW);
                    }
                    self.send.acknowledge();
                    *delivered = true;
                    return self.receive_burst(Some(message));
                }
                Kind::ResendRequest => {
                    let Some(block) = self.send.resend(message.number) else {
                        return self.violation(Reason::WINDOW);
                    };
                    let wait = falp::send_wait(
                        self.last_received,
                        falp::frame_bytes(block.len()),
                        &self.local,
                        &self.peer,
                        false,
                    );
                    self.reader.link.wait(wait);
                    self.send_packet(&block)?;
                    repeated = Some(block);
                    attempts = ATTEMPTS;
                }
                Kind::Farewell => return self.violation(Reason::FORMAT),
                Kind::Handshake | Kind::HandshakeResponse | Kind::Resend => {
                    return self.violation(Reason::UNEXPECTED);
                }
            }
        }
    }

    /// Collect the peer's burst, starting with `first` if already received.
    fn receive_burst(&mut self, first: Option<Message<'_>>) -> Result<Vec<u8>, TurnEnd<T::Error>> {
        let mut pending = first.map(|m| m.bytes.to_vec());
        loop {
            let bytes = match pending.take() {
                Some(bytes) => bytes,
                None => match self.next_message(DATA_WAIT)? {
                    Incoming::Timeout => return Err(TurnEnd::Failed(TransferCause::Timeout)),
                    Incoming::Farewell(reason) => return Err(TurnEnd::Closed(reason)),
                    Incoming::Message(bytes) => bytes,
                },
            };
            let message = self.parse(&bytes)?;
            match message.kind {
                Kind::Data | Kind::Switch | Kind::SwitchBusy => {
                    if self.receive.store(&message).is_err() {
                        return self.violation(Reason::WINDOW);
                    }
                    if message.kind != Kind::Data {
                        self.peer_busy = message.kind == Kind::SwitchBusy;
                        self.peer_empty = message.body().is_empty();
                        return self.complete_burst();
                    }
                }
                Kind::Farewell => return self.violation(Reason::FORMAT),
                _ => return self.violation(Reason::UNEXPECTED),
            }
        }
    }

    /// Request missing blocks one at a time, then deliver the burst.
    fn complete_burst(&mut self) -> Result<Vec<u8>, TurnEnd<T::Error>> {
        loop {
            match self.receive.gaps() {
                Gaps::Complete => return Ok(self.receive.take()),
                Gaps::Excessive => return self.violation(Reason::LOSS),
                Gaps::Missing { first } => self.recover_block(first)?,
            }
        }
    }

    fn recover_block(&mut self, number: u16) -> Result<(), TurnEnd<T::Error>> {
        let request = falp::message(Kind::ResendRequest, number, &[]);
        let mut wait_first = true;
        let mut attempts = ATTEMPTS;
        let mut strikes = 0;
        loop {
            if wait_first {
                let wait = falp::send_wait(
                    self.last_received,
                    falp::frame_bytes(request.len()),
                    &self.local,
                    &self.peer,
                    false,
                );
                self.reader.link.wait(wait);
            }
            self.send_packet(&request)?;
            wait_first = true;
            let bytes = loop {
                let wait = falp::receive_timeout(&self.local, &self.peer, false);
                match self.next_message(wait)? {
                    Incoming::Timeout => {
                        attempts -= 1;
                        if attempts == 0 {
                            return Err(TurnEnd::Failed(TransferCause::Timeout));
                        }
                        wait_first = false;
                        break None;
                    }
                    Incoming::Farewell(reason) => return Err(TurnEnd::Closed(reason)),
                    Incoming::Message(bytes) => {
                        let message = self.parse(&bytes)?;
                        if message.kind != Kind::Data {
                            break Some(bytes);
                        }
                    }
                }
            };
            let Some(bytes) = bytes else { continue };
            let message = self.parse(&bytes)?;
            match message.kind {
                Kind::Resend if message.number == number => {
                    if self.receive.store(&message).is_err() {
                        return self.violation(Reason::WINDOW);
                    }
                    return Ok(());
                }
                Kind::Resend | Kind::Switch | Kind::SwitchBusy | Kind::ResendRequest => {
                    strikes += 1;
                    if strikes >= STRIKES {
                        let reason = if message.kind == Kind::Resend {
                            Reason::WINDOW
                        } else {
                            Reason::UNEXPECTED
                        };
                        return self.violation(reason);
                    }
                }
                Kind::Farewell => return self.violation(Reason::FORMAT),
                _ => return self.violation(Reason::UNEXPECTED),
            }
        }
    }
}
