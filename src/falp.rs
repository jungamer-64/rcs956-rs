//! FALP packet, parameter and window rules, without reader commands.
//!
//! FALP carries a byte stream between two devices in FeliCa packets. Each
//! side sends bursts of numbered blocks; the last block of a burst passes the
//! sending turn to the peer, and the peer's next burst acknowledges the whole
//! burst. Missing blocks are requested one at a time before the turn passes.

use crate::felica::Idm;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{fmt, time::Duration};

/// Bytes of a block message before its data: type and big-endian number.
const MESSAGE_HEADER: usize = 3;
/// Bytes of a `BC` / `AE` envelope before the message.
const ENVELOPE_HEADER: usize = 5;
/// Fewest bytes of a handshake message without its application identifier.
const HANDSHAKE_MINIMUM: usize = 48;
/// Bytes of a handshake response message.
const HANDSHAKE_RESPONSE_BYTES: usize = 42;
/// Largest application identifier in a handshake.
pub const MAX_APPLICATION_ID_BYTES: usize = 32;

const PROPOSE: u8 = 0xaa;
const ANSWER: u8 = 0xab;
const DATA: u8 = 0xbc;
const DATA_ACK: u8 = 0xbd;
const FAREWELL: u8 = 0xae;
const STATUS_QUERY: u8 = 0xbe;
const STATUS_REPLY: u8 = 0xbf;

/// Parameter set chosen for a session, matching the Sony driver's
/// `FalpSpeed` registry value. Larger values receive more blocks per burst
/// and wait less between frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// `FalpSpeed` 0: 16 blocks per burst, 40 ms turnaround and frame
    /// interval, 10 ms between blocks.
    Speed0,
    /// `FalpSpeed` 1, the driver default: 256 blocks per burst, 20 ms
    /// turnaround and frame interval.
    Speed1,
    /// `FalpSpeed` 2: 512 blocks per burst, 3 ms turnaround, 5 ms frame
    /// interval and no frame processing allowance.
    Speed2,
}

/// Farewell reason code. Peers may send codes this crate does not name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reason(pub u16);

impl Reason {
    /// Orderly end of the session.
    pub const NORMAL: Self = Self(0);
    /// Malformed message, length outside the block limits, or undefined type.
    pub const FORMAT: Self = Self(0x100);
    /// Block number outside the receive window, or a resend request for a
    /// block that was not sent.
    pub const WINDOW: Self = Self(0x101);
    /// Short handshake or a parameter outside its accepted range.
    pub const PARAMETER: Self = Self(0x102);
    /// Defined message type that the current state does not accept.
    pub const UNEXPECTED: Self = Self(0x103);
    /// More than three blocks and more than 3 % of a burst were missing.
    pub const LOSS: Self = Self(0x104);
    /// The application identifier is not accepted.
    pub const APPLICATION: Self = Self(0x105);
    /// Local processing failed.
    pub const INTERNAL: Self = Self(0x1ff);
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FALP reason {:04X}", self.0)
    }
}

/// RF bit rate in bit/s of the FeliCa rates (13.56 MHz / 64 and / 32).
pub(crate) const RF_212: u32 = 211_875;
pub(crate) const RF_424: u32 = 423_750;

/// Parameters exchanged in the handshake. Times are microseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Parameters {
    /// Blocks the sender of these parameters receives in one burst.
    pub(crate) blocks: u16,
    /// Largest block message, including its three-byte header.
    pub(crate) block_bytes: u16,
    pub(crate) frame_processing: u32,
    pub(crate) rf_overhead: u8,
    pub(crate) rf_bit_rate: u32,
    pub(crate) host_send_overhead: u8,
    pub(crate) host_send_bits: u8,
    pub(crate) host_bit_rate: u32,
    /// Time until the sender of these parameters takes the next block.
    pub(crate) block_turnaround: u32,
    /// Sent by the Sony driver but never read by it.
    pub(crate) reserved: u32,
    pub(crate) frame_interval: u32,
    pub(crate) receive_margin: u32,
    pub(crate) direction_switch: u32,
}

/// Local parameters, including values that never leave this device.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LocalParameters {
    pub(crate) wire: Parameters,
    pub(crate) host_receive_bits: u8,
    pub(crate) host_receive_overhead: u8,
    /// Added before every block after the first of a burst.
    pub(crate) inter_block_delay: Duration,
}

impl LocalParameters {
    /// Profile values with the reader's RF rate and processing allowance.
    pub(crate) fn new(profile: Profile, rf_bit_rate: u32, processing_allowance: u32) -> Self {
        let (blocks, processing, turnaround, interval, delay) = match profile {
            Profile::Speed0 => (16, 3500, 40_000, 40_000, 10),
            Profile::Speed1 => (256, 3500, 20_000, 20_000, 0),
            Profile::Speed2 => (512, 0, 3000, 5000, 0),
        };
        Self {
            wire: Parameters {
                blocks,
                block_bytes: 0xf9,
                frame_processing: u32::saturating_add(processing, processing_allowance),
                rf_overhead: 11,
                rf_bit_rate,
                host_send_overhead: 14,
                host_send_bits: 8,
                host_bit_rate: 230_400,
                block_turnaround: turnaround,
                reserved: 100_000,
                frame_interval: interval,
                receive_margin: 100_000,
                direction_switch: 200_000,
            },
            host_receive_bits: 8,
            host_receive_overhead: 15,
            inter_block_delay: Duration::from_millis(delay),
        }
    }
}

/// Fields in handshake order; the response omits the RF fields.
#[derive(Clone, Copy)]
enum Field {
    Blocks,
    BlockBytes,
    FrameProcessing,
    RfOverhead,
    RfBitRate,
    HostSendOverhead,
    HostSendBits,
    HostBitRate,
    BlockTurnaround,
    Reserved,
    FrameInterval,
    ReceiveMargin,
    DirectionSwitch,
}

const HANDSHAKE_FIELDS: [Field; 13] = [
    Field::Blocks,
    Field::BlockBytes,
    Field::FrameProcessing,
    Field::RfOverhead,
    Field::RfBitRate,
    Field::HostSendOverhead,
    Field::HostSendBits,
    Field::HostBitRate,
    Field::BlockTurnaround,
    Field::Reserved,
    Field::FrameInterval,
    Field::ReceiveMargin,
    Field::DirectionSwitch,
];

const RESPONSE_FIELDS: [Field; 11] = [
    Field::Blocks,
    Field::BlockBytes,
    Field::FrameProcessing,
    Field::HostSendOverhead,
    Field::HostSendBits,
    Field::HostBitRate,
    Field::BlockTurnaround,
    Field::Reserved,
    Field::FrameInterval,
    Field::ReceiveMargin,
    Field::DirectionSwitch,
];

impl Field {
    fn width(self) -> usize {
        match self {
            Self::Blocks | Self::BlockBytes => 2,
            Self::RfOverhead | Self::HostSendOverhead | Self::HostSendBits => 1,
            _ => 4,
        }
    }

    fn get(self, p: &Parameters) -> u32 {
        match self {
            Self::Blocks => p.blocks.into(),
            Self::BlockBytes => p.block_bytes.into(),
            Self::FrameProcessing => p.frame_processing,
            Self::RfOverhead => p.rf_overhead.into(),
            Self::RfBitRate => p.rf_bit_rate,
            Self::HostSendOverhead => p.host_send_overhead.into(),
            Self::HostSendBits => p.host_send_bits.into(),
            Self::HostBitRate => p.host_bit_rate,
            Self::BlockTurnaround => p.block_turnaround,
            Self::Reserved => p.reserved,
            Self::FrameInterval => p.frame_interval,
            Self::ReceiveMargin => p.receive_margin,
            Self::DirectionSwitch => p.direction_switch,
        }
    }

    /// Store a decoded value; `value` never exceeds the field width.
    fn set(self, p: &mut Parameters, value: u32) {
        let narrow16 = u16::try_from(value).unwrap_or(u16::MAX);
        let narrow8 = u8::try_from(value).unwrap_or(u8::MAX);
        match self {
            Self::Blocks => p.blocks = narrow16,
            Self::BlockBytes => p.block_bytes = narrow16,
            Self::FrameProcessing => p.frame_processing = value,
            Self::RfOverhead => p.rf_overhead = narrow8,
            Self::RfBitRate => p.rf_bit_rate = value,
            Self::HostSendOverhead => p.host_send_overhead = narrow8,
            Self::HostSendBits => p.host_send_bits = narrow8,
            Self::HostBitRate => p.host_bit_rate = value,
            Self::BlockTurnaround => p.block_turnaround = value,
            Self::Reserved => p.reserved = value,
            Self::FrameInterval => p.frame_interval = value,
            Self::ReceiveMargin => p.receive_margin = value,
            Self::DirectionSwitch => p.direction_switch = value,
        }
    }
}

fn encode_fields(out: &mut Vec<u8>, p: &Parameters, fields: &[Field]) {
    for field in fields {
        let bytes = field.get(p).to_be_bytes();
        out.extend_from_slice(&bytes[4 - field.width()..]);
    }
    out.extend_from_slice(&[0; 5]);
}

fn decode_fields(input: &[u8], base: Parameters, fields: &[Field]) -> Parameters {
    let mut p = base;
    let mut at = 0;
    for field in fields {
        let value = input[at..at + field.width()]
            .iter()
            .fold(0u32, |v, b| (v << 8) | u32::from(*b));
        field.set(&mut p, value);
        at += field.width();
    }
    p
}

/// Check received parameters and clamp an oversized block length.
fn validate(mut p: Parameters, rf_required: bool) -> Result<Parameters, Reason> {
    if p.blocks == 0 || p.blocks > 0x8000 || p.block_bytes < 0x80 {
        return Err(Reason::PARAMETER);
    }
    p.block_bytes = p.block_bytes.min(0xf9);
    if p.frame_interval > 1_000_000 || p.host_bit_rate == 0 || (rf_required && p.rf_bit_rate == 0) {
        return Err(Reason::PARAMETER);
    }
    Ok(p)
}

/// Message type, the first byte of a block message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Handshake,
    HandshakeResponse,
    Data,
    /// Last block of a burst; the sender can receive a full burst.
    Switch,
    /// Last block of a burst; the sender's receive space is short.
    SwitchBusy,
    ResendRequest,
    Resend,
    Farewell,
}

impl Kind {
    fn code(self) -> u8 {
        match self {
            Self::Handshake => 0,
            Self::HandshakeResponse => 1,
            Self::Data => 2,
            Self::Switch => 3,
            Self::SwitchBusy => 4,
            Self::ResendRequest => 5,
            Self::Resend => 6,
            Self::Farewell => 7,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Handshake,
            1 => Self::HandshakeResponse,
            2 => Self::Data,
            3 => Self::Switch,
            4 => Self::SwitchBusy,
            5 => Self::ResendRequest,
            6 => Self::Resend,
            7 => Self::Farewell,
            _ => return None,
        })
    }
}

/// A validated block message borrowed from its packet.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Message<'a> {
    pub(crate) kind: Kind,
    pub(crate) number: u16,
    pub(crate) bytes: &'a [u8],
}

impl<'a> Message<'a> {
    /// Parse a message no longer than `limit` bytes.
    pub(crate) fn parse(bytes: &'a [u8], limit: u16) -> Result<Self, Reason> {
        if bytes.len() < MESSAGE_HEADER || bytes.len() > usize::from(limit) {
            return Err(Reason::FORMAT);
        }
        let kind = Kind::from_code(bytes[0]).ok_or(Reason::FORMAT)?;
        Ok(Self {
            kind,
            number: u16::from_be_bytes([bytes[1], bytes[2]]),
            bytes,
        })
    }

    pub(crate) fn body(&self) -> &'a [u8] {
        &self.bytes[MESSAGE_HEADER..]
    }
}

pub(crate) fn message(kind: Kind, number: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MESSAGE_HEADER + body.len());
    out.push(kind.code());
    out.extend_from_slice(&number.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Handshake message carrying the initiator's identifier and parameters.
pub(crate) fn handshake(application: &[u8], p: &Parameters) -> Vec<u8> {
    let mut out = message(Kind::Handshake, 0, &[]);
    // The caller bounds the identifier by MAX_APPLICATION_ID_BYTES.
    out.push(u8::try_from(application.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(application);
    encode_fields(&mut out, p, &HANDSHAKE_FIELDS);
    out
}

/// Received handshake: identifier and validated initiator parameters.
#[derive(Debug)]
pub(crate) struct Handshake<'a> {
    pub(crate) application: &'a [u8],
    pub(crate) parameters: Parameters,
}

pub(crate) fn parse_handshake<'a>(
    m: &Message<'a>,
    base: Parameters,
) -> Result<Handshake<'a>, Reason> {
    let bytes = m.bytes;
    if bytes.len() < HANDSHAKE_MINIMUM {
        return Err(Reason::PARAMETER);
    }
    let length = usize::from(bytes[MESSAGE_HEADER]);
    if length > MAX_APPLICATION_ID_BYTES || bytes.len() < HANDSHAKE_MINIMUM + length {
        return Err(Reason::PARAMETER);
    }
    let fields = MESSAGE_HEADER + 1 + length;
    let parameters = validate(
        decode_fields(&bytes[fields..], base, &HANDSHAKE_FIELDS),
        true,
    )?;
    Ok(Handshake {
        application: &bytes[MESSAGE_HEADER + 1..fields],
        parameters,
    })
}

pub(crate) fn handshake_response(p: &Parameters) -> Vec<u8> {
    let mut out = message(Kind::HandshakeResponse, 0, &[]);
    encode_fields(&mut out, p, &RESPONSE_FIELDS);
    out
}

/// Parse the target's parameters. RF fields keep the initiator's values,
/// which the target adopted.
pub(crate) fn parse_handshake_response(
    m: &Message<'_>,
    base: Parameters,
) -> Result<Parameters, Reason> {
    if m.bytes.len() < HANDSHAKE_RESPONSE_BYTES {
        return Err(Reason::PARAMETER);
    }
    validate(
        decode_fields(&m.bytes[MESSAGE_HEADER..], base, &RESPONSE_FIELDS),
        false,
    )
}

pub(crate) fn farewell(reason: Reason) -> Vec<u8> {
    message(Kind::Farewell, 0, &reason.0.to_be_bytes())
}

/// One FALP packet body, after its FeliCa length byte.
#[derive(Debug)]
pub(crate) enum Pdu<'a> {
    Propose {
        idm: Idm,
        port: u16,
    },
    Accepted {
        port: u16,
    },
    Rejected {
        status: u8,
        reason: u8,
    },
    Data {
        acknowledge: bool,
        message: &'a [u8],
    },
    Farewell {
        message: &'a [u8],
    },
    StatusQuery {
        idm: Idm,
    },
    /// Other or malformed packets, ignored by receivers.
    Other,
}

impl<'a> Pdu<'a> {
    /// Parse a FeliCa packet whose length byte the caller validated.
    pub(crate) fn parse(packet: &'a [u8]) -> Self {
        let pdu = packet.get(1..).unwrap_or_default();
        match pdu {
            [PROPOSE, ..] if pdu.len() >= 15 => {
                let mut idm = [0; 8];
                idm.copy_from_slice(&pdu[1..9]);
                Self::Propose {
                    idm: Idm::new(idm),
                    port: u16::from_le_bytes([pdu[9], pdu[10]]),
                }
            }
            [ANSWER, ..] if pdu.len() >= 11 && pdu[9] != 0 => Self::Rejected {
                status: pdu[9],
                reason: pdu[10],
            },
            [ANSWER, ..] if pdu.len() >= 14 => Self::Accepted {
                port: u16::from_le_bytes([pdu[12], pdu[13]]),
            },
            [kind @ (DATA | FAREWELL), _, _, flag, length, message @ ..]
                if usize::from(*length) == message.len() =>
            {
                if *kind == DATA {
                    Self::Data {
                        acknowledge: *flag == 0,
                        message,
                    }
                } else {
                    Self::Farewell { message }
                }
            }
            [STATUS_QUERY, ..] if pdu.len() == 10 => {
                let mut idm = [0; 8];
                idm.copy_from_slice(&pdu[1..9]);
                Self::StatusQuery { idm: Idm::new(idm) }
            }
            _ => Self::Other,
        }
    }
}

/// Wrap a packet body with its FeliCa length byte.
fn packet(pdu: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(pdu.len() + 1);
    // Bodies are bounded by the 249-byte message limit plus their envelope.
    out.push(u8::try_from(pdu.len() + 1).unwrap_or(u8::MAX));
    out.extend(pdu);
    out
}

pub(crate) fn propose_packet(idm: Idm, port: u16, timeout: Duration) -> Vec<u8> {
    let millis = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let field = u16::try_from(millis.saturating_add(100).min(0x7fff)).unwrap_or(0x7fff);
    let mut pdu = vec![PROPOSE];
    pdu.extend_from_slice(idm.as_bytes());
    pdu.extend_from_slice(&port.to_le_bytes());
    pdu.extend_from_slice(&field.to_le_bytes());
    pdu.extend_from_slice(&[0, 0]);
    packet(pdu)
}

pub(crate) fn accept_packet(idm: Idm, port: u16) -> Vec<u8> {
    let mut pdu = vec![ANSWER];
    pdu.extend_from_slice(idm.as_bytes());
    pdu.extend_from_slice(&[0, 0, 1]);
    pdu.extend_from_slice(&port.to_le_bytes());
    packet(pdu)
}

pub(crate) fn reject_packet(idm: Idm) -> Vec<u8> {
    let mut pdu = vec![ANSWER];
    pdu.extend_from_slice(idm.as_bytes());
    pdu.extend_from_slice(&[0xff, 0xf0]);
    packet(pdu)
}

/// `BC` packet sent without requesting a `BD` acknowledgement.
pub(crate) fn data_packet(port: u16, message: &[u8]) -> Vec<u8> {
    envelope(DATA, port, 1, message)
}

pub(crate) fn farewell_packet(port: u16, message: &[u8]) -> Vec<u8> {
    envelope(FAREWELL, port, 0, message)
}

fn envelope(kind: u8, port: u16, flag: u8, message: &[u8]) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(ENVELOPE_HEADER + message.len());
    pdu.push(kind);
    pdu.extend_from_slice(&port.to_le_bytes());
    pdu.push(flag);
    // Messages are bounded by the 249-byte block limit.
    pdu.push(u8::try_from(message.len()).unwrap_or(u8::MAX));
    pdu.extend_from_slice(message);
    packet(pdu)
}

pub(crate) fn data_ack_packet() -> Vec<u8> {
    packet(vec![DATA_ACK, 0, 0, 0])
}

pub(crate) fn status_reply_packet(idm: Idm, in_session: bool, port: u16) -> Vec<u8> {
    let mut pdu = vec![STATUS_REPLY];
    pdu.extend_from_slice(idm.as_bytes());
    pdu.extend_from_slice(&[0, 0, u8::from(in_session)]);
    pdu.extend_from_slice(&port.to_le_bytes());
    packet(pdu)
}

/// Frame length of a message in its `BC` envelope.
pub(crate) fn frame_bytes(message: usize) -> u32 {
    u32::try_from(message + ENVELOPE_HEADER).unwrap_or(u32::MAX)
}

fn ceil_div(numerator: u64, denominator: u32) -> u32 {
    let denominator = u64::from(denominator.max(1));
    u32::try_from(numerator.div_ceil(denominator)).unwrap_or(u32::MAX)
}

/// RF transfer time of a frame: own fixed bytes at the peer's rate.
fn rf_time(frame: u32, local: &LocalParameters, peer: &Parameters) -> u32 {
    ceil_div(
        8_000_000 * (u64::from(frame) + u64::from(local.wire.rf_overhead)),
        peer.rf_bit_rate,
    )
}

/// Host transfer time of a frame toward the reader by `p`'s side.
fn host_send(frame: u32, p: &Parameters) -> u32 {
    ceil_div(
        1_000_000
            * u64::from(p.host_send_bits)
            * (u64::from(frame) + u64::from(p.host_send_overhead)),
        p.host_bit_rate,
    )
}

fn host_receive(frame: u32, local: &LocalParameters) -> u32 {
    ceil_div(
        1_000_000
            * u64::from(local.host_receive_bits)
            * (u64::from(frame) + u64::from(local.host_receive_overhead)),
        local.wire.host_bit_rate,
    )
}

fn millis(micros: u32) -> Duration {
    Duration::from_millis(u64::from(micros).div_ceil(1000))
}

/// Wait before the next block of a burst (`IVa`), from the lengths of the
/// block just sent and the next one.
pub(crate) fn block_interval(
    sent: u32,
    next: u32,
    local: &LocalParameters,
    peer: &Parameters,
) -> Duration {
    let ready = u64::from(peer.block_turnaround)
        + u64::from(host_send(sent, peer))
        + u64::from(peer.frame_processing)
        + u64::from(rf_time(sent, local, peer));
    let wait = ready.saturating_sub(u64::from(host_receive(next, local)));
    millis(u32::try_from(wait).unwrap_or(u32::MAX))
}

/// Wait before starting to send (`IVb`), from the length of the frame last
/// received and the frame about to be sent. `switching` applies when both
/// this burst and the peer's last burst carry no data.
pub(crate) fn send_wait(
    received: u32,
    next: u32,
    local: &LocalParameters,
    peer: &Parameters,
    switching: bool,
) -> Duration {
    if peer.rf_bit_rate == 0 || peer.frame_interval > 1_000_000 {
        return Duration::ZERO;
    }
    let spent = u64::from(rf_time(received, local, peer))
        + u64::from(host_send(received, &local.wire))
        + u64::from(host_receive(next, local));
    let interval = u64::from(peer.frame_interval);
    if switching && interval <= spent + u64::from(local.wire.direction_switch) {
        return millis(local.wire.direction_switch);
    }
    millis(u32::try_from(interval.saturating_sub(spent)).unwrap_or(u32::MAX))
}

/// Wait for the peer's next frame (`TOb` without the Sony driver's random
/// extension). `switching` applies after a burst without data.
pub(crate) fn receive_timeout(
    local: &LocalParameters,
    peer: &Parameters,
    switching: bool,
) -> Duration {
    let own = frame_bytes(usize::from(local.wire.block_bytes));
    let theirs = frame_bytes(usize::from(peer.block_bytes));
    let mut total = u64::from(peer.receive_margin)
        + u64::from(host_send(own, &local.wire))
        + u64::from(rf_time(own, local, peer))
        + u64::from(rf_time(theirs, local, peer))
        + 2 * u64::from(local.wire.frame_processing)
        + u64::from(host_send(theirs, peer))
        + 2 * u64::from(peer.frame_processing);
    if switching {
        total += u64::from(peer.direction_switch);
    }
    let floor = (3 * u64::from(local.wire.frame_interval)).div_ceil(2);
    millis(u32::try_from(total.max(floor)).unwrap_or(u32::MAX))
}

/// Blocks received in the peer's current burst, keyed by offset from the
/// next expected block number.
#[derive(Debug)]
pub(crate) struct ReceiveWindow {
    base: u16,
    size: u16,
    blocks: BTreeMap<u16, Vec<u8>>,
}

/// Completeness of the received burst.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Gaps {
    Complete,
    /// Missing blocks remain; request the first one.
    Missing {
        first: u16,
    },
    /// Losses exceed the accepted limit.
    Excessive,
}

impl ReceiveWindow {
    pub(crate) fn new(size: u16) -> Self {
        Self {
            base: 0,
            size,
            blocks: BTreeMap::new(),
        }
    }

    pub(crate) fn contains(&self, number: u16) -> bool {
        number.wrapping_sub(self.base) < self.size
    }

    /// Store a message; a repeated number replaces the earlier copy.
    pub(crate) fn store(&mut self, message: &Message<'_>) -> Result<(), Reason> {
        if !self.contains(message.number) {
            return Err(Reason::WINDOW);
        }
        self.blocks.insert(
            message.number.wrapping_sub(self.base),
            message.bytes.to_vec(),
        );
        Ok(())
    }

    pub(crate) fn gaps(&self) -> Gaps {
        let Some(last) = self.blocks.keys().next_back() else {
            return Gaps::Complete;
        };
        let span = usize::from(*last) + 1;
        let missing = span - self.blocks.len();
        if missing == 0 {
            return Gaps::Complete;
        }
        if missing > 3 && 100 * missing / span > 3 {
            return Gaps::Excessive;
        }
        let first = (0..=*last)
            .find(|offset| !self.blocks.contains_key(offset))
            .unwrap_or(0);
        Gaps::Missing {
            first: self.base.wrapping_add(first),
        }
    }

    /// Deliver the complete burst's data in order and open the next window.
    pub(crate) fn take(&mut self) -> Vec<u8> {
        let count = u16::try_from(self.blocks.len()).unwrap_or(u16::MAX);
        let mut data = Vec::new();
        for block in core::mem::take(&mut self.blocks).into_values() {
            data.extend_from_slice(&block[MESSAGE_HEADER..]);
        }
        self.base = self.base.wrapping_add(count);
        data
    }

    /// Data of the contiguous prefix received so far.
    pub(crate) fn prefix(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for (expected, (offset, block)) in self.blocks.iter().enumerate() {
            if usize::from(*offset) != expected {
                break;
            }
            data.extend_from_slice(&block[MESSAGE_HEADER..]);
        }
        data
    }
}

/// Messages of this side's current burst, kept until the peer's next burst
/// acknowledges them.
#[derive(Debug, Default)]
pub(crate) struct SendWindow {
    base: u16,
    blocks: Vec<Vec<u8>>,
}

/// One burst: its messages and the data bytes it carries.
#[derive(Debug)]
pub(crate) struct Burst {
    pub(crate) carried: usize,
    /// The burst consists of one switch without data.
    pub(crate) empty: bool,
}

impl SendWindow {
    /// Build the next burst from `data` for a peer with `peer` parameters.
    /// `send_data` is false while the peer reported short receive space.
    pub(crate) fn build(&mut self, data: &[u8], peer: &Parameters, send_data: bool) -> Burst {
        self.blocks.clear();
        let chunk = usize::from(peer.block_bytes) - MESSAGE_HEADER;
        let data = if send_data { data } else { &[] };
        let pieces: Vec<&[u8]> = data.chunks(chunk).take(usize::from(peer.blocks)).collect();
        if pieces.is_empty() {
            self.blocks.push(message(Kind::Switch, self.base, &[]));
            return Burst {
                carried: 0,
                empty: true,
            };
        }
        let last = pieces.len() - 1;
        let mut carried = 0;
        for (index, piece) in pieces.into_iter().enumerate() {
            let kind = if index == last {
                Kind::Switch
            } else {
                Kind::Data
            };
            let offset = u16::try_from(index).unwrap_or(u16::MAX);
            self.blocks
                .push(message(kind, self.base.wrapping_add(offset), piece));
            carried += piece.len();
        }
        Burst {
            carried,
            empty: false,
        }
    }

    pub(crate) fn messages(&self) -> &[Vec<u8>] {
        &self.blocks
    }

    /// The block with `number` as a resend message.
    pub(crate) fn resend(&self, number: u16) -> Option<Vec<u8>> {
        let index = usize::from(number.wrapping_sub(self.base));
        self.blocks.get(index).map(|block| {
            let mut copy = block.clone();
            copy[0] = Kind::Resend.code();
            copy
        })
    }

    /// The peer started its burst; every block of this burst was received.
    pub(crate) fn acknowledge(&mut self) {
        let count = u16::try_from(self.blocks.len()).unwrap_or(u16::MAX);
        self.base = self.base.wrapping_add(count);
        self.blocks.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(profile: Profile) -> LocalParameters {
        LocalParameters::new(profile, RF_424, 0)
    }

    #[test]
    fn handshake_round_trips_and_matches_the_driver_layout() -> Result<(), Reason> {
        let p = local(Profile::Speed1).wire;
        let bytes = handshake(b"APP", &p);
        assert_eq!(bytes.len(), HANDSHAKE_MINIMUM + 3);
        // Type, number, identifier, then 08 0A 18 32 0C ...
        assert_eq!(
            &bytes[..12],
            &[0, 0, 0, 3, b'A', b'P', b'P', 1, 0, 0, 0xf9, 0]
        );
        assert_eq!(&bytes[12..20], &[0, 0x0d, 0xac, 11, 0, 6, 0x77, 0x46]);
        let received = Message::parse(&bytes, 0xf9)?;
        let parsed = parse_handshake(&received, local(Profile::Speed0).wire)?;
        assert_eq!(parsed.application, b"APP");
        assert_eq!(parsed.parameters, p);
        Ok(())
    }

    #[test]
    fn handshake_response_omits_rf_fields() -> Result<(), Reason> {
        let target = local(Profile::Speed2).wire;
        let bytes = handshake_response(&target);
        assert_eq!(bytes.len(), HANDSHAKE_RESPONSE_BYTES);
        let mut base = local(Profile::Speed1).wire;
        base.rf_bit_rate = RF_212;
        let parsed = parse_handshake_response(&Message::parse(&bytes, 0xf9)?, base)?;
        assert_eq!(parsed.blocks, 512);
        assert_eq!(parsed.rf_bit_rate, RF_212);
        Ok(())
    }

    #[test]
    fn parameter_limits_follow_the_receiver_checks() {
        let base = local(Profile::Speed1).wire;
        for (field, value) in [(0usize, 0u32), (0, 0x8001), (1, 0x7f)] {
            let mut p = base;
            HANDSHAKE_FIELDS[field].set(&mut p, value);
            assert_eq!(validate(p, true), Err(Reason::PARAMETER));
        }
        let mut p = base;
        p.block_bytes = 0x100;
        assert!(matches!(validate(p, true), Ok(v) if v.block_bytes == 0xf9));
        p.frame_interval = 1_000_001;
        assert_eq!(validate(p, true), Err(Reason::PARAMETER));
    }

    #[test]
    fn packets_carry_their_length_and_little_endian_ports() {
        let idm = Idm::new([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            propose_packet(idm, 0x1234, Duration::from_millis(0x8000)),
            [
                16, 0xaa, 1, 2, 3, 4, 5, 6, 7, 8, 0x34, 0x12, 0xff, 0x7f, 0, 0
            ]
        );
        assert!(matches!(
            Pdu::parse(&accept_packet(idm, 0x1234)),
            Pdu::Accepted { port: 0x1234 }
        ));
        assert!(matches!(
            Pdu::parse(&reject_packet(idm)),
            Pdu::Rejected {
                status: 0xff,
                reason: 0xf0
            }
        ));
        assert_eq!(
            data_packet(0x1234, &[2, 0, 1]),
            [9, 0xbc, 0x34, 0x12, 1, 3, 2, 0, 1]
        );
        assert!(matches!(
            Pdu::parse(&[9, 0xbc, 0, 0, 0, 3, 2, 0, 1]),
            Pdu::Data {
                acknowledge: true,
                message: [2, 0, 1]
            }
        ));
        assert!(matches!(
            Pdu::parse(&[9, 0xbc, 0, 0, 0, 4, 2, 0, 1]),
            Pdu::Other
        ));
        assert_eq!(
            farewell_packet(7, &farewell(Reason::LOSS)),
            [11, 0xae, 7, 0, 0, 5, 7, 0, 0, 1, 4]
        );
    }

    #[test]
    fn timing_vectors_follow_the_driver_formulas() {
        let a = local(Profile::Speed1);
        let peer = a.wire;
        // TOb: 100000 + H(254) + 2 RF(254) + 2*2*3500 + H(254), floor 30000.
        // H(254) = ceil(8e6 * 268 / 230400) = 9306; RF(254) = ceil(8e6*265/423750) = 5003.
        assert_eq!(
            receive_timeout(&a, &peer, false),
            Duration::from_millis(u64::from(
                (100_000u32 + 9306 * 2 + 5003 * 2 + 14_000).div_ceil(1000)
            ))
        );
        // IVb with the frame interval below the transfer time is zero.
        assert_eq!(send_wait(254, 254, &a, &peer, false), Duration::ZERO);
        assert_eq!(send_wait(8, 8, &a, &peer, true), Duration::from_millis(200));
        // IVa: 20000 + H(254) + 3500 + RF(254) - Hr(254); Hr = ceil(8e6*269/230400) = 9341.
        assert_eq!(
            block_interval(254, 254, &a, &peer),
            Duration::from_millis(u64::from(
                (20_000u32 + 9306 + 3500 + 5003 - 9341).div_ceil(1000)
            ))
        );
    }

    #[test]
    fn receive_window_reports_gaps_and_delivers_in_order() -> Result<(), Reason> {
        let mut window = ReceiveWindow::new(16);
        let blocks: Vec<Vec<u8>> = (0u16..5)
            .map(|n| message(Kind::Data, n, &[u8::try_from(n).unwrap_or(0)]))
            .collect();
        for n in [0, 1, 3, 4] {
            window.store(&Message::parse(&blocks[n], 0xf9)?)?;
        }
        assert_eq!(window.gaps(), Gaps::Missing { first: 2 });
        assert_eq!(window.prefix(), [0, 1]);
        window.store(&Message::parse(&blocks[2], 0xf9)?)?;
        assert_eq!(window.gaps(), Gaps::Complete);
        assert_eq!(window.take(), [0, 1, 2, 3, 4]);
        assert!(!window.contains(4));
        assert!(window.contains(5));
        assert!(
            window
                .store(&Message::parse(&message(Kind::Data, 30, &[]), 0xf9)?)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn excessive_loss_needs_more_than_three_blocks_and_three_percent() -> Result<(), Reason> {
        let mut window = ReceiveWindow::new(512);
        let last = message(Kind::Switch, 199, &[]);
        window.store(&Message::parse(&last, 0xf9)?)?;
        assert_eq!(window.gaps(), Gaps::Excessive);
        // Four of 100 blocks (4 %) are excessive; four of 200 (2 %) and
        // three of 100 are requested again.
        for (missing, span, expected) in [
            (4u16, 100u16, Gaps::Excessive),
            (4, 200, Gaps::Missing { first: 0 }),
            (3, 100, Gaps::Missing { first: 0 }),
        ] {
            let mut window = ReceiveWindow::new(512);
            for n in missing..span {
                window.store(&Message::parse(&message(Kind::Data, n, &[]), 0xf9)?)?;
            }
            assert_eq!(window.gaps(), expected);
        }
        Ok(())
    }

    #[test]
    fn bursts_split_by_the_peer_limits_and_resend_as_type_six() {
        let mut peer = local(Profile::Speed0).wire;
        peer.block_bytes = 0x80;
        peer.blocks = 2;
        let mut window = SendWindow::default();
        let data = vec![7; 300];
        let burst = window.build(&data, &peer, true);
        assert_eq!(burst.carried, 250);
        assert_eq!(window.messages().len(), 2);
        assert_eq!(window.messages()[0][..3], [2, 0, 0]);
        assert_eq!(window.messages()[1][..3], [3, 0, 1]);
        assert_eq!(window.resend(1).map(|m| m[0]), Some(6));
        assert_eq!(window.resend(2), None);
        window.acknowledge();
        let burst = window.build(&data, &peer, false);
        assert!(burst.empty);
        assert_eq!(window.messages(), [vec![3, 0, 2]]);
    }
}
