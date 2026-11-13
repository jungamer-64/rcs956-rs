//! Reader configuration and lifetime-bound NFC card access.

mod dep;
mod falp;
mod identity;
mod type1;
mod type2_target;

pub use dep::{
    DepActivation, DepError, DepInitiator, DepLink, DepMessage, DepMode, DepPeer, DepRate,
    DepRequest, DepTransferCause, MAX_DEP_MESSAGE_BYTES, PassiveDepTarget,
};
pub use falp::{
    FalpAccepted, FalpConnect, FalpError, FalpLink, FalpListen, FalpTurn, TransferCause,
};
pub use identity::{DeviceNameError, Model, Product};
pub use type1::Type1Tag;
pub use type2_target::{
    MAX_TYPE2_EMULATED_NDEF_BYTES, Type2EmulationError, Type2Event, Type2Target,
};

use crate::{
    felica::{
        self, BitRate, BlockWrite, CardError, PollRequest, PollResponse, ReadResponse, ServiceEntry,
    },
    isodep, nfca, nfcb,
    transport::{Failure, Link, Progress, TransactionError, Transport},
};
use alloc::{string::String, vec, vec::Vec};
use core::{error, fmt, mem, num::NonZeroU8, time::Duration};

/// Maximum card-command bytes accepted by the reader's NFC-A exchange.
pub const MAX_TYPE_A_COMMAND_BYTES: usize = 262;
/// Maximum card-command bytes accepted by the reader's NFC-B `40` exchange.
pub const MAX_TYPE_B_FRAME_COMMAND_BYTES: usize = 63;
const MAX_TYPE_A_RESPONSE_FRAGMENTS: usize = 256;
/// `40` reader status bit announcing a further response fragment.
const TARGET_MORE_INFORMATION: u8 = 0x40;

/// Failures of reader initialization, RF configuration, or card exchange.
#[derive(Debug)]
pub enum Error<E> {
    /// Host transport transaction failed. Unless its progress is
    /// [`Progress::NotSent`] and the stream was usable, the reader must be
    /// reinitialized.
    Transaction(TransactionError<E>),
    /// Recovery failed, preserving the phase of its out-of-band ACK transfer.
    Recovery(TransactionError<E>),
    /// Reader initialization is required before the requested operation.
    NotInitialized,
    /// A command response did not have the required layout.
    Response(&'static str),
    /// The configuration image failed validation.
    Configuration(ConfigurationError),
    /// Register write returned an error value.
    RegisterStatus(u8),
    /// Raw RF status and its command-specific classification. A masked `0D`
    /// requires reader initialization; a masked `0B` is returned only after a
    /// 10 ms settle wait.
    RfStatus(u8),
    /// FeliCa request validation failed before the command was sent.
    FelicaRequest(CardError),
    /// The FeliCa command was sent but the card reply reported an error or
    /// failed validation. The command may have taken effect.
    FelicaResponse(CardError),
    /// The requested RF wait cannot be encoded as nonzero half-ms ticks.
    Timeout(TimeoutRange),
    /// NFC-A activation data failed validation.
    TypeA(nfca::Error),
    /// NFC-B activation data failed validation.
    TypeB(nfcb::Error),
    /// Activated NFC-B parameters cannot construct a supported ISO-DEP session.
    IsoDepParameters(isodep::ParameterError),
    /// Payload exceeds the selected reader command's supported limit.
    InputLength {
        /// Maximum accepted bytes.
        maximum: usize,
        /// Supplied bytes.
        actual: usize,
    },
}
impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transaction(_) => f.write_str("reader transaction failed"),
            Self::Recovery(_) => f.write_str("reader recovery failed"),
            Self::NotInitialized => f.write_str("reader requires initialization"),
            Self::Response(reason) => write!(f, "malformed reader response: {reason}"),
            Self::Configuration(_) => f.write_str("invalid reader configuration"),
            Self::RegisterStatus(status) => write!(f, "register write returned {status:02X}"),
            Self::RfStatus(status) => write!(f, "RF status {status:02X}"),
            Self::FelicaRequest(_) => f.write_str("FeliCa request rejected before sending"),
            Self::FelicaResponse(_) => {
                f.write_str("FeliCa response failed; the command may have taken effect")
            }
            Self::Timeout(_) => f.write_str("invalid RF wait"),
            Self::TypeA(_) => f.write_str("invalid NFC-A activation"),
            Self::TypeB(_) => f.write_str("invalid NFC-B activation"),
            Self::IsoDepParameters(_) => f.write_str("unsupported ISO-DEP parameters"),
            Self::InputLength { maximum, actual } => {
                write!(f, "input of {actual} bytes exceeds {maximum}")
            }
        }
    }
}
impl<E: error::Error + 'static> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Transaction(error) | Self::Recovery(error) => Some(error),
            Self::Configuration(error) => Some(error),
            Self::FelicaRequest(error) | Self::FelicaResponse(error) => Some(error),
            Self::Timeout(error) => Some(error),
            Self::TypeA(error) => Some(error),
            Self::TypeB(error) => Some(error),
            Self::IsoDepParameters(error) => Some(error),
            _ => None,
        }
    }
}
impl<E> From<TimeoutRange> for Error<E> {
    fn from(e: TimeoutRange) -> Self {
        Self::Timeout(e)
    }
}

/// The requested wait is zero or exceeds 65535 half-ms ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutRange;

impl fmt::Display for TimeoutRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RF wait must be positive and fit in 65535 half-ms ticks")
    }
}
impl error::Error for TimeoutRange {}

/// Positive RF timeout with a checked conversion to RC-S956 wire ticks.
#[derive(Debug, Clone, Copy)]
pub struct RfTimeout {
    ticks: u16,
}
impl RfTimeout {
    /// Round a positive duration up to half-ms ticks.
    ///
    /// # Errors
    ///
    /// Returns [`TimeoutRange`] for zero or a duration requiring more than 65535 ticks.
    pub fn new(duration: Duration) -> Result<Self, TimeoutRange> {
        let ticks = duration.as_nanos().div_ceil(500_000);
        if ticks == 0 {
            return Err(TimeoutRange);
        }
        Ok(Self {
            ticks: u16::try_from(ticks).map_err(|_| TimeoutRange)?,
        })
    }
    /// Encoded little-endian device timeout.
    pub fn ticks(self) -> u16 {
        self.ticks
    }
    fn host_wait(self) -> Duration {
        Duration::from_micros(u64::from(self.ticks) * 500) + Duration::from_secs(1)
    }
}

/// Invalid reader configuration image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationError {
    /// The configuration signature was absent.
    Signature,
    /// A checksummed region did not sum to zero.
    Checksum {
        /// Byte offset where the failing region begins.
        offset: usize,
    },
    /// The image's model class is unsupported.
    ModelClass,
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature => f.write_str("configuration signature is absent"),
            Self::Checksum { offset } => {
                write!(f, "configuration checksum fails at offset {offset:02X}")
            }
            Self::ModelClass => f.write_str("unsupported configuration model class"),
        }
    }
}
impl error::Error for ConfigurationError {}

/// Immutable, validated configuration read from one attached reader.
#[derive(Debug, Clone)]
pub struct ConfigImage {
    bytes: [u8; 256],
    model: Model,
}
impl ConfigImage {
    /// Check the signature, three defined checksum ranges, and model class.
    /// Bytes C0..FF are not covered by those checksums.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if the image fails validation.
    pub fn parse(bytes: [u8; 256]) -> Result<Self, ConfigurationError> {
        if bytes[..2] != [0x55, 0xaa] {
            return Err(ConfigurationError::Signature);
        }
        for range in [0..16, 16..64, 64..192] {
            let offset = range.start;
            if bytes[range].iter().fold(0u8, |s, b| s.wrapping_add(*b)) != 0 {
                return Err(ConfigurationError::Checksum { offset });
            }
        }
        if !matches!(bytes[253], 1 | 2) {
            return Err(ConfigurationError::ModelClass);
        }
        let model = Model::new(u16::from_be_bytes([bytes[253], bytes[254]]));
        Ok(Self { bytes, model })
    }
    /// Model word from E[FD..FE].
    pub fn model(&self) -> Model {
        self.model
    }
    /// Device name stored in the image, if `E[03]` announces one.
    ///
    /// The name is outside the RF configuration; a malformed name does not
    /// invalidate the image.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceNameError`] if the announced name is malformed.
    pub fn device_name(&self) -> Result<Option<String>, DeviceNameError> {
        identity::device_name(&self.bytes)
    }
    /// Snapshot of the original 256 reader configuration bytes.
    pub fn bytes(&self) -> &[u8; 256] {
        &self.bytes
    }
    fn rf_configuration(&self, protocol: RfProtocol) -> Vec<Vec<u8>> {
        match protocol {
            RfProtocol::TypeA => {
                let mut item = vec![0x0a];
                item.extend_from_slice(&self.bytes[0x10..=0x1a]);
                vec![item]
            }
            RfProtocol::Felica => {
                let mut item = vec![0x0b];
                item.extend_from_slice(&self.bytes[0x1b..=0x22]);
                vec![item]
            }
            RfProtocol::TypeB(profile) => {
                let options = match profile {
                    nfcb::RfProfile::Standard => &self.bytes[0x23..=0x25],
                    nfcb::RfProfile::Alternate => &self.bytes[0xcf..=0xd1],
                };
                let mut analog = vec![
                    0x0a,
                    self.bytes[0xc0],
                    options[0],
                    self.bytes[0xc1],
                    options[1],
                    self.bytes[0xc2],
                    options[2],
                ];
                analog.extend_from_slice(&self.bytes[0x16..=0x1a]);
                vec![analog, vec![0x0c, options[0], options[1], options[2]]]
            }
        }
    }
}

/// Hardware observations obtained by a completed initialization.
#[derive(Debug, Clone)]
pub struct ReaderInfo {
    /// Raw firmware identification; not interpreted as another module's revision.
    pub firmware: [u8; 4],
    /// Raw byte from command 0C.
    pub flags: u8,
    /// Configuration read from this connection.
    pub configuration: ConfigImage,
}

/// Parameter of the reader's 1C timer, derived only from a validated RF wait.
/// This timer and the A0 half-ms field are different protocol representations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReaderTimer(u16);
impl ReaderTimer {
    fn for_rf_timeout(timeout: RfTimeout) -> Self {
        // The accepted tick range is 1..=65535, so this conversion yields
        // 1..=33 whole seconds and a parameter in 99..=3299.
        Self(timeout.ticks.div_ceil(2000) * 100 - 1)
    }

    fn args(self) -> [u8; 3] {
        let [lo, hi] = self.0.to_le_bytes();
        [0x80, lo, hi]
    }
}

/// The reader response selector is independent of each A0 block timeout.
/// Each variant fixes both a 32/02 selector and its effective milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum ResponseTimeout {
    Ms51 = 51,
    Ms102 = 102,
    Ms204 = 204,
    Ms409 = 409,
    Ms819 = 819,
    Ms1640 = 1640,
    Ms3280 = 3280,
}
impl ResponseTimeout {
    fn for_request(request: RfTimeout) -> Self {
        match request.ticks.div_ceil(2) {
            0..=51 => Self::Ms51,
            52..=102 => Self::Ms102,
            103..=204 => Self::Ms204,
            205..=409 => Self::Ms409,
            410..=819 => Self::Ms819,
            820..=1640 => Self::Ms1640,
            _ => Self::Ms3280,
        }
    }

    fn args(self) -> [u8; 4] {
        let code = match self {
            Self::Ms51 => 0x0a,
            Self::Ms102 => 0x0b,
            Self::Ms204 => 0x0c,
            Self::Ms409 => 0x0d,
            Self::Ms819 => 0x0e,
            Self::Ms1640 => 0x0f,
            Self::Ms3280 => 0x10,
        };
        [2, 0x0b, 0x0b, code]
    }

    fn wait(self) -> Duration {
        Duration::from_millis(u64::from(self as u16))
    }

    fn host_wait(self) -> Duration {
        self.wait() + Duration::from_secs(1)
    }
}

/// Firmware parameters written by command `12`. Bits 3 and 4 are fixed to
/// one; bit 4 makes firmware send RATS while activating an ISO-DEP NFC-A
/// card, so `4B` reports its ATS. Reset changes only the operating mode and
/// leaves these parameters as last written.
#[derive(Debug, Clone, Copy)]
struct Parameters {
    node_address: bool,
    automatic_atr_response: bool,
}
impl Parameters {
    const DEFAULT: Self = Self {
        node_address: false,
        automatic_atr_response: true,
    };

    fn byte(self) -> u8 {
        0x18 | u8::from(self.node_address) | (u8::from(self.automatic_atr_response) << 2)
    }
}

/// `06` arguments reading CIU_Status1 and CIU_Command.
const RECEIVER_PROBE: [u8; 4] = [0x63, 0x37, 0x63, 0x31];
/// CIU_Status1 bit set while the receiver is stalled so that
/// InListPassiveTarget cannot send its first request.
const RECEIVER_STALLED: u8 = 0x08;
const CIU_COMMAND: u16 = 0x6331;
const CIU_RECEIVE: u8 = 0x08;
const CIU_IDLE: u8 = 0x00;

/// Failure of an InListPassiveTarget activation, split at the `4A` request.
#[derive(Debug)]
enum ActivationError<E> {
    /// Receiver preparation failed; no RF request was sent.
    BeforeRequest(Error<E>),
    /// The `4A` transaction or its response failed.
    Request(Error<E>),
}
impl<E> From<ActivationError<E>> for Error<E> {
    fn from(error: ActivationError<E>) -> Self {
        match error {
            ActivationError::BeforeRequest(error) | ActivationError::Request(error) => error,
        }
    }
}

/// RF configuration and the timer are published only after all writes succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RfProtocol {
    TypeA,
    Felica,
    TypeB(nfcb::RfProfile),
}

#[derive(Debug, Clone, Copy)]
enum RfMode {
    Off,
    Configured {
        protocol: RfProtocol,
        timer: ReaderTimer,
        selection: RfSelection,
    },
    RawTypeA(RawTypeAResponse),
}

#[derive(Debug, Clone, Copy)]
enum RawTypeAResponse {
    Idle,
    Pending { frames: usize },
}

#[derive(Debug, Clone, Copy)]
enum RfSelection {
    Ordinary,
    Type2Sector(NonZeroU8),
    /// Firmware activated a target that this crate rejected without granting
    /// a handle. Such a card can ignore the next request, so the next
    /// selection cycles the RF field first.
    RejectedActivation,
    #[cfg(any(feature = "felica-lite-s", feature = "felica-standard-aes"))]
    FelicaAuthentication,
}

#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded configuration snapshot belongs to the reader state; inline storage avoids a separate session allocation"
)]
enum State {
    NeedsInitialization,
    Ready {
        info: ReaderInfo,
        rf: RfMode,
        // 32/02 is independent of RF protocol/timer configuration. Only a
        // completed write establishes it; reset or an uncertain failure revokes it.
        response_timeout: Option<ResponseTimeout>,
    },
}

/// Exclusive reader owner. Uncertain transport failures revoke RF readiness.
#[derive(Debug)]
pub struct Reader<T: Transport> {
    link: Link<T>,
    state: State,
}
impl<T: Transport> Reader<T> {
    /// Own a newly opened transport. Initialization sends no data until requested.
    pub fn new(transport: T) -> Self {
        Self {
            link: Link::new(transport),
            state: State::NeedsInitialization,
        }
    }

    fn command(&mut self, cc: u8, args: &[u8], wait: Duration) -> Result<Vec<u8>, Error<T::Error>> {
        match self.link.command(cc, args, wait) {
            Ok(r) => Ok(r.data),
            Err(e) => {
                // A rejected, never-sent request leaves reader and card state
                // unchanged unless the stream itself already requires recovery.
                if e.progress != Progress::NotSent || matches!(e.failure, Failure::RecoveryRequired)
                {
                    self.state = State::NeedsInitialization;
                }
                Err(Error::Transaction(e))
            }
        }
    }

    /// Recover the transport, reset the reader, read its configuration, and enter
    /// RF-off readiness. Failure leaves the reader uninitialized; no command replay.
    /// Reset restores neither firmware parameters nor the `63 0D` reception
    /// setting, so this rewrites the defaults that NFC-A activation and every
    /// 106 kbps role rely on after a target role that changed them. It also
    /// sets the firmware's RF retry count (`32 04`) to zero, so that a mute or
    /// failed exchange never resends card data behind the caller.
    pub fn initialize(&mut self) -> Result<ReaderInfo, Error<T::Error>> {
        self.state = State::NeedsInitialization;
        self.link.recover().map_err(Error::Recovery)?;
        let wait = Duration::from_secs(1);
        self.link
            .reset(wait)
            .and_then(|commit| commit.commit())
            .map_err(Error::Transaction)?;
        let firmware: [u8; 4] = self
            .command(2, &[], wait)?
            .try_into()
            .map_err(|_| Error::Response("firmware length"))?;
        let probe = self.command(6, &[0xa0, 0], wait)?;
        if probe.len() != 1 {
            return Err(Error::Response("configuration probe length"));
        }
        let mut config = [0u8; 256];
        for bank in 0u8..4 {
            let mut addresses = Vec::with_capacity(128);
            for i in 0u8..64 {
                addresses.extend_from_slice(&[0xa0, bank * 64 + i]);
            }
            let values = self.command(6, &addresses, wait)?;
            if values.len() != 64 {
                return Err(Error::Response("configuration bank length"));
            }
            let begin = usize::from(bank) * 64;
            config[begin..begin + 64].copy_from_slice(&values);
        }
        let configuration = ConfigImage::parse(config).map_err(Error::Configuration)?;
        let flags = self
            .command(0x0c, &[], wait)?
            .first()
            .copied()
            .ok_or(Error::Response("reader flags length"))?;
        self.set_parameters(Parameters::DEFAULT)?;
        if !self.command(0x32, &[4, 0], wait)?.is_empty() {
            return Err(Error::Response("RF retry response length"));
        }
        self.write_register(0x630a, 0x40)?;
        self.write_register(0x630d, 0)?;
        self.disable_rf()?;
        let info = ReaderInfo {
            firmware,
            flags,
            configuration,
        };
        self.state = State::Ready {
            info: info.clone(),
            rf: RfMode::Off,
            response_timeout: None,
        };
        Ok(info)
    }

    fn write_register(&mut self, address: u16, value: u8) -> Result<(), Error<T::Error>> {
        self.write_registers(&[(address, value)])
    }

    /// Write registers in order with one `08` command. The reader returns one
    /// status per register; the first nonzero status is reported.
    fn write_registers(&mut self, writes: &[(u16, u8)]) -> Result<(), Error<T::Error>> {
        let args: Vec<u8> = writes
            .iter()
            .flat_map(|&(address, value)| {
                let [hi, lo] = address.to_be_bytes();
                [hi, lo, value]
            })
            .collect();
        let reply = self.command(8, &args, Duration::from_secs(1))?;
        if reply.len() != writes.len() {
            return Err(Error::Response("register write length"));
        }
        match reply.iter().find(|status| **status != 0) {
            Some(status) => Err(Error::RegisterStatus(*status)),
            None => Ok(()),
        }
    }

    fn set_parameters(&mut self, parameters: Parameters) -> Result<(), Error<T::Error>> {
        let reply = self.command(0x12, &[parameters.byte()], Duration::from_secs(1))?;
        if reply.is_empty() {
            Ok(())
        } else {
            Err(Error::Response("parameter response length"))
        }
    }

    /// Send InListPassiveTarget (`4A`). The firmware can stall its receiver
    /// so that no request is sent and the command never finds a card; a
    /// stalled receiver is restarted (Receive, then Idle, keeping the upper
    /// command bits) before every activation.
    fn list_passive_target(
        &mut self,
        args: &[u8],
        wait: Duration,
    ) -> Result<Vec<u8>, ActivationError<T::Error>> {
        self.restart_stalled_receiver()
            .map_err(ActivationError::BeforeRequest)?;
        self.command(0x4a, args, wait)
            .map_err(ActivationError::Request)
    }

    /// Reading the probe changes nothing. Once the restart writes begin, a
    /// failure can leave the receiver in an unknown command state, so only
    /// both completed writes keep the configured mode published.
    fn restart_stalled_receiver(&mut self) -> Result<(), Error<T::Error>> {
        let [status, command]: [u8; 2] = self
            .command(6, &RECEIVER_PROBE, Duration::from_secs(1))?
            .try_into()
            .map_err(|_| Error::Response("receiver probe length"))?;
        if status & RECEIVER_STALLED == 0 {
            return Ok(());
        }
        let ready = mem::replace(&mut self.state, State::NeedsInitialization);
        if matches!(ready, State::NeedsInitialization) {
            return Err(Error::NotInitialized);
        }
        let kept = command & 0xf0;
        self.write_registers(&[
            (CIU_COMMAND, kept | CIU_RECEIVE),
            (CIU_COMMAND, kept | CIU_IDLE),
        ])?;
        self.state = ready;
        Ok(())
    }

    fn configure_rf(
        &mut self,
        protocol: RfProtocol,
        timeout: RfTimeout,
    ) -> Result<(), Error<T::Error>> {
        if let State::Ready { rf, .. } = self.state
            && !matches!(
                rf,
                RfMode::Off
                    | RfMode::Configured {
                        selection: RfSelection::Ordinary,
                        ..
                    }
            )
        {
            self.rf_off()?;
        }
        let timer = ReaderTimer::for_rf_timeout(timeout);
        let (info, apply_mode, response_timeout) = match &self.state {
            State::Ready {
                rf:
                    RfMode::Configured {
                        protocol: applied,
                        timer: old,
                        ..
                    },
                ..
            } if *applied == protocol && *old == timer => return Ok(()),
            State::Ready {
                info,
                rf,
                response_timeout,
            } => (
                info.clone(),
                !matches!(rf,
                RfMode::Configured { protocol: applied, .. } if *applied == protocol),
                *response_timeout,
            ),
            State::NeedsInitialization => return Err(Error::NotInitialized),
        };
        // Any partial configuration revokes the preceding published mode.
        self.state = State::NeedsInitialization;
        self.command(0x1c, &timer.args(), Duration::from_secs(1))?;
        if apply_mode {
            let (retry, timing) = if protocol == RfProtocol::Felica {
                (0, 0xb7)
            } else {
                (4, 0x8f)
            };
            self.command(0x32, &[5, 0, 0, retry], Duration::from_secs(1))?;
            self.command(0x32, &[0x81, timing], Duration::from_secs(1))?;
            for item in info.configuration.rf_configuration(protocol) {
                self.command(0x32, &item, Duration::from_secs(1))?;
            }
            self.write_register(0x630d, 0)?;
        }
        self.state = State::Ready {
            info,
            rf: RfMode::Configured {
                protocol,
                timer,
                selection: RfSelection::Ordinary,
            },
            response_timeout,
        };
        Ok(())
    }

    fn prepare_exchange_timing(
        &mut self,
        protocol: RfProtocol,
        timeout: ResponseTimeout,
    ) -> Result<(), Error<T::Error>> {
        let desired_timer = ReaderTimer::for_rf_timeout(RfTimeout::new(timeout.wait())?);
        let (info, applied_timer, applied_timeout, selection) = match &self.state {
            State::Ready {
                rf:
                    RfMode::Configured {
                        protocol: applied_protocol,
                        timer,
                        ..
                    },
                response_timeout: Some(applied),
                ..
            } if *applied_protocol == protocol
                && *applied == timeout
                && *timer == desired_timer =>
            {
                return Ok(());
            }
            State::Ready {
                info,
                rf:
                    RfMode::Configured {
                        protocol: applied,
                        timer,
                        selection,
                    },
                response_timeout,
            } if *applied == protocol => (info.clone(), *timer, *response_timeout, *selection),
            _ => return Err(Error::NotInitialized),
        };
        // Do not publish a partial pair. Even if 32/02 succeeds, failure of 1C
        // requires explicit initialization before another card command is sent.
        self.state = State::NeedsInitialization;
        if applied_timeout != Some(timeout) {
            self.command(0x32, &timeout.args(), Duration::from_secs(1))?;
        }
        if applied_timer != desired_timer {
            self.command(0x1c, &desired_timer.args(), Duration::from_secs(1))?;
        }
        self.state = State::Ready {
            info,
            rf: RfMode::Configured {
                protocol,
                timer: desired_timer,
                selection,
            },
            response_timeout: Some(timeout),
        };
        Ok(())
    }

    /// Select one FeliCa card at the supplied rate. The returned card exclusively borrows
    /// this reader, so its identity cannot survive a reset/mode change through it.
    /// Unsupported Polling request data may be absent and is preserved as such.
    pub fn poll_felica(
        &mut self,
        rate: BitRate,
        request: PollRequest,
        timeout: RfTimeout,
    ) -> Result<Option<FelicaCard<'_, T>>, Error<T::Error>> {
        self.configure_rf(RfProtocol::Felica, timeout)?;
        let poll = request.encode();
        let mut args = vec![1, rate.selector()];
        args.extend_from_slice(&poll[1..]);
        let response = self.list_passive_target(&args, timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, packet @ ..] if *target != 0 => {
                let observation = match PollResponse::parse(packet) {
                    Ok(observation) => observation,
                    Err(error) => {
                        self.record_rejected_activation();
                        return Err(Error::FelicaResponse(error));
                    }
                };
                Ok(Some(FelicaCard {
                    reader: self,
                    observation,
                    target: *target,
                    timeout,
                    rate,
                }))
            }
            _ => {
                self.record_rejected_activation();
                Err(Error::Response("poll target count/layout"))
            }
        }
    }

    /// Activate one NFC-A target at 106 kbps. UID, SAK and optional ATS are
    /// validated before granting the returned card access to this reader.
    /// A preceding raw NFC-A exchange requires a field cycle before selection.
    pub fn poll_type_a(
        &mut self,
        timeout: RfTimeout,
    ) -> Result<Option<TypeACard<'_, T>>, Error<T::Error>> {
        self.configure_rf(RfProtocol::TypeA, timeout)?;
        let response = self.list_passive_target(&[1, 0], timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, data @ ..] if *target != 0 => {
                let observation = match nfca::Observation::parse(data) {
                    Ok(observation) => observation,
                    Err(error) => {
                        self.record_rejected_activation();
                        return Err(Error::TypeA(error));
                    }
                };
                Ok(Some(TypeACard {
                    reader: self,
                    observation,
                    target: *target,
                    timeout,
                }))
            }
            _ => {
                self.record_rejected_activation();
                Err(Error::Response("NFC-A target count/layout"))
            }
        }
    }

    /// Activate one NFC-B target at 106 kbps. ATQB determines which exchange
    /// authority the result grants. The caller chooses the RF table and AFI.
    /// `timeout` is the detection wait; ISO-DEP block waits come from ATQB.
    pub fn poll_type_b(
        &mut self,
        options: nfcb::PollOptions,
        timeout: RfTimeout,
    ) -> Result<Option<TypeBSelection<'_, T>>, Error<T::Error>> {
        let protocol = RfProtocol::TypeB(options.profile);
        self.configure_rf(protocol, timeout)?;
        let response = self.list_passive_target(&[1, 3, options.afi, 1], timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, data @ ..] if *target != 0 => {
                let (observation, session) = match type_b_activation(data, options) {
                    Ok(activation) => activation,
                    Err(error) => {
                        self.record_rejected_activation();
                        return Err(error);
                    }
                };
                self.apply_type_b_receiver()?;
                let target = TypeBTarget {
                    reader: self,
                    number: *target,
                    observation,
                    profile: options.profile,
                };
                Ok(Some(match session {
                    Some(session) => TypeBSelection::IsoDep(TypeBCard { target, session }),
                    None => TypeBSelection::Frame(TypeBFrameCard { target, timeout }),
                }))
            }
            _ => {
                self.record_rejected_activation();
                Err(Error::Response("NFC-B target count/layout"))
            }
        }
    }

    /// Record that firmware activated a target which this crate rejected.
    /// The next selection cycles the RF field before its request.
    fn record_rejected_activation(&mut self) {
        if let State::Ready {
            rf: RfMode::Configured { selection, .. },
            ..
        } = &mut self.state
        {
            *selection = RfSelection::RejectedActivation;
        }
    }

    /// Write the NFC-B receiver register (`63 03 = 8B`) that every activated
    /// Type B selection exchanges under. A selection handle exists only after
    /// this write succeeds; failure leaves the reader requiring initialization.
    /// Other protocols do not restore the register.
    fn apply_type_b_receiver(&mut self) -> Result<(), Error<T::Error>> {
        let State::Ready {
            info,
            rf,
            response_timeout,
        } = mem::replace(&mut self.state, State::NeedsInitialization)
        else {
            return Err(Error::NotInitialized);
        };
        self.write_register(0x6303, 0x8b)?;
        self.state = State::Ready {
            info,
            rf,
            response_timeout,
        };
        Ok(())
    }

    fn exchange_rf(
        &mut self,
        data: &[u8],
        timeout: RfTimeout,
        protocol: RfProtocol,
    ) -> Result<Vec<u8>, Error<T::Error>> {
        if !matches!(self.state, State::Ready { rf: RfMode::Configured { protocol: applied, .. }, .. } if applied == protocol)
        {
            return Err(Error::NotInitialized);
        }
        if data.len() > 255 {
            return Err(Error::InputLength {
                maximum: 255,
                actual: data.len(),
            });
        }
        let mut args = Vec::with_capacity(data.len() + 2);
        args.extend_from_slice(&timeout.ticks.to_le_bytes());
        args.extend_from_slice(data);
        let response = self.command(0xa0, &args, timeout.host_wait())?;
        self.rf_response(response)
    }

    fn rf_response(&mut self, response: Vec<u8>) -> Result<Vec<u8>, Error<T::Error>> {
        match response.split_first() {
            Some((status, body)) if status & 0x3f == 0 => Ok(body.to_vec()),
            Some((status, _)) => {
                if status & 0x3f == 0x0d {
                    self.state = State::NeedsInitialization;
                }
                if status & 0x3f == 0x0b {
                    // Settle this RF error before the caller can issue another
                    // exchange; returning the error alone does not impose a gap.
                    self.link.wait(Duration::from_millis(10));
                }
                Err(Error::RfStatus(*status))
            }
            None => Err(Error::Response("missing RF status")),
        }
    }

    fn exchange_target(
        &mut self,
        target: u8,
        data: &[u8],
        timeout: ResponseTimeout,
    ) -> Result<TargetResponse, Error<T::Error>> {
        let mut args = Vec::with_capacity(data.len() + 1);
        args.push(target);
        args.extend_from_slice(data);
        let response = self.command(0x40, &args, timeout.host_wait())?;
        let status = response
            .first()
            .copied()
            .ok_or(Error::Response("missing RF status"))?;
        let data = self.rf_response(response)?;
        Ok(TargetResponse { status, data })
    }

    fn prepare_target_exchange(
        &mut self,
        protocol: RfProtocol,
        timeout: ResponseTimeout,
    ) -> Result<(), TargetExchangeError<T::Error>> {
        if !matches!(
            self.state,
            State::Ready {
                rf: RfMode::Configured { protocol: applied, .. },
                ..
            } if applied == protocol
        ) {
            return Err(TargetExchangeError::SessionInvalid);
        }
        self.prepare_exchange_timing(protocol, timeout)
            .map_err(TargetExchangeError::Preparation)
    }

    /// Exchange one `40` command whose response is a single fragment.
    fn exchange_single_response(
        &mut self,
        protocol: RfProtocol,
        target: u8,
        data: &[u8],
        timeout: ResponseTimeout,
    ) -> Result<TargetResponse, TargetExchangeError<T::Error>> {
        self.prepare_target_exchange(protocol, timeout)?;
        let response = self.exchange_target(target, data, timeout);
        // These commands cannot collect a pending fragment. A missing status
        // also leaves the continuation state unknown.
        if match &response {
            Ok(reply) => reply.status & TARGET_MORE_INFORMATION != 0,
            Err(Error::RfStatus(status)) => status & TARGET_MORE_INFORMATION != 0,
            Err(Error::Response(_)) => true,
            Err(_) => false,
        } {
            self.state = State::NeedsInitialization;
        }
        response.map_err(TargetExchangeError::Exchange)
    }

    fn disable_rf(&mut self) -> Result<(), Error<T::Error>> {
        let response = self.command(0x32, &[1, 0], Duration::from_secs(1))?;
        if !response.is_empty() {
            return Err(Error::Response("RF off response length"));
        }
        self.link.wait(Duration::from_millis(5));
        Ok(())
    }

    /// Disable RF and invalidate the configured mode. Call explicitly to observe
    /// failure; dropping a reader only releases the backend's OS resources.
    /// If a raw NFC-A response was left pending, use [`Self::initialize`] to
    /// recover the reader stream before issuing further commands.
    pub fn rf_off(&mut self) -> Result<(), Error<T::Error>> {
        let (info, response_timeout) = match &self.state {
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Pending { .. }),
                ..
            }
            | State::NeedsInitialization => return Err(Error::NotInitialized),
            State::Ready {
                info,
                response_timeout,
                ..
            } => (info.clone(), *response_timeout),
        };
        self.state = State::NeedsInitialization;
        self.disable_rf()?;
        self.state = State::Ready {
            info,
            rf: RfMode::Off,
            response_timeout,
        };
        Ok(())
    }
}

/// Reply to a reader-managed target exchange. The complete reader status is
/// retained, including upper bits whose continuation semantics are not assumed.
#[derive(Debug, Clone)]
pub struct TargetResponse {
    /// Unmodified status byte of command 41; its low six bits are zero on success.
    pub status: u8,
    /// Card bytes returned by the reader, without a fabricated APDU status word.
    pub data: Vec<u8>,
}

/// Failure of one card command sent through the reader's `40` target
/// exchange, classified by its application effect.
#[derive(Debug)]
pub enum TargetExchangeError<E> {
    /// The supplied byte count is outside `1..=maximum` for the selection.
    /// Nothing was sent and the selection remains usable.
    InputLength {
        /// Largest command the selection admits.
        maximum: usize,
        /// Supplied bytes.
        actual: usize,
    },
    /// The selection has already lost its operation authority.
    SessionInvalid,
    /// A raw NFC-A exchange has a response fragment waiting to be collected.
    ResponsePending,
    /// The raw NFC-A response exceeded the fragment budget. Reinitialize the reader.
    FragmentLimit,
    /// Reader timing setup failed before any card command was sent.
    Preparation(Error<E>),
    /// The card command transaction or its response failed. Consult the cause
    /// for transport progress; the command may have taken effect.
    Exchange(Error<E>),
}

impl<E: fmt::Debug> fmt::Display for TargetExchangeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLength { maximum, actual } => {
                write!(f, "card command of {actual} bytes is outside 1..={maximum}")
            }
            Self::SessionInvalid => f.write_str("card selection is no longer valid"),
            Self::ResponsePending => f.write_str("an NFC-A response fragment is pending"),
            Self::FragmentLimit => f.write_str("NFC-A response fragment limit exceeded"),
            Self::Preparation(_) => f.write_str("reader setup failed before the card command"),
            Self::Exchange(_) => {
                f.write_str("card exchange failed; the command may have taken effect")
            }
        }
    }
}

impl<E: error::Error + 'static> error::Error for TargetExchangeError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Preparation(error) | Self::Exchange(error) => Some(error),
            Self::InputLength { .. }
            | Self::SessionInvalid
            | Self::ResponsePending
            | Self::FragmentLimit => None,
        }
    }
}

/// NFC-A selection tied to one exclusive reader borrow.
#[derive(Debug)]
pub struct TypeACard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    observation: nfca::Observation,
    target: u8,
    timeout: RfTimeout,
}
impl<'a, T: Transport> TypeACard<'a, T> {
    pub(crate) fn type2_sector(&self) -> u8 {
        match self.reader.state {
            State::Ready {
                rf:
                    RfMode::Configured {
                        selection: RfSelection::Type2Sector(sector),
                        ..
                    },
                ..
            } => sector.get(),
            _ => 0,
        }
    }

    pub(crate) fn record_type2_sector(&mut self, selected: u8) {
        if let State::Ready {
            rf: RfMode::Configured { selection, .. },
            ..
        } = &mut self.reader.state
        {
            *selection =
                NonZeroU8::new(selected).map_or(RfSelection::Ordinary, RfSelection::Type2Sector);
        }
    }

    pub(crate) fn invalidate(&mut self) {
        self.reader.state = State::NeedsInitialization;
    }

    /// Validated activation data for this selection.
    pub fn observation(&self) -> &nfca::Observation {
        &self.observation
    }
    /// Target identifier returned by the reader.
    pub fn target(&self) -> u8 {
        self.target
    }
    /// Largest APDU [`Self::exchange_apdu`] admits. The reader performs ISO-DEP
    /// chaining, so this is its `40` command limit.
    pub fn maximum_apdu_bytes(&self) -> usize {
        MAX_TYPE_A_COMMAND_BYTES
    }
    /// Replace the card response wait of later exchanges through this
    /// selection, including [`Self::into_raw`]. It starts as the polling
    /// timeout, so a caller polling with a short wait can grant card commands
    /// a longer one. The `32/02` step rounding and `1C` timer of `40` exchanges
    /// apply unchanged.
    pub fn set_exchange_timeout(&mut self, timeout: RfTimeout) {
        self.timeout = timeout;
    }
    /// Consume the typed selection and allow caller-defined card commands.
    /// Such commands can change card state that typed operations depend on.
    pub fn into_raw(self) -> RawTypeACard<'a, T> {
        RawTypeACard {
            reader: self.reader,
            target: self.target,
            timeout: ResponseTimeout::for_request(self.timeout),
        }
    }

    // Only for crate-owned commands whose response is a single frame and
    // whose effects preserve the typed selection's activation assumptions.
    pub(crate) fn exchange(
        &mut self,
        data: &[u8],
    ) -> Result<TargetResponse, TargetExchangeError<T::Error>> {
        admit_command(data, MAX_TYPE_A_COMMAND_BYTES)?;
        let timeout = ResponseTimeout::for_request(self.timeout);
        self.reader
            .exchange_single_response(RfProtocol::TypeA, self.target, data, timeout)
    }

    /// Exchange one ISO-DEP APDU and collect reader-reported continuation
    /// fragments. Requires completed activation with ATS. The APDU is sent
    /// once. Failure after submission returns any accumulated response and
    /// invalidates the selection before another command can be sent.
    pub fn exchange_apdu(
        &mut self,
        apdu: &[u8],
    ) -> Result<Vec<u8>, isodep::Error<Error<T::Error>>> {
        const MAX_RESPONSE_BYTES: usize = 65_536;
        let mut progress = isodep::Progress::default();
        let mut output = Vec::new();
        let result = (|| {
            if !self.observation.supports_iso_dep() || self.observation.ats().is_none() {
                return Err(isodep::Cause::ActivationRequired);
            }
            if apdu.is_empty() || apdu.len() > MAX_TYPE_A_COMMAND_BYTES {
                return Err(isodep::Cause::InputLength {
                    actual: apdu.len(),
                    maximum: MAX_TYPE_A_COMMAND_BYTES,
                });
            }
            let timeout = ResponseTimeout::for_request(self.timeout);
            match self
                .reader
                .prepare_target_exchange(RfProtocol::TypeA, timeout)
            {
                Ok(()) => {}
                Err(TargetExchangeError::Preparation(error)) => {
                    return Err(isodep::Cause::Preparation(error));
                }
                Err(_) => return Err(isodep::Cause::SessionInvalid),
            }
            progress.attempted_application_bytes = apdu.len();
            progress.frames = 1;
            let mut response = match self.reader.exchange_target(self.target, apdu, timeout) {
                Ok(response) => {
                    progress.acknowledged_application_bytes = apdu.len();
                    response
                }
                Err(error) => return Err(isodep::Cause::Transport(error)),
            };
            loop {
                if response.status & 0x80 != 0 {
                    return Err(isodep::Cause::InvalidBlock("unexpected NFC-A NAD"));
                }
                if output.len() + response.data.len() > MAX_RESPONSE_BYTES {
                    return Err(isodep::Cause::Budget(isodep::Budget::ResponseBytes));
                }
                output.extend_from_slice(&response.data);
                progress.received_application_bytes = output.len();
                if response.status & TARGET_MORE_INFORMATION == 0 {
                    return Ok(());
                }
                if progress.frames == MAX_TYPE_A_RESPONSE_FRAGMENTS {
                    return Err(isodep::Cause::Budget(isodep::Budget::Frames));
                }
                progress.frames += 1;
                response = self
                    .reader
                    .exchange_target(self.target, &[], timeout)
                    .map_err(isodep::Cause::Transport)?;
            }
        })();
        if let Err(cause) = result {
            if progress.frames != 0 {
                self.reader.state = State::NeedsInitialization;
            }
            return Err(isodep::Error {
                cause,
                progress,
                partial_response: output,
            });
        }
        Ok(output)
    }
}

/// Exclusive raw command access to a selected NFC-A target.
///
/// A pending response can only be continued through this handle. Abandoning
/// it requires reader initialization. A completed raw exchange requires RF
/// off before the next selection to clear card state such as the Type 2 sector.
#[derive(Debug)]
pub struct RawTypeACard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    target: u8,
    timeout: ResponseTimeout,
}

impl<T: Transport> RawTypeACard<'_, T> {
    /// Submit one caller-defined card command and return its first fragment,
    /// including the unmodified reader status.
    ///
    /// Input must contain 1 to 262 bytes. Input rejection preserves the
    /// selection. When a response is pending, call [`Self::receive_continuation`].
    pub fn exchange(
        &mut self,
        data: &[u8],
    ) -> Result<TargetResponse, TargetExchangeError<T::Error>> {
        admit_command(data, MAX_TYPE_A_COMMAND_BYTES)?;
        match self.reader.state {
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Pending { .. }),
                ..
            } => {
                return Err(TargetExchangeError::ResponsePending);
            }
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Idle),
                ..
            } => {}
            _ => self
                .reader
                .prepare_target_exchange(RfProtocol::TypeA, self.timeout)?,
        }
        // Record loss of typed selection before the first raw transfer. This
        // survives release of the handle and errors that leave the link usable.
        self.set_response(RawTypeAResponse::Idle);
        self.transfer(data, 1)
    }

    /// Receive the next fragment without sending card command data. Returns
    /// `None` when the selection has no pending response. An exchange can
    /// return up to 256 fragments. Continuation failure requires reinitialization.
    pub fn receive_continuation(
        &mut self,
    ) -> Result<Option<TargetResponse>, TargetExchangeError<T::Error>> {
        let frames = match self.reader.state {
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Pending { frames }),
                ..
            } => frames,
            State::Ready { .. } => return Ok(None),
            State::NeedsInitialization => return Err(TargetExchangeError::SessionInvalid),
        };
        if frames == MAX_TYPE_A_RESPONSE_FRAGMENTS {
            self.reader.state = State::NeedsInitialization;
            return Err(TargetExchangeError::FragmentLimit);
        }
        self.transfer(&[], frames + 1).map(Some)
    }

    fn set_response(&mut self, response: RawTypeAResponse) {
        if let State::Ready { rf, .. } = &mut self.reader.state {
            *rf = RfMode::RawTypeA(response);
        }
    }

    fn transfer(
        &mut self,
        data: &[u8],
        frames: usize,
    ) -> Result<TargetResponse, TargetExchangeError<T::Error>> {
        let result = self.reader.exchange_target(self.target, data, self.timeout);
        match &result {
            Ok(response) => {
                let next = if response.status & TARGET_MORE_INFORMATION != 0 {
                    RawTypeAResponse::Pending { frames }
                } else {
                    RawTypeAResponse::Idle
                };
                self.set_response(next);
            }
            Err(Error::RfStatus(status))
                if frames == 1 && status & TARGET_MORE_INFORMATION == 0 => {}
            Err(_) => self.reader.state = State::NeedsInitialization,
        }
        result.map_err(TargetExchangeError::Exchange)
    }
}

/// NFC-B ISO-DEP selection, with a block-number state that cannot outlive the
/// reader selection. Protocol failure poisons the session; it never replays APDUs.
#[derive(Debug)]
pub struct TypeBCard<'a, T: Transport> {
    target: TypeBTarget<'a, T>,
    session: isodep::Session,
}
impl<T: Transport> TypeBCard<'_, T> {
    /// Largest APDU this session admits: the local limit, the card buffer
    /// advertised by MBLI, and the frame budget, whichever is smallest.
    pub fn maximum_apdu_bytes(&self) -> usize {
        self.session.maximum_apdu_bytes()
    }

    /// Validated activation data, including ATQB and negotiated CID.
    pub fn observation(&self) -> &nfcb::Observation {
        &self.target.observation
    }
    /// Target identifier returned by the reader.
    pub fn target(&self) -> u8 {
        self.target.number
    }
    /// Exchange one APDU, handling ISO-DEP chaining, R-blocks and bounded WTX.
    /// Errors distinguish reader setup (zero application progress) from RF
    /// transfer attempts. Setup applies 32/02 selector 0x10 and a 3280 ms reader
    /// response step; each A0 block independently uses its FWI/WTX wait.
    /// Application APDUs are never retried.
    pub fn exchange_apdu(
        &mut self,
        apdu: &[u8],
    ) -> Result<Vec<u8>, isodep::Error<Error<T::Error>>> {
        let reader = &mut self.target.reader;
        let protocol = RfProtocol::TypeB(self.target.profile);
        let exchange = self.session.prepare(apdu)?;
        // One fixed 3280 ms selector and its 1C timer cover every block of the
        // APDU. A0 keeps its independent FWI/WTX wait; individual blocks do
        // not reprogram 1C.
        let setup = reader.prepare_exchange_timing(protocol, ResponseTimeout::Ms3280);
        exchange.exchange(
            setup,
            |error| matches!(error, Error::RfStatus(status) if status & 0x3f == 1),
            |block, wait| {
                let timeout = RfTimeout::new(wait)?;
                reader.exchange_rf(block, timeout, protocol)
            },
        )
    }

    /// Confirm that the card still answers between APDUs, using the same
    /// reader setup as [`Self::exchange_apdu`]. The probe carries no
    /// application data and leaves block numbering unchanged. Any failure,
    /// including an absent card, invalidates the session.
    pub fn check_presence(&mut self) -> Result<(), isodep::PresenceError<Error<T::Error>>> {
        let reader = &mut self.target.reader;
        let protocol = RfProtocol::TypeB(self.target.profile);
        let check = self.session.admit_presence_check()?;
        let setup = reader.prepare_exchange_timing(protocol, ResponseTimeout::Ms3280);
        check.run(
            setup,
            |error| matches!(error, Error::RfStatus(status) if status & 0x3f == 1),
            |block, wait| {
                let timeout = RfTimeout::new(wait)?;
                reader.exchange_rf(block, timeout, protocol)
            },
        )
    }
}

/// An NFC-B selection granting the operations of its advertised protocol.
#[derive(Debug)]
pub enum TypeBSelection<'a, T: Transport> {
    /// The card advertises ISO-DEP block exchange.
    IsoDep(TypeBCard<'a, T>),
    /// The card advertises another protocol. The caller supplies its frames.
    Frame(TypeBFrameCard<'a, T>),
}

impl<'a, T: Transport> TypeBSelection<'a, T> {
    /// Validated ATQB and ATTRIB data common to both selections.
    pub fn observation(&self) -> &nfcb::Observation {
        &self.target().observation
    }

    /// Target identifier returned by the reader.
    pub fn target_number(&self) -> u8 {
        self.target().number
    }

    fn target(&self) -> &TypeBTarget<'a, T> {
        match self {
            Self::IsoDep(card) => &card.target,
            Self::Frame(card) => &card.target,
        }
    }
}

#[derive(Debug)]
struct TypeBTarget<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    number: u8,
    observation: nfcb::Observation,
    profile: nfcb::RfProfile,
}

/// A selected NFC-B target for caller-defined non-ISO-DEP commands.
#[derive(Debug)]
pub struct TypeBFrameCard<'a, T: Transport> {
    target: TypeBTarget<'a, T>,
    timeout: RfTimeout,
}

impl<T: Transport> TypeBFrameCard<'_, T> {
    /// Send one target command through `40` and return its single response
    /// fragment. The reader's Type B command limit is
    /// [`MAX_TYPE_B_FRAME_COMMAND_BYTES`]. Card-specific command semantics
    /// belong to the caller. A response announcing a further fragment, or
    /// lacking its reader status, cannot be collected through this handle and
    /// invalidates the selection.
    pub fn exchange(
        &mut self,
        data: &[u8],
    ) -> Result<TargetResponse, TargetExchangeError<T::Error>> {
        admit_command(data, MAX_TYPE_B_FRAME_COMMAND_BYTES)?;
        let protocol = RfProtocol::TypeB(self.target.profile);
        let timeout = ResponseTimeout::for_request(self.timeout);
        self.target
            .reader
            .exchange_single_response(protocol, self.target.number, data, timeout)
    }
}

/// Validate NFC-B activation data and the ISO-DEP session it grants.
fn type_b_activation<E>(
    data: &[u8],
    options: nfcb::PollOptions,
) -> Result<(nfcb::Observation, Option<isodep::Session>), Error<E>> {
    let observation = nfcb::Observation::parse(data).map_err(Error::TypeB)?;
    if options.node_address.is_some()
        && !(observation.supports_iso_dep() && observation.nad_supported())
    {
        return Err(Error::IsoDepParameters(
            isodep::ParameterError::NadUnsupported,
        ));
    }
    if !observation.supports_iso_dep() {
        return Ok((observation, None));
    }
    let cid = match observation.cid() {
        0 => None,
        cid => Some(cid),
    };
    let session = isodep::Session::new(
        observation.card_frame_size(),
        cid,
        isodep::block_frame_wait(observation.fwi()),
        observation.maximum_command_bytes(),
        options.node_address,
    )
    .map_err(Error::IsoDepParameters)?;
    Ok((observation, Some(session)))
}

/// Reject an empty or oversized card command before any reader setup.
fn admit_command<E>(data: &[u8], maximum: usize) -> Result<(), TargetExchangeError<E>> {
    if data.is_empty() || data.len() > maximum {
        return Err(TargetExchangeError::InputLength {
            maximum,
            actual: data.len(),
        });
    }
    Ok(())
}

/// Selected card identity whose operation authority is tied to one reader borrow.
#[derive(Debug)]
pub struct FelicaCard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    observation: PollResponse,
    target: u8,
    timeout: RfTimeout,
    rate: BitRate,
}
impl<'a, T: Transport> FelicaCard<'a, T> {
    #[cfg(any(feature = "felica-lite-s", feature = "felica-standard-aes"))]
    pub(crate) fn begin_felica_authentication(&mut self) {
        if let State::Ready {
            rf: RfMode::Configured { selection, .. },
            ..
        } = &mut self.reader.state
        {
            *selection = RfSelection::FelicaAuthentication;
        }
    }

    /// Polling information. IDm is a session address, not a universal persistent ID.
    pub fn observation(&self) -> &PollResponse {
        &self.observation
    }
    /// Reader-selected target number.
    pub fn target(&self) -> u8 {
        self.target
    }
    /// Read up to twelve blocks from one unencrypted service. The caller chooses
    /// a service known to exist on this card; no card data is written.
    pub fn read_without_encryption(
        &mut self,
        service: u16,
        blocks: &[u16],
    ) -> Result<ReadResponse, Error<T::Error>> {
        let request = felica::read_without_encryption(self.observation.idm, service, blocks)
            .map_err(Error::FelicaRequest)?;
        let response = self
            .reader
            .exchange_rf(&request, self.timeout, RfProtocol::Felica)?;
        ReadResponse::parse(&response, self.observation.idm, blocks.len())
            .map_err(Error::FelicaResponse)
    }

    /// Write blocks to one service with Write Without Encryption. Card-specific
    /// limits still apply. [`Error::FelicaRequest`] means validation stopped
    /// the command before sending. [`Error::FelicaResponse`] means it was sent
    /// and the write outcome may be uncertain. Transport failures carry their
    /// own transaction progress.
    pub fn write_without_encryption(
        &mut self,
        service: u16,
        blocks: &[BlockWrite],
    ) -> Result<(), Error<T::Error>> {
        let idm = self.observation.idm;
        let request =
            felica::write_without_encryption(idm, service, blocks).map_err(Error::FelicaRequest)?;
        let response = self
            .reader
            .exchange_rf(&request, self.timeout, RfProtocol::Felica)?;
        felica::write_response(&response, idm).map_err(Error::FelicaResponse)
    }

    /// Confirm that the selected card still answers at its IDm, using Request
    /// Response. Returns the card's current mode byte; the command changes no
    /// card state. An absent card surfaces as the RF timeout
    /// [`Error::RfStatus`], a different card as [`Error::FelicaResponse`].
    pub fn request_response(&mut self) -> Result<u8, Error<T::Error>> {
        match self.exchange_command(0x04, &[], 0x05)?.as_slice() {
            [mode] => Ok(*mode),
            payload => Err(Error::FelicaResponse(CardError::Length {
                expected: 11,
                actual: payload.len() + 10,
            })),
        }
    }

    /// Request the system codes exposed by this card. Card products can omit this command.
    pub fn request_system_codes(&mut self) -> Result<Vec<u16>, Error<T::Error>> {
        let idm = self.observation.idm;
        let response = self.exchange_addressed(0x0c, &[])?;
        felica::system_codes(&response, idm).map_err(Error::FelicaResponse)
    }

    /// Look up one service or area index within the selected system.
    /// The end-of-list marker returns `None`; an RF failure remains an error.
    pub fn search_service_code(
        &mut self,
        index: u16,
    ) -> Result<Option<ServiceEntry>, Error<T::Error>> {
        let idm = self.observation.idm;
        let response = self.exchange_addressed(0x0a, &index.to_le_bytes())?;
        felica::service_entry(&response, idm).map_err(Error::FelicaResponse)
    }

    /// Send a caller-supplied FeliCa command with the selected IDm. `parameters`
    /// starts after IDm. Returns the payload after checking the length, response
    /// code and IDm. The caller owns command semantics and any cryptography.
    pub fn exchange_command(
        &mut self,
        command: u8,
        parameters: &[u8],
        response_code: u8,
    ) -> Result<Vec<u8>, Error<T::Error>> {
        let idm = self.observation.idm;
        let response = self.exchange_addressed(command, parameters)?;
        felica::addressed_response(&response, idm, response_code)
            .map(<[u8]>::to_vec)
            .map_err(Error::FelicaResponse)
    }

    fn exchange_addressed(&mut self, command: u8, data: &[u8]) -> Result<Vec<u8>, Error<T::Error>> {
        let request = felica::addressed_command(self.observation.idm, command, data)
            .map_err(Error::FelicaRequest)?;
        self.reader
            .exchange_rf(&request, self.timeout, RfProtocol::Felica)
    }

    /// Consume the selected card's typed command authority to send opaque
    /// packets at its negotiated FeliCa rate. Packets can affect addressing
    /// or card state, so the original identity is no longer an authority.
    pub fn into_raw(self) -> RawFelicaCard<'a, T> {
        RawFelicaCard {
            reader: self.reader,
            timeout: self.timeout,
        }
    }
}

/// Raw packet authority for an activated FeliCa RF field.
#[derive(Debug)]
pub struct RawFelicaCard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    timeout: RfTimeout,
}

impl<T: Transport> RawFelicaCard<'_, T> {
    /// Send a caller-built FeliCa packet using `A0`. Both packets include
    /// their FeliCa length byte. Address, command, status, and any ciphertext
    /// belong to the caller; packet effects are never replayed automatically.
    pub fn exchange_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error<T::Error>> {
        felica::validate_length(packet, 2).map_err(Error::FelicaRequest)?;
        let response = self
            .reader
            .exchange_rf(packet, self.timeout, RfProtocol::Felica)?;
        felica::validate_length(&response, 2).map_err(Error::FelicaResponse)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timeout_uses_ceil_and_rejects_overflow() {
        assert!(RfTimeout::new(Duration::ZERO).is_err());
        assert!(matches!(RfTimeout::new(Duration::from_micros(501)),Ok(t) if t.ticks()==2));
        assert!(RfTimeout::new(Duration::from_secs(33)).is_err());
    }
    #[test]
    fn config_checks_regions_and_model() {
        let mut e = [0u8; 256];
        e[0] = 0x55;
        e[1] = 0xaa;
        e[2] = 1;
        e[253] = 1;
        e[254] = 0x31;
        assert!(matches!(ConfigImage::parse(e),Ok(c) if c.model().word()==0x0131));
        e[0x40] = 1;
        assert!(matches!(
            ConfigImage::parse(e),
            Err(ConfigurationError::Checksum { offset: 0x40 })
        ));
    }

    #[test]
    fn reader_timer_wire_values_cover_second_boundaries() -> Result<(), TimeoutRange> {
        for (wait, expected) in [
            (Duration::from_millis(100), [0x80, 0x63, 0]),
            (Duration::from_secs(1), [0x80, 0x63, 0]),
            (Duration::from_micros(1_000_500), [0x80, 0xc7, 0]),
            (Duration::from_micros(32_767_500), [0x80, 0xe3, 0x0c]),
        ] {
            assert_eq!(
                ReaderTimer::for_rf_timeout(RfTimeout::new(wait)?).args(),
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn response_timeout_vectors_cover_quantization_and_saturation() -> Result<(), TimeoutRange> {
        // Independent boundary vectors from f:3B250's millisecond intervals.
        for (microseconds, selector, effective_ms, timer) in [
            (500, 0x0a, 51, [0x80, 0x63, 0]),
            (51_000, 0x0a, 51, [0x80, 0x63, 0]),
            (51_500, 0x0b, 102, [0x80, 0x63, 0]),
            (102_000, 0x0b, 102, [0x80, 0x63, 0]),
            (102_500, 0x0c, 204, [0x80, 0x63, 0]),
            (204_000, 0x0c, 204, [0x80, 0x63, 0]),
            (204_500, 0x0d, 409, [0x80, 0x63, 0]),
            (409_000, 0x0d, 409, [0x80, 0x63, 0]),
            (409_500, 0x0e, 819, [0x80, 0x63, 0]),
            (500_000, 0x0e, 819, [0x80, 0x63, 0]),
            (819_000, 0x0e, 819, [0x80, 0x63, 0]),
            (819_500, 0x0f, 1640, [0x80, 0xc7, 0]),
            (1_640_000, 0x0f, 1640, [0x80, 0xc7, 0]),
            (1_640_500, 0x10, 3280, [0x80, 0x8f, 1]),
            (32_767_500, 0x10, 3280, [0x80, 0x8f, 1]),
        ] {
            let timeout =
                ResponseTimeout::for_request(RfTimeout::new(Duration::from_micros(microseconds))?);
            assert_eq!(timeout.args(), [2, 0x0b, 0x0b, selector]);
            assert_eq!(timeout.wait(), Duration::from_millis(effective_ms));
            assert_eq!(
                timeout.host_wait(),
                Duration::from_millis(effective_ms + 1000)
            );
            assert_eq!(
                ReaderTimer::for_rf_timeout(RfTimeout::new(timeout.wait())?).args(),
                timer
            );
        }
        Ok(())
    }
}
