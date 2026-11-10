//! Reader configuration and lifetime-bound NFC card access.

use crate::{
    felica::{
        self, BitRate, BlockWrite, CardError, PollRequest, PollResponse, ReadResponse, ServiceEntry,
    },
    isodep, nfca, nfcb,
    transport::{Link, TransactionError, Transport},
};
use alloc::{vec, vec::Vec};
use core::{error, fmt, time::Duration};

/// Maximum card-command bytes accepted by the reader's NFC-A exchange.
pub const MAX_TYPE_A_COMMAND_BYTES: usize = 262;
const MAX_TYPE_A_RESPONSE_FRAGMENTS: usize = 256;
const TYPE_A_MORE_INFORMATION: u8 = 0x40;

/// Failures of reader initialization, RF configuration, or card exchange.
#[derive(Debug)]
pub enum Error<E> {
    /// Host transport transaction failed; the stream must be reinitialized.
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
    /// Raw RF status and its command-specific classification.
    RfStatus(u8),
    /// Card-level response validation failed.
    Card(CardError),
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
        write!(f, "{self:?}")
    }
}
impl<E: error::Error + 'static> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Transaction(error) | Self::Recovery(error) => Some(error),
            Self::Configuration(error) => Some(error),
            Self::Card(error) => Some(error),
            Self::Timeout(error) => Some(error),
            Self::TypeA(error) => Some(error),
            Self::TypeB(error) => Some(error),
            Self::IsoDepParameters(error) => Some(error),
            _ => None,
        }
    }
}
impl<E> From<CardError> for Error<E> {
    fn from(e: CardError) -> Self {
        Self::Card(e)
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
        write!(f, "{self:?}")
    }
}
impl error::Error for ConfigurationError {}

/// Immutable, validated configuration read from one attached reader.
#[derive(Debug, Clone)]
pub struct ConfigImage {
    bytes: [u8; 256],
    model: u16,
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
        let model = u16::from_be_bytes([bytes[253], bytes[254]]);
        Ok(Self { bytes, model })
    }
    /// Model word from E[FD..FE], distinct from USB PID.
    pub fn model(&self) -> u16 {
        self.model
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
    },
    RawTypeA(RawTypeAResponse),
}

#[derive(Debug, Clone, Copy)]
enum RawTypeAResponse {
    Idle,
    Pending { frames: usize },
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
                self.state = State::NeedsInitialization;
                Err(Error::Transaction(e))
            }
        }
    }

    /// Recover the transport, reset the reader, read its configuration, and enter
    /// RF-off readiness. Failure leaves the reader uninitialized; no command replay.
    pub fn initialize(&mut self) -> Result<ReaderInfo, Error<T::Error>> {
        self.state = State::NeedsInitialization;
        self.link.recover().map_err(Error::Recovery)?;
        let wait = Duration::from_secs(1);
        self.command(0x18, &[1], wait)?;
        self.link.host_ack(wait).map_err(Error::Transaction)?;
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
        self.write_register(0x630a, 0x40)?;
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
        let [hi, lo] = address.to_be_bytes();
        let reply = self.command(8, &[hi, lo, value], Duration::from_secs(1))?;
        match reply.as_slice() {
            [0] => Ok(()),
            [status] => Err(Error::RegisterStatus(*status)),
            _ => Err(Error::Response("register write length")),
        }
    }

    fn configure_rf(
        &mut self,
        protocol: RfProtocol,
        timeout: RfTimeout,
    ) -> Result<(), Error<T::Error>> {
        if matches!(
            self.state,
            State::Ready {
                rf: RfMode::RawTypeA(_),
                ..
            }
        ) {
            self.rf_off()?;
        }
        let timer = ReaderTimer::for_rf_timeout(timeout);
        let (info, apply_mode, response_timeout) = match &self.state {
            State::Ready {
                rf:
                    RfMode::Configured {
                        protocol: applied,
                        timer: old,
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
            rf: RfMode::Configured { protocol, timer },
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
        let (info, applied_timer, applied_timeout) = match &self.state {
            State::Ready {
                rf:
                    RfMode::Configured {
                        protocol: applied_protocol,
                        timer,
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
                    },
                response_timeout,
            } if *applied == protocol => (info.clone(), *timer, *response_timeout),
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
        let response = self.command(0x4a, &args, timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, packet @ ..] if *target != 0 => {
                let observation = PollResponse::parse(packet)?;
                Ok(Some(FelicaCard {
                    reader: self,
                    observation,
                    target: *target,
                    timeout,
                }))
            }
            _ => Err(Error::Response("poll target count/layout")),
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
        let response = self.command(0x4a, &[1, 0], timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, data @ ..] if *target != 0 => {
                let observation = nfca::Observation::parse(data).map_err(Error::TypeA)?;
                Ok(Some(TypeACard {
                    reader: self,
                    observation,
                    target: *target,
                    timeout,
                }))
            }
            _ => Err(Error::Response("NFC-A target count/layout")),
        }
    }

    /// Activate one NFC-B target at 106 kbps. ATQB determines which exchange
    /// authority the result grants. The caller chooses the RF table and AFI.
    pub fn poll_type_b(
        &mut self,
        options: nfcb::PollOptions,
        timeout: RfTimeout,
    ) -> Result<Option<TypeBSelection<'_, T>>, Error<T::Error>> {
        let protocol = RfProtocol::TypeB(options.profile);
        self.configure_rf(protocol, timeout)?;
        let response = self.command(0x4a, &[1, 3, options.afi, 1], timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, data @ ..] if *target != 0 => {
                let observation = nfcb::Observation::parse(data).map_err(Error::TypeB)?;
                if options.node_address.is_some()
                    && !(observation.supports_iso_dep() && observation.nad_supported())
                {
                    return Err(Error::IsoDepParameters(
                        isodep::ParameterError::NadUnsupported,
                    ));
                }
                if !observation.supports_iso_dep() {
                    return Ok(Some(TypeBSelection::Frame(TypeBFrameCard {
                        target: TypeBTarget {
                            reader: self,
                            number: *target,
                            observation,
                            profile: options.profile,
                        },
                        timeout,
                    })));
                }
                let wait = isodep::block_frame_wait(observation.fwi());
                let cid = match observation.cid() {
                    0 => None,
                    cid => Some(cid),
                };
                let session = isodep::Session::new(
                    observation.frame_size(),
                    observation.reader_frame_size(),
                    cid,
                    wait,
                    observation.maximum_command_bytes(),
                    options.node_address,
                )
                .map_err(Error::IsoDepParameters)?;
                let (info, response_timeout) = match &self.state {
                    State::Ready {
                        info,
                        response_timeout,
                        ..
                    } => (info.clone(), *response_timeout),
                    State::NeedsInitialization => return Err(Error::NotInitialized),
                };
                // The ordinary driver path configures software block exchange
                // after activation. Failure must not publish a usable card.
                self.state = State::NeedsInitialization;
                self.write_register(0x6303, 0x8b)?;
                // Re-establish the fully applied mode only after the write.
                // The existing snapshot remains authoritative across this write.
                self.state = State::Ready {
                    info,
                    rf: RfMode::Configured {
                        protocol,
                        timer: ReaderTimer::for_rf_timeout(timeout),
                    },
                    response_timeout,
                };
                Ok(Some(TypeBSelection::IsoDep(TypeBCard {
                    target: TypeBTarget {
                        reader: self,
                        number: *target,
                        observation,
                        profile: options.profile,
                    },
                    session,
                })))
            }
            _ => Err(Error::Response("NFC-B target count/layout")),
        }
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

    fn prepare_type_a_exchange(
        &mut self,
        timeout: ResponseTimeout,
    ) -> Result<(), TypeAExchangeError<T::Error>> {
        if !matches!(
            self.state,
            State::Ready {
                rf: RfMode::Configured {
                    protocol: RfProtocol::TypeA,
                    ..
                },
                ..
            }
        ) {
            return Err(TypeAExchangeError::SessionInvalid);
        }
        self.prepare_exchange_timing(RfProtocol::TypeA, timeout)
            .map_err(TypeAExchangeError::Preparation)
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

/// Failure of one NFC-A card command, classified by its application effect.
#[derive(Debug)]
pub enum TypeAExchangeError<E> {
    /// The supplied byte count is outside `1..=MAX_TYPE_A_COMMAND_BYTES`.
    InputLength(usize),
    /// The selection has already lost its operation authority.
    SessionInvalid,
    /// A raw exchange has a response fragment waiting to be collected.
    ResponsePending,
    /// The raw response exceeded the fragment budget. Reinitialize the reader.
    FragmentLimit,
    /// Reader timing setup failed before any card command was sent.
    Preparation(Error<E>),
    /// The card command transaction or its response failed. Consult the cause
    /// for transport progress; the command may have taken effect.
    Exchange(Error<E>),
}

impl<E: fmt::Debug> fmt::Display for TypeAExchangeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<E: error::Error + 'static> error::Error for TypeAExchangeError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Preparation(error) | Self::Exchange(error) => Some(error),
            Self::InputLength(_)
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
    /// Validated activation data for this selection.
    pub fn observation(&self) -> &nfca::Observation {
        &self.observation
    }
    /// Target identifier returned by the reader.
    pub fn target(&self) -> u8 {
        self.target
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
    ) -> Result<TargetResponse, TypeAExchangeError<T::Error>> {
        if data.is_empty() || data.len() > MAX_TYPE_A_COMMAND_BYTES {
            return Err(TypeAExchangeError::InputLength(data.len()));
        }
        let timeout = ResponseTimeout::for_request(self.timeout);
        self.reader.prepare_type_a_exchange(timeout)?;
        let response = self.reader.exchange_target(self.target, data, timeout);
        if match &response {
            Ok(reply) => reply.status & TYPE_A_MORE_INFORMATION != 0,
            Err(Error::RfStatus(status)) => status & TYPE_A_MORE_INFORMATION != 0,
            Err(Error::Response(_)) => true,
            Err(_) => false,
        } {
            self.reader.state = State::NeedsInitialization;
        }
        response.map_err(TypeAExchangeError::Exchange)
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
            match self.reader.prepare_type_a_exchange(timeout) {
                Ok(()) => {}
                Err(TypeAExchangeError::Preparation(error)) => {
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
                if response.status & TYPE_A_MORE_INFORMATION == 0 {
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
    ) -> Result<TargetResponse, TypeAExchangeError<T::Error>> {
        if data.is_empty() || data.len() > MAX_TYPE_A_COMMAND_BYTES {
            return Err(TypeAExchangeError::InputLength(data.len()));
        }
        match self.reader.state {
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Pending { .. }),
                ..
            } => {
                return Err(TypeAExchangeError::ResponsePending);
            }
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Idle),
                ..
            } => {}
            _ => self.reader.prepare_type_a_exchange(self.timeout)?,
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
    ) -> Result<Option<TargetResponse>, TypeAExchangeError<T::Error>> {
        let frames = match self.reader.state {
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Pending { frames }),
                ..
            } => frames,
            State::Ready { .. } => return Ok(None),
            State::NeedsInitialization => return Err(TypeAExchangeError::SessionInvalid),
        };
        if frames == MAX_TYPE_A_RESPONSE_FRAGMENTS {
            self.reader.state = State::NeedsInitialization;
            return Err(TypeAExchangeError::FragmentLimit);
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
    ) -> Result<TargetResponse, TypeAExchangeError<T::Error>> {
        let result = self.reader.exchange_target(self.target, data, self.timeout);
        match &result {
            Ok(response) => {
                let next = if response.status & TYPE_A_MORE_INFORMATION != 0 {
                    RawTypeAResponse::Pending { frames }
                } else {
                    RawTypeAResponse::Idle
                };
                self.set_response(next);
            }
            Err(Error::RfStatus(status))
                if frames == 1 && status & TYPE_A_MORE_INFORMATION == 0 => {}
            Err(_) => self.reader.state = State::NeedsInitialization,
        }
        result.map_err(TypeAExchangeError::Exchange)
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
        // The APDU guard requests at least 9896 ms, saturating 32/02 to its
        // 3280 ms step. A0 keeps its independent FWI/WTX wait; individual
        // blocks do not reprogram 1C.
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
    /// Send one target command through `40`. The reader's Type B command
    /// limit is 63 bytes. Card-specific command semantics belong to the caller.
    pub fn exchange(&mut self, data: &[u8]) -> Result<TargetResponse, Error<T::Error>> {
        if !(1..=63).contains(&data.len()) {
            return Err(Error::InputLength {
                maximum: 63,
                actual: data.len(),
            });
        }
        let protocol = RfProtocol::TypeB(self.target.profile);
        let timeout = ResponseTimeout::for_request(self.timeout);
        self.target
            .reader
            .prepare_exchange_timing(protocol, timeout)?;
        self.target
            .reader
            .exchange_target(self.target.number, data, timeout)
    }
}

/// Selected card identity whose operation authority is tied to one reader borrow.
#[derive(Debug)]
pub struct FelicaCard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    observation: PollResponse,
    target: u8,
    timeout: RfTimeout,
}
impl<'a, T: Transport> FelicaCard<'a, T> {
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
        let request = felica::read_without_encryption(self.observation.idm, service, blocks)?;
        let response = self
            .reader
            .exchange_rf(&request, self.timeout, RfProtocol::Felica)?;
        Ok(ReadResponse::parse(
            &response,
            self.observation.idm,
            blocks.len(),
        )?)
    }

    /// Write blocks to one service with Write Without Encryption. Card-specific
    /// limits still apply. A failure after sending can leave the write outcome
    /// uncertain. Inspect card status or transport progress before retrying.
    pub fn write_without_encryption(
        &mut self,
        service: u16,
        blocks: &[BlockWrite],
    ) -> Result<(), Error<T::Error>> {
        let idm = self.observation.idm;
        let request = felica::write_without_encryption(idm, service, blocks)?;
        let response = self
            .reader
            .exchange_rf(&request, self.timeout, RfProtocol::Felica)?;
        Ok(felica::write_response(&response, idm)?)
    }

    /// Request the system codes exposed by this card. Card products can omit this command.
    pub fn request_system_codes(&mut self) -> Result<Vec<u16>, Error<T::Error>> {
        let idm = self.observation.idm;
        let response = self.exchange_addressed(0x0c, &[])?;
        Ok(felica::system_codes(&response, idm)?)
    }

    /// Look up one service or area index within the selected system.
    /// The end-of-list marker returns `None`; an RF failure remains an error.
    pub fn search_service_code(
        &mut self,
        index: u16,
    ) -> Result<Option<ServiceEntry>, Error<T::Error>> {
        let idm = self.observation.idm;
        let response = self.exchange_addressed(0x0a, &index.to_le_bytes())?;
        Ok(felica::service_entry(&response, idm)?)
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
        Ok(felica::addressed_response(&response, idm, response_code)?.to_vec())
    }

    fn exchange_addressed(&mut self, command: u8, data: &[u8]) -> Result<Vec<u8>, Error<T::Error>> {
        let request = felica::addressed_command(self.observation.idm, command, data)?;
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
        felica::validate_length(packet, 2)?;
        let response = self
            .reader
            .exchange_rf(packet, self.timeout, RfProtocol::Felica)?;
        felica::validate_length(&response, 2)?;
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
        assert!(matches!(ConfigImage::parse(e),Ok(c) if c.model()==0x0131));
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
