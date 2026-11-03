//! Reader configuration and lifetime-bound NFC card access.
#![forbid(unsafe_code)]

use crate::{
    felica::{self, CardError, PollRequest, PollResponse, ReadResponse},
    isodep, nfca, nfcb,
    transport::{Link, TransactionError, Transport},
};
use std::{fmt, thread, time::Duration};

/// Failures of reader initialization, RF configuration, or card exchange.
#[derive(Debug)]
pub enum Error {
    /// Host transport transaction failed; the stream must be reinitialized.
    Transaction(TransactionError),
    /// Recovery failed, preserving the phase of its out-of-band ACK transfer.
    Recovery(TransactionError),
    /// Reader initialization has not completed for this connection.
    NotInitialized,
    /// A command response did not have the required layout.
    Response(&'static str),
    /// A configuration checksum/signature failed.
    Configuration(&'static str),
    /// Register write returned an error value.
    RegisterStatus(u8),
    /// Raw RF status and its command-specific classification.
    RfStatus(u8),
    /// Card-level response validation failed.
    Card(CardError),
    /// The requested RF wait cannot be encoded as nonzero half-ms ticks.
    TimeoutRange,
    /// NFC-A activation data failed validation.
    TypeA(nfca::Error),
    /// NFC-B activation data failed validation.
    TypeB(nfcb::Error),
    /// ATQB advertises a protocol type other than the supported ISO-DEP type 1.
    TypeBProtocol(u8),
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
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<CardError> for Error {
    fn from(e: CardError) -> Self {
        Self::Card(e)
    }
}

/// Positive RF timeout with a checked conversion to RC-S956 wire ticks.
#[derive(Debug, Clone, Copy)]
pub struct RfTimeout {
    ticks: u16,
}
impl RfTimeout {
    /// Round a positive duration up to half-ms ticks. Rejects more than 65535 ticks.
    pub fn new(duration: Duration) -> Result<Self, Error> {
        let ticks = duration.as_nanos().div_ceil(500_000);
        if ticks == 0 {
            return Err(Error::TimeoutRange);
        }
        Ok(Self {
            ticks: u16::try_from(ticks).map_err(|_| Error::TimeoutRange)?,
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

/// Immutable, validated configuration read from one attached reader.
#[derive(Debug, Clone)]
pub struct ConfigImage {
    bytes: [u8; 256],
    model: u16,
}
impl ConfigImage {
    /// Check the signature, three defined checksum ranges, and model class.
    /// Bytes C0..FF are not covered by those checksums.
    pub fn parse(bytes: [u8; 256]) -> Result<Self, Error> {
        if bytes[..2] != [0x55, 0xaa] {
            return Err(Error::Configuration("signature"));
        }
        for (range, name) in [
            (0..16, "checksum 00..0F"),
            (16..64, "checksum 10..3F"),
            (64..192, "checksum 40..BF"),
        ] {
            if bytes[range].iter().fold(0u8, |s, b| s.wrapping_add(*b)) != 0 {
                return Err(Error::Configuration(name));
            }
        }
        if !matches!(bytes[253], 1 | 2) {
            return Err(Error::Configuration("unsupported model class"));
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
            RfProtocol::TypeB => {
                let mut analog = vec![
                    0x0a,
                    self.bytes[0xc0],
                    self.bytes[0x23],
                    self.bytes[0xc1],
                    self.bytes[0x24],
                    self.bytes[0xc2],
                    self.bytes[0x25],
                ];
                analog.extend_from_slice(&self.bytes[0x16..=0x1a]);
                vec![
                    analog,
                    vec![0x0c, self.bytes[0x23], self.bytes[0x24], self.bytes[0x25]],
                ]
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

/// The reader-managed target command uses a separate, quantized RF wait.
/// Each variant fixes both a 32/02 selector and its effective milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum TargetTimeout {
    Ms51 = 51,
    Ms102 = 102,
    Ms204 = 204,
    Ms409 = 409,
    Ms819 = 819,
    Ms1640 = 1640,
    Ms3280 = 3280,
}
impl TargetTimeout {
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
    TypeB,
}

#[derive(Debug, Clone, Copy)]
enum RfMode {
    Off,
    Configured {
        protocol: RfProtocol,
        timer: ReaderTimer,
    },
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
        target_timeout: Option<TargetTimeout>,
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

    fn command(&mut self, cc: u8, args: &[u8], wait: Duration) -> Result<Vec<u8>, Error> {
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
    pub fn initialize(&mut self) -> Result<ReaderInfo, Error> {
        self.state = State::NeedsInitialization;
        self.link.recover().map_err(Error::Recovery)?;
        let wait = Duration::from_secs(1);
        let reset = self.command(0x18, &[1], wait)?;
        if !reset.is_empty() {
            return Err(Error::Response("reset response"));
        }
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
        let configuration = ConfigImage::parse(config)?;
        let flags = self
            .command(0x0c, &[], wait)?
            .first()
            .copied()
            .ok_or(Error::Response("reader flags length"))?;
        self.write_register(0x630a, 0x40)?;
        self.command(0x32, &[1, 0], wait)?;
        thread::sleep(Duration::from_millis(5));
        let info = ReaderInfo {
            firmware,
            flags,
            configuration,
        };
        self.state = State::Ready {
            info: info.clone(),
            rf: RfMode::Off,
            target_timeout: None,
        };
        Ok(info)
    }

    fn write_register(&mut self, address: u16, value: u8) -> Result<(), Error> {
        let [hi, lo] = address.to_be_bytes();
        let reply = self.command(8, &[hi, lo, value], Duration::from_secs(1))?;
        match reply.as_slice() {
            [0] => Ok(()),
            [status] => Err(Error::RegisterStatus(*status)),
            _ => Err(Error::Response("register write length")),
        }
    }

    fn configure_rf(&mut self, protocol: RfProtocol, timeout: RfTimeout) -> Result<(), Error> {
        let timer = ReaderTimer::for_rf_timeout(timeout);
        let (info, apply_mode, target_timeout) = match &self.state {
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
                target_timeout,
            } => (
                info.clone(),
                !matches!(rf,
                RfMode::Configured { protocol: applied, .. } if *applied == protocol),
                *target_timeout,
            ),
            State::NeedsInitialization => return Err(Error::NotInitialized),
        };
        // Any partial configuration revokes the preceding published mode.
        self.state = State::NeedsInitialization;
        self.command(0x1c, &timer.args(), Duration::from_secs(1))?;
        if apply_mode {
            let (retry, timing) = match protocol {
                RfProtocol::Felica => (0, 0xb7),
                RfProtocol::TypeA | RfProtocol::TypeB => (4, 0x8f),
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
            target_timeout,
        };
        Ok(())
    }

    /// Select one FeliCa card at 212 kbps. The returned card exclusively borrows
    /// this reader, so its identity cannot survive a reset/mode change through it.
    /// Unsupported Polling request data may be absent and is preserved as such.
    pub fn poll_felica(
        &mut self,
        request: PollRequest,
        timeout: RfTimeout,
    ) -> Result<Option<FelicaCard<'_, T>>, Error> {
        self.configure_rf(RfProtocol::Felica, timeout)?;
        let poll = request.encode();
        let mut args = vec![1, 1];
        args.extend_from_slice(&poll[1..]);
        let response = self.command(0x4a, &args, timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, packet @ ..] => {
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
    pub fn poll_type_a(&mut self, timeout: RfTimeout) -> Result<Option<TypeACard<'_, T>>, Error> {
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

    /// Activate one NFC-B ISO-DEP target at 106 kbps, using the normal RF table
    /// and AFI wildcard. A card requiring another protocol is detected as an
    /// unsupported activation rather than granted ISO-DEP operation authority.
    pub fn poll_type_b(&mut self, timeout: RfTimeout) -> Result<Option<TypeBCard<'_, T>>, Error> {
        self.configure_rf(RfProtocol::TypeB, timeout)?;
        let response = self.command(0x4a, &[1, 3, 0, 1], timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, data @ ..] if *target != 0 => {
                let observation = nfcb::Observation::parse(data).map_err(Error::TypeB)?;
                if !observation.supports_iso_dep() {
                    return Err(Error::TypeBProtocol(observation.protocol_info()[1] & 0x0f));
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
                )
                .map_err(Error::IsoDepParameters)?;
                let (info, target_timeout) = match &self.state {
                    State::Ready {
                        info,
                        target_timeout,
                        ..
                    } => (info.clone(), *target_timeout),
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
                        protocol: RfProtocol::TypeB,
                        timer: ReaderTimer::for_rf_timeout(timeout),
                    },
                    target_timeout,
                };
                Ok(Some(TypeBCard {
                    reader: self,
                    observation,
                    target: *target,
                    session,
                }))
            }
            _ => Err(Error::Response("NFC-B target count/layout")),
        }
    }

    fn exchange_rf(
        &mut self,
        data: &[u8],
        timeout: RfTimeout,
        protocol: RfProtocol,
    ) -> Result<Vec<u8>, Error> {
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
        self.configure_rf(protocol, timeout)?;
        let mut args = Vec::with_capacity(data.len() + 2);
        args.extend_from_slice(&timeout.ticks.to_le_bytes());
        args.extend_from_slice(data);
        let response = self.command(0xa0, &args, timeout.host_wait())?;
        self.rf_response(response)
    }

    fn rf_response(&mut self, response: Vec<u8>) -> Result<Vec<u8>, Error> {
        match response.split_first() {
            Some((status, body)) if status & 0x3f == 0 => Ok(body.to_vec()),
            Some((status, _)) => {
                if status & 0x3f == 0x0d {
                    self.state = State::NeedsInitialization;
                }
                if status & 0x3f == 0x0b {
                    // Settle this RF error before the caller can issue another
                    // exchange; returning the error alone does not impose a gap.
                    thread::sleep(Duration::from_millis(10));
                }
                Err(Error::RfStatus(*status))
            }
            None => Err(Error::Response("missing RF status")),
        }
    }

    /// Disable RF and invalidate the configured mode. Call explicitly to observe
    /// failure; dropping a reader only releases the backend's OS resources.
    pub fn rf_off(&mut self) -> Result<(), Error> {
        let (info, target_timeout) = match &self.state {
            State::Ready {
                info,
                target_timeout,
                ..
            } => (info.clone(), *target_timeout),
            State::NeedsInitialization => return Err(Error::NotInitialized),
        };
        self.state = State::NeedsInitialization;
        self.command(0x32, &[1, 0], Duration::from_secs(1))?;
        thread::sleep(Duration::from_millis(5));
        self.state = State::Ready {
            info,
            rf: RfMode::Off,
            target_timeout,
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

/// NFC-A selection tied to one exclusive reader borrow.
#[derive(Debug)]
pub struct TypeACard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    observation: nfca::Observation,
    target: u8,
    timeout: RfTimeout,
}
impl<T: Transport> TypeACard<'_, T> {
    /// Validated activation data for this selection.
    pub fn observation(&self) -> &nfca::Observation {
        &self.observation
    }
    /// Target identifier returned by the reader.
    pub fn target(&self) -> u8 {
        self.target
    }
    /// Exchange up to 262 card-command bytes through reader command 40. Card
    /// command semantics belong to the caller; no application request is replayed.
    /// The complete status is preserved rather than assuming another controller's
    /// upper status bits imply an automatic continuation.
    /// The requested RF wait is rounded upward to a 32/02 timing step, capped
    /// at 3280 ms. The reader timer uses that effective wait; host waiting adds 1 s.
    pub fn exchange(&mut self, data: &[u8]) -> Result<TargetResponse, Error> {
        if data.is_empty() || data.len() > 262 {
            return Err(Error::InputLength {
                maximum: 262,
                actual: data.len(),
            });
        }
        if !matches!(
            self.reader.state,
            State::Ready {
                rf: RfMode::Configured {
                    protocol: RfProtocol::TypeA,
                    ..
                },
                ..
            }
        ) {
            return Err(Error::NotInitialized);
        }
        let mut args = Vec::with_capacity(data.len() + 1);
        args.push(self.target);
        args.extend_from_slice(data);
        let timeout = TargetTimeout::for_request(self.timeout);
        self.reader.prepare_target_exchange(timeout)?;
        let response = self.reader.command(0x40, &args, timeout.host_wait())?;
        let status = response
            .first()
            .copied()
            .ok_or(Error::Response("missing RF status"))?;
        let data = self.reader.rf_response(response)?;
        Ok(TargetResponse { status, data })
    }
}

/// NFC-B ISO-DEP selection, with a block-number state that cannot outlive the
/// reader selection. Protocol failure poisons the session; it never replays APDUs.
#[derive(Debug)]
pub struct TypeBCard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    observation: nfcb::Observation,
    target: u8,
    session: isodep::Session,
}
impl<T: Transport> TypeBCard<'_, T> {
    /// Validated activation data, including ATQB and negotiated CID.
    pub fn observation(&self) -> &nfcb::Observation {
        &self.observation
    }
    /// Target identifier returned by the reader.
    pub fn target(&self) -> u8 {
        self.target
    }
    /// Exchange one APDU, handling ISO-DEP chaining, R-blocks and bounded WTX.
    /// Errors retain partial progress. Application APDUs are never retried.
    pub fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, isodep::Error<Error>> {
        let reader = &mut self.reader;
        self.session.exchange(apdu, |block, wait| {
            let timeout = RfTimeout::new(wait)?;
            reader.exchange_rf(block, timeout, RfProtocol::TypeB)
        })
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
impl<T: Transport> FelicaCard<'_, T> {
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
    ) -> Result<ReadResponse, Error> {
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
            Err(Error::Configuration("checksum 40..BF"))
        ));
    }

    #[test]
    fn reader_timer_wire_values_cover_second_boundaries() -> Result<(), Error> {
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
    fn target_timeout_vectors_cover_quantization_and_saturation() -> Result<(), Error> {
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
                TargetTimeout::for_request(RfTimeout::new(Duration::from_micros(microseconds))?);
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
