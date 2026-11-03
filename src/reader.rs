//! Reader configuration and lifetime-bound FeliCa card access.
#![forbid(unsafe_code)]

use crate::{
    felica::{self, CardError, PollRequest, PollResponse, ReadResponse},
    transport::{Link, TransactionError, Transport},
};
use std::{fmt, thread, time::Duration};

/// Failures of reader initialization, RF configuration, or card exchange.
#[derive(Debug)]
pub enum Error {
    /// Host transport transaction failed; the stream must be reinitialized.
    Transaction(TransactionError),
    /// Explicit transport recovery failed before initialization.
    Recovery(std::io::Error),
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
    fn felica_config(&self) -> [u8; 9] {
        let mut out = [0u8; 9];
        out[0] = 0x0b;
        out[1..].copy_from_slice(&self.bytes[0x1b..=0x22]);
        out
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

/// A published FeliCa mode always carries its successfully applied timer.
#[derive(Debug, Clone, Copy)]
enum RfMode {
    Off,
    Felica(ReaderTimer),
}

#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded configuration snapshot belongs to the reader state; inline storage avoids a separate session allocation"
)]
enum State {
    NeedsInitialization,
    Ready { info: ReaderInfo, rf: RfMode },
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
        thread::sleep(Duration::from_millis(10));
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

    fn configure_felica(&mut self, timeout: RfTimeout) -> Result<(), Error> {
        let timer = ReaderTimer::for_rf_timeout(timeout);
        let (info, apply_mode) = match &self.state {
            State::Ready {
                rf: RfMode::Felica(applied),
                ..
            } if *applied == timer => return Ok(()),
            State::Ready { info, rf } => (info.clone(), matches!(rf, RfMode::Off)),
            State::NeedsInitialization => return Err(Error::NotInitialized),
        };
        // A partially applied timer/mode is not the preceding published mode.
        self.state = State::NeedsInitialization;
        self.command(0x1c, &timer.args(), Duration::from_secs(1))?;
        if apply_mode {
            self.command(0x32, &[5, 0, 0, 0], Duration::from_secs(1))?;
            self.command(0x32, &[0x81, 0xb7], Duration::from_secs(1))?;
            self.command(
                0x32,
                &info.configuration.felica_config(),
                Duration::from_secs(1),
            )?;
            self.write_register(0x630d, 0)?;
        }
        self.state = State::Ready {
            info,
            rf: RfMode::Felica(timer),
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
        self.configure_felica(timeout)?;
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

    fn exchange(&mut self, data: &[u8], timeout: RfTimeout) -> Result<Vec<u8>, Error> {
        if !matches!(self.state, State::Ready { .. }) {
            return Err(Error::NotInitialized);
        }
        if data.len() > 255 {
            return Err(Error::Response("RF input exceeds 255 bytes"));
        }
        self.configure_felica(timeout)?;
        let mut args = Vec::with_capacity(data.len() + 2);
        args.extend_from_slice(&timeout.ticks.to_le_bytes());
        args.extend_from_slice(data);
        let response = self.command(0xa0, &args, timeout.host_wait())?;
        match response.split_first() {
            Some((status, body)) if status & 0x3f == 0 => Ok(body.to_vec()),
            Some((status, _)) => {
                if status & 0x3f == 0x0d {
                    self.state = State::NeedsInitialization;
                }
                Err(Error::RfStatus(*status))
            }
            None => Err(Error::Response("missing RF status")),
        }
    }

    /// Disable RF and invalidate the configured mode. Call explicitly to observe
    /// failure; dropping a reader only releases the backend's OS resources.
    pub fn rf_off(&mut self) -> Result<(), Error> {
        let info = match &self.state {
            State::Ready { info, .. } => info.clone(),
            State::NeedsInitialization => return Err(Error::NotInitialized),
        };
        self.state = State::NeedsInitialization;
        self.command(0x32, &[1, 0], Duration::from_secs(1))?;
        thread::sleep(Duration::from_millis(5));
        self.state = State::Ready {
            info,
            rf: RfMode::Off,
        };
        Ok(())
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
        let response = self.reader.exchange(&request, self.timeout)?;
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
}
