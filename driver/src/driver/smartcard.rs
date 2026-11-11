use std::{
    rc::Rc,
    thread,
    time::{Duration, Instant},
};

use rcs956::{
    isodep,
    reader::{Error as ReaderError, Reader, RfTimeout, TypeACard, TypeBCard, TypeBSelection},
    transport::Failure,
};

use super::{
    pcsc::{self, Command, Icc, Power, Slot},
    queue::{Queues, Request},
    status::{self, Status},
    usb::UsbTransport,
    worker::Control,
};

const SCAN_PERIOD: Duration = Duration::from_millis(200);
const SCAN_WAIT: Duration = Duration::from_millis(100);
/// NFC-A APDU response wait: the largest `32/02` step, so that card
/// processing is bounded by the reader's ISO-DEP handling rather than by the
/// short polling wait.
const APDU_WAIT: Duration = Duration::from_millis(3280);
/// Card silence after which a powered card is probed. Every completed
/// exchange or probe restarts it.
const PRESENCE_PERIOD: Duration = Duration::from_secs(2);
const INIT_BUDGET: Duration = Duration::from_secs(6);

pub(crate) struct Frontend {
    service: Service,
    reader: Reader<UsbTransport>,
}

impl Frontend {
    pub(crate) fn new(
        transport: UsbTransport,
        queues: Queues,
        unit: u32,
        control: Rc<Control>,
    ) -> Result<Self, Status> {
        let service = Service {
            queues,
            unit,
            control,
            scan: RfTimeout::new(SCAN_WAIT)
                .map_err(|_| Status(status::DEVICE_CONFIGURATION_ERROR))?,
            apdu: RfTimeout::new(APDU_WAIT)
                .map_err(|_| Status(status::DEVICE_CONFIGURATION_ERROR))?,
        };
        let mut reader = Reader::new(transport);
        service.initialize(&mut reader)?;
        Ok(Self { service, reader })
    }

    pub(crate) fn run(&mut self) {
        self.service.run(&mut self.reader);
    }

    pub(crate) fn shutdown(&mut self) {
        self.service.control.bound(Duration::from_secs(1));
        // RF off is best-effort during D0 exit. PnP releases the USB target.
        if let Err(error) = self.reader.rf_off() {
            super::trace(format_args!("RF shutdown: {}", super::Chain(&error)));
        }
    }
}

struct Service {
    queues: Queues,
    unit: u32,
    control: Rc<Control>,
    scan: RfTimeout,
    apdu: RfTimeout,
}

#[derive(Clone, Copy)]
enum Technology {
    A,
    B,
}

impl Technology {
    fn alternate(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

enum Card<'a> {
    A(TypeACard<'a, UsbTransport>),
    B(TypeBCard<'a, UsbTransport>),
}

impl Card<'_> {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>, isodep::Error<ReaderError<Status>>> {
        match self {
            Self::A(card) => card.exchange_apdu(apdu),
            Self::B(card) => card.exchange_apdu(apdu),
        }
    }

    /// `None` when the selection offers no probe that leaves the card's
    /// protocol state unchanged. The reader firmware owns NFC-A ISO-DEP
    /// blocks, so only NFC-B sessions are probed.
    fn check_presence(&mut self) -> Option<Result<(), isodep::PresenceError<ReaderError<Status>>>> {
        match self {
            Self::A(_) => None,
            Self::B(card) => Some(card.check_presence()),
        }
    }
}

struct Reset {
    request: Request,
    output_capacity: usize,
}

/// How a selection ended, and what the resource manager must observe.
enum Next {
    /// Re-select an unpowered card to observe its continued presence.
    Rescan,
    /// The resource manager requested a reset; reply with the next ATR.
    Reset(Reset),
    /// The resource manager requested power down.
    PowerDown(Request),
    /// The powered card session was lost. Its protocol state cannot be
    /// recovered, so the resource manager observes a removal.
    Departed,
    /// Selection failed in the reader; reinitialize before scanning.
    ReaderFault,
    Stop,
}

impl Service {
    fn initialize(&self, reader: &mut Reader<UsbTransport>) -> Result<(), Status> {
        self.control.bound(INIT_BUDGET);
        reader.initialize().map(|_| ()).map_err(reader_status)
    }

    fn run(&self, reader: &mut Reader<UsbTransport>) {
        let mut technology = Technology::A;
        let mut reset = None;
        let mut ready = true;
        while !self.control.stopping() {
            if !ready {
                match self.initialize(reader) {
                    Ok(()) => ready = true,
                    Err(error) => {
                        self.queues.fail_watches(error);
                        self.without_card(Some(error));
                        continue;
                    }
                }
            }
            self.control.bound(INIT_BUDGET);
            let next = match select(reader, technology, self.scan, self.apdu) {
                Ok(Some((card, icc))) => {
                    self.queues.signal(true);
                    self.selected(card, &icc, reset.take())
                }
                Ok(None) => {
                    if let Some(reset) = reset.take() {
                        reset.request.fail(Status(status::NO_MEDIA));
                    }
                    self.queues.signal(false);
                    self.without_card(None);
                    technology = technology.alternate();
                    Next::Rescan
                }
                Err(error) => {
                    let error = reader_status(error);
                    if let Some(reset) = reset.take() {
                        reset.request.fail(error);
                    }
                    self.queues.fail_watches(error);
                    self.without_card(Some(error));
                    Next::ReaderFault
                }
            };
            if matches!(next, Next::Stop) {
                break;
            }
            if matches!(next, Next::Departed) {
                self.queues.signal(false);
            }
            self.control.bound(Duration::from_secs(1));
            let field = reader.rf_off().map_err(reader_status);
            ready &= field.is_ok();
            match next {
                Next::Reset(pending) => match field {
                    Ok(()) => reset = Some(pending),
                    Err(error) => pending.request.fail(error),
                },
                Next::PowerDown(request) => complete(request, field.map(|()| Vec::new())),
                Next::ReaderFault => ready = false,
                Next::Rescan | Next::Departed | Next::Stop => {}
            }
        }
        if let Some(reset) = reset {
            reset.request.fail(Status(status::CANCELLED));
        }
    }

    fn without_card(&self, failure: Option<Status>) {
        let until = Instant::now() + SCAN_PERIOD;
        while !self.control.stopping() && Instant::now() < until {
            let Some(request) = self.queues.pop() else {
                thread::park_timeout(until.saturating_duration_since(Instant::now()));
                continue;
            };
            let (code, input, _) = match request.decode() {
                Ok(decoded) => decoded,
                Err(error) => {
                    request.fail(error);
                    continue;
                }
            };
            let command = match pcsc::parse(code, &input) {
                Ok(command) => command,
                Err(error) => {
                    request.fail(error);
                    continue;
                }
            };
            if let Command::Presence(present) = command {
                match (failure, present) {
                    (Some(error), _) => request.fail(error),
                    (None, true) => self.queues.watch(request, true),
                    (None, false) => request.reply(&[]),
                }
                continue;
            }
            let result = match (&command, failure) {
                (Command::GetState, Some(error)) => Err(error),
                _ => self
                    .common(&command, Slot::Empty)
                    .unwrap_or_else(|| match command {
                        Command::PowerDown => Ok(Vec::new()),
                        _ => Err(failure.unwrap_or(Status(status::NO_MEDIA))),
                    }),
            };
            complete(request, result);
        }
    }

    fn selected(&self, mut card: Card<'_>, icc: &Icc, reset: Option<Reset>) -> Next {
        let atr = icc.atr();
        let mut power = match reset {
            Some(reset) if reset.output_capacity >= atr.len() => {
                reset.request.reply(atr);
                Power::Negotiable
            }
            Some(reset) => {
                reset.request.fail(Status(status::BUFFER_TOO_SMALL));
                Power::Unpowered
            }
            None => Power::Unpowered,
        };
        // An unpowered card is re-selected; a powered one is probed instead,
        // because selection would discard its protocol state.
        let rescan = Instant::now() + SCAN_PERIOD;
        let mut probe = Some(Instant::now() + PRESENCE_PERIOD);
        while !self.control.stopping() {
            let deadline = match power {
                Power::Unpowered => Some(rescan),
                Power::Negotiable | Power::Specific => probe,
            };
            if let Some(deadline) = deadline
                && Instant::now() >= deadline
            {
                if power == Power::Unpowered {
                    return Next::Rescan;
                }
                self.control.unbound();
                match card.check_presence() {
                    None => probe = None,
                    Some(Ok(())) => probe = Some(Instant::now() + PRESENCE_PERIOD),
                    Some(Err(error)) => {
                        super::trace(format_args!("presence check: {}", super::Chain(&error)));
                        return Next::Departed;
                    }
                }
                continue;
            }
            let Some(request) = self.queues.pop() else {
                match deadline {
                    Some(deadline) => {
                        thread::park_timeout(deadline.saturating_duration_since(Instant::now()));
                    }
                    None => thread::park(),
                }
                continue;
            };
            let (code, input, output) = match request.decode() {
                Ok(decoded) => decoded,
                Err(error) => {
                    request.fail(error);
                    continue;
                }
            };
            let command = match pcsc::parse(code, &input) {
                Ok(command) => command,
                Err(error) => {
                    request.fail(error);
                    continue;
                }
            };
            if let Some(result) = self.common(&command, Slot::Occupied { icc, power }) {
                complete(request, result);
                continue;
            }
            match command {
                Command::Presence(true) => request.reply(&[]),
                Command::Presence(false) => self.queues.watch(request, false),
                Command::Swallow => request.reply(&[]),
                Command::Reset if output < atr.len() => {
                    request.fail(Status(status::BUFFER_TOO_SMALL))
                }
                Command::Reset => {
                    return Next::Reset(Reset {
                        request,
                        output_capacity: output,
                    });
                }
                Command::PowerDown => return Next::PowerDown(request),
                Command::SelectT1 if power == Power::Unpowered => {
                    request.fail(Status(status::INVALID_DEVICE_STATE))
                }
                Command::SelectT1 if output < 4 => request.fail(Status(status::BUFFER_TOO_SMALL)),
                Command::SelectT1 => {
                    power = Power::Specific;
                    request.reply(&pcsc::t1());
                }
                Command::Transmit(_) if power != Power::Specific => {
                    request.fail(Status(status::INVALID_DEVICE_STATE))
                }
                Command::Transmit(_) if output < pcsc::PCI_BYTES + 2 => {
                    request.fail(Status(status::BUFFER_TOO_SMALL))
                }
                Command::Transmit(apdu) => {
                    self.control.unbound();
                    match card.exchange(apdu) {
                        Ok(data) if data.len() >= 2 => {
                            request.reply(&pcsc::transmit_reply(&data));
                            // A complete response confirms presence.
                            probe = probe.map(|_| Instant::now() + PRESENCE_PERIOD);
                        }
                        Ok(_) => {
                            request.fail(Status(status::DEVICE_PROTOCOL_ERROR));
                            return Next::Departed;
                        }
                        Err(error) if rejected_before_rf(&error) => {
                            request.fail(Status(status::INVALID_PARAMETER));
                        }
                        Err(error) => {
                            request.fail(apdu_status(error));
                            return Next::Departed;
                        }
                    }
                }
                _ => request.fail(Status(status::INVALID_DEVICE_REQUEST)),
            }
        }
        Next::Stop
    }

    fn common(&self, command: &Command<'_>, slot: Slot<'_>) -> Option<Result<Vec<u8>, Status>> {
        match *command {
            Command::GetState => Some(Ok(pcsc::get_state(slot))),
            Command::Attribute(tag) => Some(pcsc::read_attribute(tag, slot, self.unit)),
            Command::DeviceInUse | Command::Features => Some(Ok(Vec::new())),
            _ => None,
        }
    }
}

/// Select one ISO-DEP card. Cards without ISO-DEP activation are outside
/// PC/SC mode and are reported like an empty field. NFC-B APDUs use the
/// session's own block waits; NFC-A APDUs use `apdu`.
fn select(
    reader: &mut Reader<UsbTransport>,
    technology: Technology,
    timeout: RfTimeout,
    apdu: RfTimeout,
) -> Result<Option<(Card<'_>, Icc)>, ReaderError<Status>> {
    Ok(match technology {
        Technology::A => reader.poll_type_a(timeout)?.and_then(|mut card| {
            let observation = card.observation();
            let ats = observation
                .ats()
                .filter(|_| observation.supports_iso_dep())?;
            let icc = Icc::type_a(ats, card.maximum_apdu_bytes());
            card.set_exchange_timeout(apdu);
            Some((Card::A(card), icc))
        }),
        Technology::B => match reader.poll_type_b(Default::default(), timeout)? {
            Some(TypeBSelection::IsoDep(card)) => {
                let icc = Icc::type_b(card.observation(), card.maximum_apdu_bytes());
                Some((Card::B(card), icc))
            }
            Some(TypeBSelection::Frame(_)) | None => None,
        },
    })
}

fn complete(request: Request, result: Result<Vec<u8>, Status>) {
    match result {
        Ok(data) => request.reply(&data),
        Err(error) => request.fail(error),
    }
}

/// The selection refused the APDU before any RF transfer and remains usable.
fn rejected_before_rf(error: &isodep::Error<ReaderError<Status>>) -> bool {
    match error.cause {
        isodep::Cause::InputLength { .. } => true,
        isodep::Cause::Budget(isodep::Budget::Frames) => error.progress.frames == 0,
        _ => false,
    }
}

fn reader_status(error: ReaderError<Status>) -> Status {
    match error {
        ReaderError::Transaction(error) | ReaderError::Recovery(error) => match error.failure {
            Failure::Io(status) => status,
            Failure::Deadline => Status(status::IO_TIMEOUT),
            _ => Status(status::DEVICE_PROTOCOL_ERROR),
        },
        ReaderError::RfStatus(value) if value & 0x3f == 1 => Status(status::IO_TIMEOUT),
        ReaderError::NotInitialized => Status(status::DEVICE_NOT_READY),
        _ => Status(status::DEVICE_PROTOCOL_ERROR),
    }
}

fn apdu_status(error: isodep::Error<ReaderError<Status>>) -> Status {
    match error.cause {
        isodep::Cause::Deselected => Status(status::NO_MEDIA),
        isodep::Cause::Preparation(error)
        | isodep::Cause::Transport(error)
        | isodep::Cause::RecoveryExhausted(error) => reader_status(error),
        _ => Status(status::DEVICE_PROTOCOL_ERROR),
    }
}
