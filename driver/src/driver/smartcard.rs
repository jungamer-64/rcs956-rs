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
    pcsc::{self, Command, State},
    queue::{Queues, Request},
    status::{self, Status},
    usb::UsbTransport,
    worker::Control,
};

const SCAN_PERIOD: Duration = Duration::from_millis(200);
const SCAN_WAIT: Duration = Duration::from_millis(100);
const INIT_BUDGET: Duration = Duration::from_secs(6);
const EXCHANGE_BUDGET: Duration = Duration::from_secs(10);

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
            super::trace(format_args!("RF shutdown: {error}"));
        }
    }
}

struct Service {
    queues: Queues,
    unit: u32,
    control: Rc<Control>,
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
    fn atr(&self) -> Option<Vec<u8>> {
        match self {
            Self::A(card) => card.observation().ats().and_then(pcsc::atr_a),
            Self::B(card) => Some(pcsc::atr_b(card.observation())),
        }
    }

    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>, isodep::Error<ReaderError<Status>>> {
        match self {
            Self::A(card) => card.exchange_apdu(apdu),
            Self::B(card) => card.exchange_apdu(apdu),
        }
    }
}

struct Reset {
    request: Request,
    output_capacity: usize,
}

enum Next {
    Scan,
    Reset(Reset),
    PowerDown(Request),
    Invalidated,
    Stop,
}

impl Service {
    fn initialize(&self, reader: &mut Reader<UsbTransport>) -> Result<(), Status> {
        self.control.bound(INIT_BUDGET);
        reader.initialize().map(|_| ()).map_err(reader_status)
    }

    fn run(&self, reader: &mut Reader<UsbTransport>) {
        let Ok(timeout) = RfTimeout::new(SCAN_WAIT) else {
            return;
        };
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
            let next = match select(reader, technology, timeout) {
                Ok(Some(card)) => match card.atr() {
                    Some(atr) => {
                        self.queues.signal(true);
                        self.selected(card, &atr, reset.take())
                    }
                    None => {
                        self.no_card(&mut reset);
                        technology = technology.alternate();
                        Next::Scan
                    }
                },
                Ok(None) => {
                    self.no_card(&mut reset);
                    technology = technology.alternate();
                    Next::Scan
                }
                Err(error) => {
                    let error = reader_status(error);
                    if let Some(reset) = reset.take() {
                        reset.request.fail(error);
                    }
                    self.queues.fail_watches(error);
                    self.without_card(Some(error));
                    Next::Invalidated
                }
            };
            if matches!(next, Next::Stop) {
                break;
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
                Next::Invalidated => ready = false,
                Next::Scan | Next::Stop => {}
            }
        }
        if let Some(reset) = reset {
            reset.request.fail(Status(status::CANCELLED));
        }
    }

    fn no_card(&self, reset: &mut Option<Reset>) {
        if let Some(reset) = reset.take() {
            reset.request.fail(Status(status::NO_MEDIA));
        }
        self.queues.signal(false);
        self.without_card(None);
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
            let result =
                self.common(&command, State::Absent, None)
                    .unwrap_or_else(|| match command {
                        Command::PowerDown => Ok(Vec::new()),
                        _ => Err(failure.unwrap_or(Status(status::NO_MEDIA))),
                    });
            let result = match (&command, failure) {
                (Command::GetState, Some(error)) => Err(error),
                _ => result,
            };
            complete(request, result);
        }
    }

    fn selected(&self, mut card: Card<'_>, atr: &[u8], reset: Option<Reset>) -> Next {
        let mut phase = match reset {
            Some(reset) if reset.output_capacity >= atr.len() => {
                reset.request.reply(atr);
                State::Negotiable
            }
            Some(reset) => {
                reset.request.fail(Status(status::BUFFER_TOO_SMALL));
                State::Detected
            }
            None => State::Detected,
        };
        let refresh = Instant::now() + SCAN_PERIOD;
        while !self.control.stopping() {
            if phase == State::Detected && Instant::now() >= refresh {
                return Next::Scan;
            }
            let Some(request) = self.queues.pop() else {
                if phase == State::Detected {
                    thread::park_timeout(refresh.saturating_duration_since(Instant::now()));
                } else {
                    thread::park();
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
            if let Some(result) = self.common(&command, phase, Some(atr)) {
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
                Command::SelectT1 if phase == State::Detected => {
                    request.fail(Status(status::INVALID_DEVICE_STATE))
                }
                Command::SelectT1 if output < 4 => request.fail(Status(status::BUFFER_TOO_SMALL)),
                Command::SelectT1 => {
                    phase = State::Specific;
                    request.reply(&pcsc::t1());
                }
                Command::Transmit(_) if phase != State::Specific => {
                    request.fail(Status(status::INVALID_DEVICE_STATE))
                }
                Command::Transmit(_) if output < pcsc::PCI_BYTES + 2 => {
                    request.fail(Status(status::BUFFER_TOO_SMALL))
                }
                Command::Transmit(apdu) => {
                    self.control.bound(EXCHANGE_BUDGET);
                    match card.exchange(apdu) {
                        Ok(data) if data.len() >= 2 => request.reply(&pcsc::transmit_reply(&data)),
                        Ok(_) => {
                            request.fail(Status(status::DEVICE_PROTOCOL_ERROR));
                            return Next::Invalidated;
                        }
                        Err(error) => {
                            let invalidates =
                                !matches!(error.cause, isodep::Cause::InputLength { .. });
                            request.fail(apdu_status(error));
                            if invalidates {
                                return Next::Invalidated;
                            }
                        }
                    }
                }
                _ => request.fail(Status(status::INVALID_DEVICE_REQUEST)),
            }
        }
        Next::Stop
    }

    fn common(
        &self,
        command: &Command<'_>,
        phase: State,
        atr: Option<&[u8]>,
    ) -> Option<Result<Vec<u8>, Status>> {
        match *command {
            Command::GetState => Some(Ok(phase.value().to_le_bytes().to_vec())),
            Command::Attribute(tag) => Some(pcsc::read_attribute(tag, phase, atr, self.unit)),
            Command::DeviceInUse | Command::Features => Some(Ok(Vec::new())),
            _ => None,
        }
    }
}

fn select(
    reader: &mut Reader<UsbTransport>,
    technology: Technology,
    timeout: RfTimeout,
) -> Result<Option<Card<'_>>, ReaderError<Status>> {
    match technology {
        Technology::A => reader.poll_type_a(timeout).map(|selected| {
            selected
                .filter(|card| card.observation().supports_iso_dep())
                .map(Card::A)
        }),
        Technology::B => reader
            .poll_type_b(Default::default(), timeout)
            .map(|selected| match selected {
                Some(TypeBSelection::IsoDep(card)) => Some(Card::B(card)),
                _ => None,
            }),
    }
}

fn complete(request: Request, result: Result<Vec<u8>, Status>) {
    match result {
        Ok(data) => request.reply(&data),
        Err(error) => request.fail(error),
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
        isodep::Cause::InputLength { .. } => Status(status::INVALID_PARAMETER),
        isodep::Cause::Deselected => Status(status::NO_MEDIA),
        isodep::Cause::Preparation(error)
        | isodep::Cause::Transport(error)
        | isodep::Cause::RecoveryExhausted(error) => reader_status(error),
        _ => Status(status::DEVICE_PROTOCOL_ERROR),
    }
}
