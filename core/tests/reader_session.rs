//! Reader-level wire scenarios with independent response construction.
//!
//! These model command/response contracts, not physical device operation.

use rcs956_core::{
    felica::{BitRate, BlockWrite, CardError, Idm, PollRequest, ServiceEntry},
    isodep,
    reader::{
        ConfigurationError, Error as ReaderError, Reader, RfTimeout, TimeoutRange,
        TypeAExchangeError,
    },
    transport::{Progress, TransactionError, Transport},
    wire::{self, Direction, Frame},
};
use std::{cell::RefCell, collections::VecDeque, error::Error, io, rc::Rc, time::Duration};

const IDENTITY: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const PARAMETERS: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

#[derive(Clone, Debug, Eq, PartialEq)]
enum Request {
    Command(u8, Vec<u8>),
    HostAck,
}

#[derive(Debug)]
enum Answer {
    Data(Vec<u8>),
    LostAfterAck,
}

#[derive(Debug)]
struct Step {
    request: Request,
    answer: Answer,
}

fn command(cc: u8, args: &[u8], data: &[u8]) -> Step {
    Step {
        request: Request::Command(cc, args.to_vec()),
        answer: Answer::Data(data.to_vec()),
    }
}

#[derive(Debug)]
enum Input {
    Bytes(Vec<u8>),
    Timeout,
}

#[derive(Debug)]
struct Journal {
    requests: Vec<Request>,
    request_times: Vec<Duration>,
    last_read_completed: Option<Duration>,
    remaining: usize,
    recoveries: usize,
}

#[derive(Debug)]
struct Script {
    steps: VecDeque<Step>,
    input: VecDeque<Input>,
    journal: Rc<RefCell<Journal>>,
    elapsed: Duration,
}

impl Script {
    fn new(steps: Vec<Step>) -> (Self, Rc<RefCell<Journal>>) {
        let journal = Rc::new(RefCell::new(Journal {
            requests: Vec::new(),
            request_times: Vec::new(),
            last_read_completed: None,
            remaining: steps.len(),
            recoveries: 0,
        }));
        (
            Self {
                steps: steps.into(),
                input: VecDeque::new(),
                journal: Rc::clone(&journal),
                elapsed: Duration::ZERO,
            },
            journal,
        )
    }
}

// Independent normal-frame oracle. Reader test packets are at most 66 payload
// bytes; the production encoder is deliberately not used to construct responses.
fn reader_response(cc: u8, data: &[u8]) -> io::Result<Vec<u8>> {
    let length = u8::try_from(data.len() + 2)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut bytes = vec![0, 0, 0xff, length, length.wrapping_neg(), 0xd5, cc];
    bytes.extend_from_slice(data);
    let checksum = data
        .iter()
        .fold(0xd5_u8.wrapping_add(cc), |sum, byte| {
            sum.wrapping_add(*byte)
        })
        .wrapping_neg();
    bytes.extend_from_slice(&[checksum, 0]);
    Ok(bytes)
}

impl Transport for Script {
    type Error = io::Error;

    fn monotonic_time(&self) -> Duration {
        self.elapsed
    }

    fn wait(&mut self, duration: Duration) {
        self.elapsed += duration;
    }

    fn write(&mut self, bytes: &[u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero());
        assert!(
            self.input.is_empty(),
            "new command before consuming the preceding reply"
        );
        let actual = match wire::parse(bytes, Direction::Host)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        {
            Frame::Ack => Request::HostAck,
            Frame::Data { command, data } => Request::Command(command, data.to_vec()),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected host frame {other:?}"),
                ));
            }
        };
        let step = self.steps.pop_front().ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected reader command")
        })?;
        assert_eq!(actual, step.request, "wire request order or arguments");
        self.journal.borrow_mut().requests.push(actual.clone());
        self.journal.borrow_mut().request_times.push(self.elapsed);
        self.journal.borrow_mut().remaining = self.steps.len();
        match actual {
            Request::HostAck => {}
            Request::Command(cc, _) => match step.answer {
                Answer::Data(data) => {
                    let response_cc = cc.checked_add(1).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "response command overflow")
                    })?;
                    self.input.push_back(Input::Bytes(
                        [wire::ACK.to_vec(), reader_response(response_cc, &data)?].concat(),
                    ));
                }
                Answer::LostAfterAck => {
                    self.input.push_back(Input::Bytes(wire::ACK.to_vec()));
                    self.input.push_back(Input::Timeout);
                }
            },
        }
        Ok(bytes.len())
    }

    fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero());
        match self.input.pop_front() {
            Some(Input::Bytes(bytes)) => {
                let output = buffer.get_mut(..bytes.len()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "response exceeds read capacity",
                    )
                })?;
                output.copy_from_slice(&bytes);
                self.journal.borrow_mut().last_read_completed = Some(self.elapsed);
                Ok(bytes.len())
            }
            Some(Input::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "scripted reader response loss",
            )),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read without a pending reader reply",
            )),
        }
    }

    fn recover(&mut self) -> io::Result<()> {
        self.input.clear();
        self.journal.borrow_mut().recoveries += 1;
        Ok(())
    }
}

fn config_image() -> [u8; 256] {
    let mut bytes = [0; 256];
    bytes[0] = 0x55;
    bytes[1] = 0xaa;
    bytes[2] = 1;
    bytes[0x1b..=0x22].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    bytes[0x3f] = 0xdc;
    bytes[0x40] = 0x11;
    bytes[0x41] = 0x22;
    bytes[0x80] = 0x33;
    bytes[0xbf] = 0x9a;
    bytes[0xfd] = 1;
    bytes[0xfe] = 0x31;
    bytes
}

fn bank_addresses(bank: u8) -> Vec<u8> {
    (0u8..64)
        .flat_map(|index| [0xa0, bank * 64 + index])
        .collect()
}

fn initialization(config: &[u8; 256]) -> Vec<Step> {
    let mut steps = vec![
        Step {
            request: Request::HostAck,
            answer: Answer::Data(Vec::new()),
        },
        command(0x18, &[1], &[]),
        Step {
            request: Request::HostAck,
            answer: Answer::Data(Vec::new()),
        },
        command(2, &[], &[0x32, 1, 6, 7]),
        command(6, &[0xa0, 0], &[0x55]),
    ];
    for bank in 0u8..4 {
        let begin = usize::from(bank) * 64;
        steps.push(command(
            6,
            &bank_addresses(bank),
            &config[begin..begin + 64],
        ));
    }
    steps.extend([
        command(0x0c, &[], &[0x1c]),
        command(8, &[0x63, 0x0a, 0x40], &[0]),
        command(0x32, &[1, 0], &[]),
    ]);
    steps
}

fn mode_configuration() -> Vec<Step> {
    vec![
        command(0x1c, &[0x80, 0x63, 0], &[]),
        command(0x32, &[5, 0, 0, 0], &[]),
        command(0x32, &[0x81, 0xb7], &[]),
        command(0x32, &[0x0b, 1, 2, 3, 4, 5, 6, 7, 8], &[]),
        command(8, &[0x63, 0x0d, 0], &[0]),
    ]
}

fn poll_request() -> Result<PollRequest, rcs956_core::felica::CardError> {
    PollRequest::new(0x1234, 1, 0)
}

fn poll_response() -> Vec<u8> {
    let mut packet = vec![1, 7, 18, 1];
    packet.extend_from_slice(&IDENTITY);
    packet.extend_from_slice(&PARAMETERS);
    packet
}

#[test]
fn felica_424_selects_card_and_exchanges_discovery_and_write_packets() -> Result<(), Box<dyn Error>>
{
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.extend([
        command(0x4a, &[1, 2, 0, 0x12, 0x34, 1, 0], &poll_response()),
        command(
            0xa0,
            &[0xc8, 0, 10, 0x0c, 1, 2, 3, 4, 5, 6, 7, 8],
            &[
                0, 15, 0x0d, 1, 2, 3, 4, 5, 6, 7, 8, 2, 0x12, 0x34, 0x88, 0xb4,
            ],
        ),
        command(
            0xa0,
            &[0xc8, 0, 12, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 0x34, 0x12],
            &[0, 14, 0x0b, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x10, 0xff, 0x10],
        ),
        command(
            0xa0,
            &[0xc8, 0, 12, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 0x35, 0x12],
            &[0, 12, 0x0b, 1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xff],
        ),
    ]);
    let mut request = vec![
        0xc8, 0, 33, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 1, 9, 0, 1, 0, 1, 1,
    ];
    request.extend([0x5a; 16]);
    steps.extend([
        command(
            0xa0,
            &request,
            &[0, 12, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0xa2],
        ),
        command(0xa0, &request, &[0, 12, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0]),
    ]);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    let mut card = reader
        .poll_felica(BitRate::Kbps424, poll_request()?, timeout()?)?
        .ok_or("card absent")?;
    assert_eq!(card.request_system_codes()?, [0x1234, 0x88b4]);
    assert_eq!(
        card.search_service_code(0x1234)?,
        Some(ServiceEntry::Area {
            code: 0x1000,
            end: 0x10ff
        })
    );
    assert_eq!(card.search_service_code(0x1235)?, None);
    let write = BlockWrite {
        block: 257,
        data: [0x5a; 16],
    };
    assert!(matches!(
        card.write_without_encryption(9, &[write; 13]),
        Err(ReaderError::Card(CardError::Length { .. }))
    ));
    assert!(matches!(
        card.write_without_encryption(9, &[write]),
        Err(ReaderError::Card(CardError::Status {
            flag1: 1,
            flag2: 0xa2
        }))
    ));
    card.write_without_encryption(9, &[write])?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn raw_felica_uses_separate_profile_and_checks_packet_length_before_io()
-> Result<(), Box<dyn Error>> {
    let mut config = config_image();
    config[0xcb..=0xce].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    let mut steps = initialization(&config);
    let poll = [6, 0, 0xff, 0xff, 0, 0];
    let raw_response = [
        0, 18, 1, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];
    steps.extend([
        command(0x1c, &[0, 0, 0], &[]),
        command(0x32, &[0x0b, 1, 0x11, 0x22, 0x33, 5, 6, 7, 0x44], &[]),
        command(8, &[0x63, 0x0d, 8], &[0]),
        command(0x32, &[0x80, 2], &[]),
        command(0xa0, &[0xc8, 0, 6, 0, 0xff, 0xff, 0, 0], &raw_response),
        command(0xa0, &[0xc8, 0, 6, 0, 0xff, 0xff, 0, 0], &[0, 5, 1]),
    ]);
    steps.extend(mode_configuration());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    assert!(matches!(
        reader.exchange_raw_felica(BitRate::Kbps424, &[3, 0], timeout()?),
        Err(ReaderError::Card(CardError::Length { .. }))
    ));
    assert_eq!(
        reader.exchange_raw_felica(BitRate::Kbps424, &poll, timeout()?)?,
        raw_response[1..]
    );
    assert!(matches!(
        reader.exchange_raw_felica(BitRate::Kbps424, &poll, timeout()?),
        Err(ReaderError::Card(CardError::Length { .. }))
    ));
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .is_none()
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

fn timeout() -> Result<RfTimeout, TimeoutRange> {
    RfTimeout::new(Duration::from_millis(100))
}

#[test]
fn initialization_commits_reset_and_loads_four_distinct_banks() -> Result<(), Box<dyn Error>> {
    let expected = config_image();
    let (script, journal) = Script::new(initialization(&expected));
    let mut reader = Reader::new(script);
    let info = reader.initialize()?;
    assert_eq!(info.firmware, [0x32, 1, 6, 7]);
    assert_eq!(info.flags, 0x1c);
    assert_eq!(info.configuration.model(), 0x0131);
    assert_eq!(info.configuration.bytes(), &expected);
    assert_eq!(journal.borrow().recoveries, 2);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn polling_read_and_rf_off_keep_identity_and_configuration_boundaries() -> Result<(), Box<dyn Error>>
{
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    // The second poll reuses the successfully applied RF mode. A request-data
    // field can be absent even when request code 1 was sent.
    steps.push(command(
        0x4a,
        &[1, 1, 0, 0x12, 0x34, 1, 0],
        &poll_response(),
    ));
    let mut read_args = vec![0xc8, 0, 16, 6];
    read_args.extend_from_slice(&IDENTITY);
    read_args.extend_from_slice(&[1, 0x8b, 0x1a, 1, 0x80, 0]);
    let mut read_reply = vec![0, 29, 7];
    read_reply.extend_from_slice(&IDENTITY);
    read_reply.extend_from_slice(&[0, 0, 1]);
    read_reply.extend_from_slice(&[0x5a; 16]);
    steps.push(command(0xa0, &read_args, &read_reply));
    steps.push(command(0x32, &[1, 0], &[]));
    // RF off invalidates the mode. A later poll must reapply all settings.
    steps.extend(mode_configuration());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .is_none()
    );
    {
        let mut card = reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .ok_or("expected selected FeliCa card")?;
        assert_eq!(card.target(), 7);
        assert_eq!(card.observation().idm, Idm::new(IDENTITY));
        assert_eq!(card.observation().pmm, PARAMETERS);
        assert_eq!(card.observation().request_data, None);
        assert_eq!(
            card.read_without_encryption(0x1a8b, &[0])?.blocks(),
            &[[0x5a; 16]]
        );
    }
    reader.rf_off()?;
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .is_none()
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn partial_configuration_failure_keeps_reader_uninitialized() -> Result<(), Box<dyn Error>> {
    let config = config_image();
    let mut steps = initialization(&config);
    let bank = steps
        .iter()
        .position(|s| s.request == Request::Command(6, bank_addresses(1)))
        .ok_or("missing bank 1")?;
    steps.truncate(bank + 1);
    steps[bank].answer = Answer::LostAfterAck;
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let result = reader.initialize();
    assert!(matches!(
        result,
        Err(ReaderError::Transaction(TransactionError {
            progress: Progress::Acknowledged,
            ..
        }))
    ));
    let sent = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert!(matches!(reader.rf_off(), Err(ReaderError::NotInitialized)));
    assert_eq!(journal.borrow().requests.len(), sent);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn short_configuration_bank_is_rejected_without_publishing_readiness() -> Result<(), Box<dyn Error>>
{
    let config = config_image();
    let mut steps = initialization(&config);
    let bank = steps
        .iter()
        .position(|s| s.request == Request::Command(6, bank_addresses(0)))
        .ok_or("missing bank 0")?;
    steps.truncate(bank + 1);
    steps[bank].answer = Answer::Data(config[..63].to_vec());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    assert!(matches!(
        reader.initialize(),
        Err(ReaderError::Response("configuration bank length"))
    ));
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn invalid_configuration_checksum_is_not_published() -> Result<(), Box<dyn Error>> {
    let mut config = config_image();
    config[0x40] ^= 1;
    let mut steps = initialization(&config);
    let bank = steps
        .iter()
        .position(|s| s.request == Request::Command(6, bank_addresses(3)))
        .ok_or("missing bank 3")?;
    steps.truncate(bank + 1);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    assert!(matches!(
        reader.initialize(),
        Err(ReaderError::Configuration(ConfigurationError::Checksum {
            offset: 0x40
        }))
    ));
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn mode_register_failure_does_not_publish_a_configured_reader() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    let mut settings = mode_configuration();
    settings[4].answer = Answer::Data(vec![1]);
    steps.extend(settings);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::RegisterStatus(1))
    ));
    let sent = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().requests.len(), sent);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn recovery_rf_status_revokes_the_selected_cards_operation_authority() -> Result<(), Box<dyn Error>>
{
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.push(command(
        0x4a,
        &[1, 1, 0, 0x12, 0x34, 1, 0],
        &poll_response(),
    ));
    let mut args = vec![0xc8, 0, 16, 6];
    args.extend_from_slice(&IDENTITY);
    args.extend_from_slice(&[1, 0x8b, 0x1a, 1, 0x80, 0]);
    // CD & 3F == 0D: classification must preserve the original status byte.
    steps.push(command(0xa0, &args, &[0xcd]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    {
        let mut card = reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .ok_or("expected selected FeliCa card")?;
        assert!(matches!(
            card.read_without_encryption(0x1a8b, &[0]),
            Err(ReaderError::RfStatus(0xcd))
        ));
        let sent = journal.borrow().requests.len();
        assert!(matches!(
            card.read_without_encryption(0x1a8b, &[0]),
            Err(ReaderError::NotInitialized)
        ));
        assert_eq!(journal.borrow().requests.len(), sent);
    }
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn changing_rf_wait_updates_reader_timer_without_reapplying_mode() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    // 1500ms rounds to 2000ms in 1C, whose parameter is (2000-10)/10=199.
    steps.push(command(0x1c, &[0x80, 0xc7, 0], &[]));
    steps.push(command(
        0x4a,
        &[1, 1, 0, 0x12, 0x34, 1, 0],
        &poll_response(),
    ));
    let mut args = vec![0xb8, 0x0b, 16, 6]; // A0 timeout remains 3000 half-ms ticks.
    args.extend_from_slice(&IDENTITY);
    args.extend_from_slice(&[1, 0x8b, 0x1a, 1, 0x80, 0]);
    let mut reply = vec![0, 29, 7];
    reply.extend_from_slice(&IDENTITY);
    reply.extend_from_slice(&[0, 0, 1]);
    reply.extend_from_slice(&[0x5a; 16]);
    steps.push(command(0xa0, &args, &reply));
    steps.push(command(0x1c, &[0x80, 0x63, 0], &[]));
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .is_none()
    );
    {
        let mut card = reader
            .poll_felica(
                BitRate::Kbps212,
                poll_request()?,
                RfTimeout::new(Duration::from_millis(1500))?,
            )?
            .ok_or("expected card")?;
        assert_eq!(
            card.read_without_encryption(0x1a8b, &[0])?.blocks(),
            &[[0x5a; 16]]
        );
    }
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .is_none()
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn failed_timer_change_revokes_preceding_mode() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    steps.push(Step {
        request: Request::Command(0x1c, vec![0x80, 0xc7, 0]),
        answer: Answer::LostAfterAck,
    });
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .is_none()
    );
    assert!(matches!(
        reader.poll_felica(
            BitRate::Kbps212,
            poll_request()?,
            RfTimeout::new(Duration::from_millis(1500))?
        ),
        Err(ReaderError::Transaction(_))
    ));
    let sent = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().requests.len(), sent);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn rf_error_0b_settles_before_a_following_exchange() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.push(command(
        0x4a,
        &[1, 1, 0, 0x12, 0x34, 1, 0],
        &poll_response(),
    ));
    let mut args = vec![0xc8, 0, 16, 6];
    args.extend_from_slice(&IDENTITY);
    args.extend_from_slice(&[1, 0x8b, 0x1a, 1, 0x80, 0]);
    steps.push(command(0xa0, &args, &[0x4b]));
    let mut reply = vec![0, 29, 7];
    reply.extend_from_slice(&IDENTITY);
    reply.extend_from_slice(&[0, 0, 1]);
    reply.extend_from_slice(&[0x5a; 16]);
    steps.push(command(0xa0, &args, &reply));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
        .ok_or("expected card")?;
    assert!(matches!(
        card.read_without_encryption(0x1a8b, &[0]),
        Err(ReaderError::RfStatus(0x4b))
    ));
    let reply_completed = journal
        .borrow()
        .last_read_completed
        .ok_or("missing error response time")?;
    assert_eq!(
        card.read_without_encryption(0x1a8b, &[0])?.blocks(),
        &[[0x5a; 16]]
    );
    let next_request = journal
        .borrow()
        .request_times
        .last()
        .copied()
        .ok_or("missing subsequent request time")?;
    assert!(next_request >= reply_completed + Duration::from_millis(10));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

fn ab_config_image() -> [u8; 256] {
    let mut image = config_image();
    image[0x10..=0x1a].copy_from_slice(&[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
    image[0x23..=0x25].copy_from_slice(&[0x31, 0x32, 0x33]);
    image[0xc0..=0xc2].copy_from_slice(&[0x41, 0x42, 0x43]);
    image[0x3f] = image[0x10..0x3f]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
        .wrapping_neg();
    image
}

fn ab_mode(type_b: bool) -> Vec<Step> {
    let mut steps = vec![
        command(0x1c, &[0x80, 0x63, 0], &[]),
        command(0x32, &[5, 0, 0, 4], &[]),
        command(0x32, &[0x81, 0x8f], &[]),
    ];
    if type_b {
        steps.push(command(
            0x32,
            &[0x0a, 0x41, 0x31, 0x42, 0x32, 0x43, 0x33, 16, 17, 18, 19, 20],
            &[],
        ));
        steps.push(command(0x32, &[0x0c, 0x31, 0x32, 0x33], &[]));
    } else {
        steps.push(command(
            0x32,
            &[0x0a, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            &[],
        ));
    }
    steps.push(command(8, &[0x63, 0x0d, 0], &[0]));
    steps
}

fn type_b_response() -> Vec<u8> {
    vec![1, 9, 0x50, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0x51, 0x40, 1, 0]
}

fn type_b_exchange_steps(activation: &[u8]) -> Vec<Step> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(true));
    steps.push(command(0x4a, &[1, 3, 0, 1], activation));
    steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps
}

#[test]
fn type_a_exchange_uses_selected_target_and_preserves_status() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.push(command(
        0x4a,
        &[1, 0],
        &[1, 7, 4, 0, 0x20, 4, 1, 2, 3, 4, 3, 0x20, 0x40],
    ));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]));
    steps.push(command(0x40, &[7, 0, 0xa4, 4, 0], &[0x40, 0x90, 0]));
    steps.push(command(0x40, &[7, 0x30, 0], &[0x0d]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    assert_eq!(card.observation().uid(), &[1, 2, 3, 4]);
    assert_eq!(card.target(), 7);
    let before = journal.borrow().requests.len();
    assert!(matches!(
        card.exchange(&vec![0; 263]),
        Err(TypeAExchangeError::InputLength(263))
    ));
    assert_eq!(journal.borrow().requests.len(), before);
    let reply = card.exchange(&[0, 0xa4, 4, 0])?;
    assert_eq!(reply.status, 0x40);
    assert_eq!(reply.data, [0x90, 0]);
    assert!(matches!(
        card.exchange(&[0x30, 0]),
        Err(TypeAExchangeError::Exchange(ReaderError::RfStatus(0x0d)))
    ));
    let before = journal.borrow().requests.len();
    assert!(matches!(
        card.exchange(&[0x30, 0]),
        Err(TypeAExchangeError::SessionInvalid)
    ));
    assert_eq!(journal.borrow().requests.len(), before);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_apdu_uses_software_blocks_without_felica_mode() -> Result<(), Box<dyn Error>> {
    let mut steps = type_b_exchange_steps(&type_b_response());
    steps.push(command(0xa0, &[11, 0, 2, 0, 0xa4, 4, 0], &[0, 2, 0x90, 0]));
    steps.push(command(
        0xa0,
        &[11, 0, 3, 0, 0xb0, 0, 0],
        &[0, 3, 0xab, 0x90, 0],
    ));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_b(timeout()?)?
        .ok_or("expected NFC-B card")?;
    assert_eq!(card.observation().pupi(), [1, 2, 3, 4]);
    assert_eq!(card.target(), 9);
    let before = journal.borrow().requests.len();
    for input in [Vec::new(), vec![0; 65536]] {
        let error = card
            .exchange_apdu(&input)
            .err()
            .ok_or("expected input rejection")?;
        assert!(matches!(error.cause, isodep::Cause::InputLength { .. }));
        assert_eq!(error.progress, isodep::Progress::default());
        assert_eq!(journal.borrow().requests.len(), before);
    }
    assert_eq!(card.exchange_apdu(&[0, 0xa4, 4, 0])?, [0x90, 0]);
    assert_eq!(card.exchange_apdu(&[0, 0xb0, 0, 0])?, [0xab, 0x90, 0]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn protocol_changes_reapply_rf_settings_and_absence_is_not_activation() -> Result<(), Box<dyn Error>>
{
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.push(command(0x4a, &[1, 0], &[0]));
    steps.extend(ab_mode(true));
    steps.push(command(0x4a, &[1, 3, 0, 1], &[0]));
    steps.extend(mode_configuration());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(reader.poll_type_a(timeout()?)?.is_none());
    assert!(reader.poll_type_b(timeout()?)?.is_none());
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .is_none()
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_activation_register_failure_revokes_readiness() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(true));
    steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
    steps.push(command(8, &[0x63, 3, 0x8b], &[1]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(matches!(
        reader.poll_type_b(timeout()?),
        Err(ReaderError::RegisterStatus(1))
    ));
    let before = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_type_a(timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().requests.len(), before);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_wtx_echoes_the_multiplier_with_a_bounded_a0_wait() -> Result<(), Box<dyn Error>> {
    for (fwi, multiplier, base, extended) in [
        (8, 20, [0xa9, 0], [0x34, 0x0d]),
        (14, 7, [0x3e, 0x2a], [0x3e, 0x2a]),
    ] {
        let mut activation = type_b_response();
        activation[13] = fwi << 4;
        let mut steps = type_b_exchange_steps(&activation);
        steps.push(command(
            0xa0,
            &[base[0], base[1], 2, 0xa4],
            &[0, 0xf2, multiplier],
        ));
        steps.push(command(
            0xa0,
            &[extended[0], extended[1], 0xf2, multiplier],
            &[0, 2, 0x90, 0],
        ));
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        let mut card = reader
            .poll_type_b(timeout()?)?
            .ok_or("expected NFC-B card")?;
        assert_eq!(card.exchange_apdu(&[0xa4])?, [0x90, 0]);
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn type_b_card_buffer_limit_is_enforced_before_timing_setup() -> Result<(), Box<dyn Error>> {
    let mut activation = type_b_response();
    activation[15] = 0x10; // FSC=64 and MBLI=1 give a 64-byte card buffer.
    let mut steps = type_b_exchange_steps(&activation);
    let apdu = [0x55; 64];
    let first = [&[11, 0, 0x12][..], &apdu[..61]].concat();
    let last = [&[11, 0, 0x03][..], &apdu[61..]].concat();
    steps.push(command(0xa0, &first, &[0, 0xa2]));
    steps.push(command(0xa0, &last, &[0, 3, 0x90, 0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_b(timeout()?)?
        .ok_or("expected NFC-B card")?;
    let before = journal.borrow().requests.len();
    let error = card
        .exchange_apdu(&[0x55; 65])
        .err()
        .ok_or("expected input rejection")?;
    assert!(matches!(
        error.cause,
        isodep::Cause::InputLength {
            maximum: 64,
            actual: 65
        }
    ));
    assert_eq!(error.progress, isodep::Progress::default());
    assert_eq!(journal.borrow().requests.len(), before);
    assert_eq!(card.exchange_apdu(&apdu)?, [0x90, 0]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_invalid_r_blocks_stop_without_retransmitting() -> Result<(), Box<dyn Error>> {
    for (pcb, payload_len, sent_pcb) in [(0xb2, 1, 2), (0xa3, 1, 2), (0xb2, 57, 0x12)] {
        let mut steps = type_b_exchange_steps(&type_b_response());
        let apdu = [
            &[0, 0xd6, 0, 0, payload_len][..],
            &vec![0x5a; usize::from(payload_len)],
        ]
        .concat();
        let sent_len = apdu.len().min(61);
        let block = [&[11, 0, sent_pcb][..], &apdu[..sent_len]].concat();
        steps.push(command(0xa0, &block, &[0, pcb]));
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        let mut card = reader
            .poll_type_b(timeout()?)?
            .ok_or("expected NFC-B card")?;
        let error = card
            .exchange_apdu(&apdu)
            .err()
            .ok_or("expected invalid block")?;
        assert!(matches!(error.cause, isodep::Cause::InvalidBlock(_)));
        assert_eq!(error.progress.frames, 1);
        assert_eq!(error.progress.attempted_application_bytes, sent_len);
        assert_eq!(error.progress.acknowledged_application_bytes, 0);
        let before = journal.borrow().requests.len();
        assert!(matches!(
            card.exchange_apdu(&apdu),
            Err(isodep::Error {
                cause: isodep::Cause::SessionInvalid,
                ..
            })
        ));
        assert_eq!(journal.borrow().requests.len(), before);
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn type_b_lost_exchange_keeps_transport_progress_without_apdu_replay() -> Result<(), Box<dyn Error>>
{
    let mut steps = type_b_exchange_steps(&type_b_response());
    steps.push(Step {
        request: Request::Command(0xa0, vec![11, 0, 2, 0xa4]),
        answer: Answer::LostAfterAck,
    });
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_b(timeout()?)?
        .ok_or("expected NFC-B card")?;
    let error = card
        .exchange_apdu(&[0xa4])
        .err()
        .ok_or("expected exchange loss")?;
    assert!(matches!(
        error.cause,
        isodep::Cause::Transport(ReaderError::Transaction(_))
    ));
    assert_eq!(error.progress.attempted_application_bytes, 1);
    let count = journal.borrow().requests.len();
    let error = card
        .exchange_apdu(&[0xa4])
        .err()
        .ok_or("expected invalid session")?;
    assert!(matches!(error.cause, isodep::Cause::SessionInvalid));
    assert_eq!(journal.borrow().requests.len(), count);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn partial_type_b_timing_setup_preserves_zero_apdu_progress_and_requires_reset()
-> Result<(), Box<dyn Error>> {
    for lose_timer in [false, true] {
        let mut steps = initialization(&ab_config_image());
        steps.extend(ab_mode(true));
        steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
        steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
        let failure = if lose_timer {
            steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
            Request::Command(0x1c, vec![0x80, 0x8f, 1])
        } else {
            Request::Command(0x32, vec![2, 0x0b, 0x0b, 0x10])
        };
        steps.push(Step {
            request: failure,
            answer: Answer::LostAfterAck,
        });
        steps.extend(initialization(&ab_config_image()));
        steps.extend(ab_mode(true));
        steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
        steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
        steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
        steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
        steps.push(command(0xa0, &[11, 0, 2, 0xa4], &[0, 2, 0x90, 0]));
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        let count;
        {
            let mut card = reader
                .poll_type_b(timeout()?)?
                .ok_or("expected NFC-B card")?;
            let error = card
                .exchange_apdu(&[0xa4])
                .err()
                .ok_or("expected timing setup loss")?;
            assert!(matches!(
                error.cause,
                isodep::Cause::Preparation(ReaderError::Transaction(TransactionError {
                    progress: Progress::Acknowledged,
                    ..
                }))
            ));
            assert_eq!(error.progress, isodep::Progress::default());
            assert!(error.partial_response.is_empty());
            assert!(
                journal
                    .borrow()
                    .requests
                    .iter()
                    .all(|request| !matches!(request, Request::Command(0xa0, _)))
            );
            count = journal.borrow().requests.len();
            let error = card
                .exchange_apdu(&[0xa4])
                .err()
                .ok_or("expected invalid session")?;
            assert!(matches!(error.cause, isodep::Cause::SessionInvalid));
            assert_eq!(error.progress, isodep::Progress::default());
        }
        assert!(matches!(
            reader.poll_type_b(timeout()?),
            Err(ReaderError::NotInitialized)
        ));
        assert_eq!(journal.borrow().requests.len(), count);
        reader.initialize()?;
        assert_eq!(
            reader
                .poll_type_b(timeout()?)?
                .ok_or("expected NFC-B card after reset")?
                .exchange_apdu(&[0xa4])?,
            [0x90, 0]
        );
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn type_b_timing_cache_survives_reselection_and_tracks_cross_protocol_changes()
-> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(true));
    steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
    steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0xa0, &[11, 0, 2, 0xa4], &[0, 2, 0x90, 0]));
    // Polling restores its own timer without reapplying the unchanged RF mode.
    // The APDU then restores 1C while retaining the successful selector.
    steps.push(command(0x1c, &[0x80, 0x63, 0], &[]));
    steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
    steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0xa0, &[11, 0, 2, 0xb0], &[0, 2, 0xab, 0x90, 0]));
    steps.extend(ab_mode(false));
    steps.push(command(0x4a, &[1, 0], &type_a_response(7)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[7, 0xa4], &[0, 0x90, 0]));
    steps.extend(ab_mode(true));
    steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
    steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0xa0, &[11, 0, 2, 0xa4], &[0, 2, 0x90, 0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert_eq!(
        reader
            .poll_type_b(timeout()?)?
            .ok_or("expected first NFC-B card")?
            .exchange_apdu(&[0xa4])?,
        [0x90, 0]
    );
    assert_eq!(
        reader
            .poll_type_b(timeout()?)?
            .ok_or("expected reselected NFC-B card")?
            .exchange_apdu(&[0xb0])?,
        [0xab, 0x90, 0]
    );
    assert_eq!(
        reader
            .poll_type_a(RfTimeout::new(Duration::from_millis(500))?)?
            .ok_or("expected NFC-A card")?
            .exchange(&[0xa4])?
            .data,
        [0x90, 0]
    );
    assert_eq!(
        reader
            .poll_type_b(timeout()?)?
            .ok_or("expected NFC-B card after NFC-A")?
            .exchange_apdu(&[0xa4])?,
        [0x90, 0]
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_fwi_boundaries_keep_the_apdu_timer_independent_of_a0_wait() -> Result<(), Box<dyn Error>>
{
    for (fwi, tick_bytes) in [(0, [1, 0]), (14, [0x3e, 0x2a])] {
        let mut response = type_b_response();
        response[13] = fwi << 4;
        let mut steps = initialization(&ab_config_image());
        steps.extend(ab_mode(true));
        steps.push(command(0x4a, &[1, 3, 0, 1], &response));
        steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
        steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
        steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
        steps.push(command(
            0xa0,
            &[tick_bytes[0], tick_bytes[1], 2, 0xa4],
            &[0, 2, 0x90, 0],
        ));
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        assert_eq!(
            reader
                .poll_type_b(timeout()?)?
                .ok_or("expected NFC-B card")?
                .exchange_apdu(&[0xa4])?,
            [0x90, 0]
        );
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn unsupported_type_b_protocol_is_not_an_iso_dep_session() -> Result<(), Box<dyn Error>> {
    let mut response = type_b_response();
    response[12] = 0x50; // ATQB protocol type 0, FSCI5.
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(true));
    steps.push(command(0x4a, &[1, 3, 0, 1], &response));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(matches!(
        reader.poll_type_b(timeout()?),
        Err(ReaderError::TypeBProtocol(0))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

fn type_a_response(target: u8) -> Vec<u8> {
    vec![1, target, 4, 0, 0x20, 4, 1, 2, 3, 4, 3, 0x20, 0x40]
}

#[test]
fn type_a_timeout_applies_the_official_500ms_selector_before_exchange() -> Result<(), Box<dyn Error>>
{
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.push(command(0x4a, &[1, 0], &type_a_response(7)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[7, 0, 0xa4, 4, 0], &[0, 0x90, 0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let wait = RfTimeout::new(Duration::from_millis(500))?;
    let mut card = reader.poll_type_a(wait)?.ok_or("expected NFC-A card")?;
    assert_eq!(card.exchange(&[0, 0xa4, 4, 0])?.data, [0x90, 0]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_a_quantized_timer_and_selector_cache_have_independent_lifetimes()
-> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    let mut setup = ab_mode(false);
    setup[0] = command(0x1c, &[0x80, 0xc7, 0], &[]);
    steps.extend(setup);
    steps.push(command(0x4a, &[1, 0], &type_a_response(7)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0x40, &[7, 0xa4], &[0, 0x90, 0]));
    steps.push(command(0x40, &[7, 0xb0], &[0, 0x90, 0]));
    // Selection uses its requested wait, then command40 restores the effective
    // quantized timer. The successfully applied 32/02 selector is still valid.
    steps.push(command(0x1c, &[0x80, 0xc7, 0], &[]));
    steps.push(command(0x4a, &[1, 0], &type_a_response(9)));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0x40, &[9, 0xa4], &[0, 0x90, 0]));
    // A different timing step changes 32/02. RF-off retains that independent
    // setting; reset must invalidate it even if the next requested step matches.
    steps.push(command(0x1c, &[0x80, 0x63, 0], &[]));
    steps.push(command(0x4a, &[1, 0], &type_a_response(5)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[5, 0xa4], &[0, 0x90, 0]));
    steps.push(command(0x32, &[1, 0], &[]));
    steps.extend(ab_mode(false));
    steps.push(command(0x4a, &[1, 0], &type_a_response(6)));
    steps.push(command(0x40, &[6, 0xa4], &[0, 0x90, 0]));
    // Reset revokes the selector; a later activation must program it again.
    steps.extend(initialization(&ab_config_image()));
    steps.extend(ab_mode(false));
    steps.push(command(0x4a, &[1, 0], &type_a_response(3)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[3, 0xa4], &[0, 0x90, 0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let wait = RfTimeout::new(Duration::from_secs(2))?;
    {
        let mut card = reader.poll_type_a(wait)?.ok_or("expected NFC-A card")?;
        card.exchange(&[0xa4])?;
        card.exchange(&[0xb0])?;
    }
    reader
        .poll_type_a(wait)?
        .ok_or("expected NFC-A card")?
        .exchange(&[0xa4])?;
    let short_wait = RfTimeout::new(Duration::from_millis(500))?;
    reader
        .poll_type_a(short_wait)?
        .ok_or("expected NFC-A card")?
        .exchange(&[0xa4])?;
    reader.rf_off()?;
    reader
        .poll_type_a(short_wait)?
        .ok_or("expected NFC-A card")?
        .exchange(&[0xa4])?;
    reader.initialize()?;
    reader
        .poll_type_a(RfTimeout::new(Duration::from_millis(500))?)?
        .ok_or("expected NFC-A card")?
        .exchange(&[0xa4])?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_a_failures_distinguish_timing_setup_from_card_exchange() -> Result<(), Box<dyn Error>> {
    for lost_command in [0x32, 0x1c, 0x40] {
        let mut steps = initialization(&ab_config_image());
        let mut setup = ab_mode(false);
        setup[0] = command(0x1c, &[0x80, 0xc7, 0], &[]);
        steps.extend(setup);
        steps.push(command(0x4a, &[1, 0], &type_a_response(7)));
        let selector = [2, 0x0b, 0x0b, 0x10];
        let timer = [0x80, 0x8f, 1];
        let args = match lost_command {
            0x32 => selector.to_vec(),
            0x1c => {
                steps.push(command(0x32, &selector, &[]));
                timer.to_vec()
            }
            _ => {
                steps.push(command(0x32, &selector, &[]));
                steps.push(command(0x1c, &timer, &[]));
                vec![7, 0xa4]
            }
        };
        let request = Request::Command(lost_command, args);
        steps.push(Step {
            request: request.clone(),
            answer: Answer::LostAfterAck,
        });
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        let mut card = reader
            .poll_type_a(RfTimeout::new(Duration::from_secs(2))?)?
            .ok_or("expected NFC-A card")?;
        let result = card.exchange(&[0xa4]);
        let error = match result {
            Err(TypeAExchangeError::Exchange(error)) if lost_command == 0x40 => error,
            Err(TypeAExchangeError::Preparation(error)) if lost_command != 0x40 => error,
            other => {
                return Err(
                    format!("unexpected error phase for {lost_command:02x}: {other:?}").into(),
                );
            }
        };
        assert!(matches!(
            error,
            ReaderError::Transaction(TransactionError {
                progress: Progress::Acknowledged,
                ..
            })
        ));
        assert_eq!(journal.borrow().requests.last(), Some(&request));
        let count = journal.borrow().requests.len();
        assert!(matches!(
            card.exchange(&[0xa4]),
            Err(TypeAExchangeError::SessionInvalid)
        ));
        assert_eq!(journal.borrow().requests.len(), count);
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}
