//! Reader-level wire scenarios with independent response construction.
//!
//! These model command/response contracts, not physical device operation.

use rcs956::{
    felica::{Idm, PollRequest},
    reader::{Error as ReaderError, Reader, RfTimeout},
    transport::{Progress, TransactionError, Transport},
    wire::{self, Direction, Frame},
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    error::Error,
    io,
    rc::Rc,
    time::{Duration, Instant},
};

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
    request_times: Vec<Instant>,
    last_read_completed: Option<Instant>,
    remaining: usize,
    recoveries: usize,
}

#[derive(Debug)]
struct Script {
    steps: VecDeque<Step>,
    input: VecDeque<Input>,
    journal: Rc<RefCell<Journal>>,
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
        self.journal.borrow_mut().request_times.push(Instant::now());
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
                self.journal.borrow_mut().last_read_completed = Some(Instant::now());
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

fn poll_request() -> Result<PollRequest, rcs956::felica::CardError> {
    PollRequest::new(0x1234, 1, 0)
}

fn poll_response() -> Vec<u8> {
    let mut packet = vec![1, 7, 18, 1];
    packet.extend_from_slice(&IDENTITY);
    packet.extend_from_slice(&PARAMETERS);
    packet
}

fn timeout() -> Result<RfTimeout, ReaderError> {
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
    assert!(reader.poll_felica(poll_request()?, timeout()?)?.is_none());
    {
        let mut card = reader
            .poll_felica(poll_request()?, timeout()?)?
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
    assert!(reader.poll_felica(poll_request()?, timeout()?)?.is_none());
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
        reader.poll_felica(poll_request()?, timeout()?),
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
        reader.poll_felica(poll_request()?, timeout()?),
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
        Err(ReaderError::Configuration("checksum 40..BF"))
    ));
    assert!(matches!(
        reader.poll_felica(poll_request()?, timeout()?),
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
        reader.poll_felica(poll_request()?, timeout()?),
        Err(ReaderError::RegisterStatus(1))
    ));
    let sent = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_felica(poll_request()?, timeout()?),
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
            .poll_felica(poll_request()?, timeout()?)?
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
    assert!(reader.poll_felica(poll_request()?, timeout()?)?.is_none());
    {
        let mut card = reader
            .poll_felica(
                poll_request()?,
                RfTimeout::new(Duration::from_millis(1500))?,
            )?
            .ok_or("expected card")?;
        assert_eq!(
            card.read_without_encryption(0x1a8b, &[0])?.blocks(),
            &[[0x5a; 16]]
        );
    }
    assert!(reader.poll_felica(poll_request()?, timeout()?)?.is_none());
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
    assert!(reader.poll_felica(poll_request()?, timeout()?)?.is_none());
    assert!(matches!(
        reader.poll_felica(
            poll_request()?,
            RfTimeout::new(Duration::from_millis(1500))?
        ),
        Err(ReaderError::Transaction(_))
    ));
    let sent = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_felica(poll_request()?, timeout()?),
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
        .poll_felica(poll_request()?, timeout()?)?
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
    assert!(next_request.duration_since(reply_completed) >= Duration::from_millis(10));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}
