//! Reader-level wire scenarios with independent response construction.
//!
//! These model command/response contracts, not physical device operation.

use rcs956::{
    falp::{Profile, Reason},
    felica::{BitRate, BlockWrite, CardError, Idm, PollRequest, ServiceEntry},
    isodep, mifare, ndef,
    nfcb::{PollOptions, RfProfile},
    reader::{
        ConfigurationError, DepActivation, DepError, DepMode, DepRate, DepTransferCause,
        Error as ReaderError, FalpAccepted, FalpConnect, FalpError, FalpLink, FalpListen, FalpTurn,
        FelicaCard, MAX_DEP_MESSAGE_BYTES, Reader, RfTimeout, TargetExchangeError, TimeoutRange,
        TransferCause, Type2EmulationError, Type2Event, TypeBCard, TypeBSelection,
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

// Independent response-frame oracle for the simulated reader.
fn reader_response(cc: u8, data: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(data.len() + 2)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut bytes = vec![0, 0, 0xff];
    if let Ok(length) = u8::try_from(length) {
        bytes.extend([length, length.wrapping_neg()]);
    } else {
        let [high, low] = length.to_be_bytes();
        bytes.extend([0xff, 0xff, high, low, high.wrapping_add(low).wrapping_neg()]);
    }
    bytes.extend([0xd5, cc]);
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
            Some(Input::Bytes(mut bytes)) => {
                // A read returns at most the supplied capacity; the rest stays queued.
                if bytes.len() > buffer.len() {
                    self.input
                        .push_front(Input::Bytes(bytes.split_off(buffer.len())));
                }
                buffer[..bytes.len()].copy_from_slice(&bytes);
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
        command(0x12, &[0x1c], &[]),
        command(0x32, &[4, 0], &[]),
        command(8, &[0x63, 0x0a, 0x40], &[0]),
        command(8, &[0x63, 0x0d, 0], &[0]),
        command(0x32, &[1, 0], &[]),
    ]);
    steps
}

/// Receiver probe before InListPassiveTarget, answered with an idle receiver.
fn idle_receiver() -> Step {
    command(6, &[0x63, 0x37, 0x63, 0x31], &[0, 0])
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

#[cfg(feature = "felica-lite-s")]
mod lite_s {
    use super::*;
    use rcs956::felica::lite_s::{Error as LiteSError, Stage, UserBlock};

    const CHALLENGE: [u8; 16] = [
        0xf1, 0x87, 0x5a, 0x01, 0xf9, 0xb2, 0x9e, 0x4c, 0x06, 0xa1, 0xce, 0xc4, 0x16, 0x55, 0x85,
        0xcf,
    ];
    const KEY: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const PMM: [u8; 8] = [0, 0xf1, 0, 0, 0, 0, 0, 0];
    const COUNTER: [u8; 16] = [0x10, 0x20, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const STATE: [u8; 16] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn read(blocks: &[u8], data: &[[u8; 16]], mac: [u8; 8]) -> Step {
        let mut request = vec![0xc8, 0, 14 + 2 * blocks.len() as u8, 6];
        request.extend(IDENTITY);
        request.extend([1, 0x0b, 0, blocks.len() as u8]);
        for &block in blocks {
            request.extend([0x80, block]);
        }
        let mut reply = vec![0, 13 + 16 * blocks.len() as u8, 7];
        reply.extend(IDENTITY);
        reply.extend([0, 0, blocks.len() as u8]);
        reply.extend(data.as_flattened());
        reply.extend(mac);
        reply.extend([0; 8]);
        command(0xa0, &request, &reply)
    }

    fn write(block: u8, data: [u8; 16], mac: Option<[u8; 8]>) -> Step {
        let mut request = vec![0xc8, 0, if mac.is_some() { 50 } else { 32 }, 8];
        request.extend(IDENTITY);
        request.extend([1, 9, 0, if mac.is_some() { 2 } else { 1 }, 0x80, block]);
        if let Some(mac) = mac {
            request.extend([0x80, 0x91]);
            request.extend(data);
            request.extend(mac);
            request.extend(&COUNTER[..8]);
        } else {
            request.extend(data);
        }
        let mut reply = vec![0, 12, 9];
        reply.extend(IDENTITY);
        reply.extend([0, 0]);
        command(0xa0, &request, &reply)
    }

    fn authentication(card_mac: [u8; 8]) -> Vec<Step> {
        let mut steps = initialization(&config_image());
        steps.extend(mode_configuration());
        let mut identity = [0; 16];
        identity[..8].copy_from_slice(&IDENTITY);
        identity[8..].copy_from_slice(&PMM);
        let mut poll = vec![1, 7, 18, 1];
        poll.extend(identity);
        steps.extend([
            idle_receiver(),
            command(0x4a, &[1, 1, 0, 0x88, 0xb4, 0, 0], &poll),
            write(0x80, CHALLENGE, None),
            read(&[0x82, 0x90, 0x91], &[identity, COUNTER], card_mac),
        ]);
        steps
    }

    #[test]
    fn mutually_authenticated_write_uses_the_authenticated_counter() -> Result<(), Box<dyn Error>> {
        // The full trace uses fixed answers computed independently with
        // DES3-CBC, reversing each 8-byte FeliCa field at the cipher boundary.
        let mut steps = authentication(0x1f2787ed70615b68u64.to_be_bytes());
        steps.extend([
            write(0x92, STATE, Some(0x6326508df35e3a07u64.to_be_bytes())),
            read(&[0x92, 0x91], &[STATE], 0x3ea6cbb6e7d3b470u64.to_be_bytes()),
            read(
                &[0x90, 0x91],
                &[COUNTER],
                0x37b2d88e659c8b38u64.to_be_bytes(),
            ),
            write(0, [0x5a; 16], Some(0x4b34193263b09c15u64.to_be_bytes())),
            read(
                &[0, 0x91],
                &[[0x5a; 16]],
                0xe99b8454a6b433adu64.to_be_bytes(),
            ),
            read(
                &[0, 0x91],
                &[[0x5b; 16]],
                0xe99b8454a6b433adu64.to_be_bytes(),
            ),
        ]);
        let (transport, journal) = Script::new(steps);
        let mut reader = Reader::new(transport);
        reader.initialize()?;
        let poll = PollRequest::new(0x88b4, 0, 0)?;
        let card = reader
            .poll_felica(BitRate::Kbps212, poll, timeout()?)?
            .ok_or("card absent")?;
        let mut card = card.authenticate_lite_s(&KEY, CHALLENGE)?;
        let block = UserBlock::new(0).ok_or("user block")?;
        card.write_block(block, [0x5a; 16])?;
        assert_eq!(card.read_block(block)?, [0x5a; 16]);
        assert!(matches!(
            card.read_block(block),
            Err(LiteSError::MacMismatch(Stage::Read))
        ));
        assert!(matches!(
            card.read_block(block),
            Err(LiteSError::SessionUnavailable)
        ));
        assert_eq!(journal.borrow().remaining, 0);
        Ok(())
    }

    #[test]
    fn invalid_card_proof_never_sends_the_host_proof() -> Result<(), Box<dyn Error>> {
        let mut steps = authentication([0; 8]);
        steps.push(command(0x32, &[1, 0], &[]));
        steps.extend(mode_configuration());
        steps.push(idle_receiver());
        steps.push(command(0x4a, &[1, 1, 0, 0x88, 0xb4, 0, 0], &[0]));
        let (transport, journal) = Script::new(steps);
        let mut reader = Reader::new(transport);
        reader.initialize()?;
        let poll = PollRequest::new(0x88b4, 0, 0)?;
        let card = reader
            .poll_felica(BitRate::Kbps212, poll, timeout()?)?
            .ok_or("card absent")?;
        assert!(matches!(
            card.authenticate_lite_s(&KEY, CHALLENGE),
            Err(LiteSError::MacMismatch(Stage::CardProof))
        ));
        assert!(
            reader
                .poll_felica(BitRate::Kbps212, poll, timeout()?)?
                .is_none()
        );
        assert_eq!(journal.borrow().remaining, 0);
        Ok(())
    }
}

#[cfg(feature = "felica-standard-aes")]
#[test]
fn standard_aes_authenticates_encrypts_and_rejects_replay() -> Result<(), Box<dyn Error>> {
    use rcs956::felica::standard_aes::{Block, Error as AesError, NodeKey};

    fn encrypted_command(packet: &[u8], response: &[u8]) -> Step {
        let mut args = vec![0xc8, 0];
        args.extend_from_slice(packet);
        let mut reply = vec![0];
        reply.extend_from_slice(response);
        command(0xa0, &args, &reply)
    }

    // Fixed wire trace derived independently with AES-ECB, OFB, and CMAC.
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    let read_reply = &[
        0x1f, 0x45, 0x02, 0x00, 0x32, 0xe0, 0x63, 0x26, 0x12, 0x52, 0x68, 0x60, 0x74, 0x5a, 0x8e,
        0x34, 0x4f, 0x4f, 0x08, 0x4f, 0xce, 0xde, 0x1c, 0x49, 0x71, 0x44, 0xd8, 0x59, 0xa4, 0x1e,
        0xc1,
    ];
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &poll_response()),
        encrypted_command(
            &[
                0x1e, 0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x01, 0x0a, 0x00,
                0x7b, 0x5f, 0xe9, 0x6d, 0x7c, 0xed, 0x9a, 0xe9, 0xaf, 0xd3, 0x61, 0x7f, 0xca, 0x55,
                0xc8, 0xac,
            ],
            &[
                0x2e, 0x41, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xb4, 0x1f, 0x4c, 0x2b,
                0x88, 0x6d, 0xdb, 0x65, 0x34, 0x7d, 0x9e, 0xd2, 0x36, 0x33, 0xac, 0x3f, 0x30, 0xdf,
                0x84, 0xb1, 0x74, 0x1c, 0xfc, 0x46, 0x7a, 0x7f, 0x44, 0xee, 0xc2, 0xbf, 0xea, 0x2a,
                0x10, 0x11, 0x12, 0x13,
            ],
        ),
        encrypted_command(
            &[
                0x1a, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x25, 0x99, 0x95, 0xe2,
                0x1a, 0x43, 0x67, 0x23, 0x45, 0xf7, 0xcb, 0xb5, 0xfc, 0xf1, 0x88, 0xc1,
            ],
            &[
                0x1c, 0x43, 0x00, 0x00, 0xef, 0x62, 0x94, 0x11, 0xb9, 0x2e, 0xc3, 0x02, 0x81, 0x94,
                0xd3, 0xd5, 0xaa, 0x1f, 0xf3, 0x0e, 0xf8, 0x4a, 0x1a, 0x53, 0x74, 0x97, 0x47, 0xba,
            ],
        ),
        encrypted_command(
            &[
                0x10, 0x44, 0x01, 0x00, 0x9b, 0xd7, 0xed, 0xc7, 0xd1, 0x77, 0x51, 0xb7, 0xe9, 0xec,
                0x43, 0x87,
            ],
            read_reply,
        ),
        encrypted_command(
            &[
                0x20, 0x46, 0x03, 0x00, 0xb1, 0x63, 0x64, 0xfa, 0x01, 0x00, 0x65, 0x8d, 0xb5, 0x6b,
                0x5e, 0xb0, 0x36, 0x5d, 0xdf, 0x18, 0x09, 0x38, 0x32, 0x72, 0x06, 0x2a, 0x12, 0x18,
                0xc3, 0xa8, 0x05, 0xba,
            ],
            &[
                0x0e, 0x47, 0x04, 0x00, 0x7d, 0x37, 0x8f, 0x1f, 0x9f, 0xf4, 0x1f, 0x3a, 0xf5, 0x30,
            ],
        ),
        encrypted_command(
            &[
                0x10, 0x44, 0x05, 0x00, 0x0e, 0x38, 0xcf, 0x1c, 0xf3, 0x29, 0xaf, 0x3b, 0xd0, 0x9a,
                0x8d, 0x03,
            ],
            read_reply,
        ),
    ]);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    let card = reader
        .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
        .ok_or("card absent")?;
    let mut session = card.authenticate_standard_aes(
        &[NodeKey {
            code: 0x000a,
            key: &0x00112233445566778899aabbccddeeffu128.to_be_bytes(),
        }],
        &core::array::from_fn(|index| index as u8),
        0,
        core::array::from_fn(|index| 0x30 + index as u8),
    )?;
    assert_eq!(session.issue().id, 0x0011223344556677u64.to_be_bytes());
    assert_eq!(
        session.issue().parameters,
        0x8899aabbccddeeffu64.to_be_bytes()
    );
    let block = Block {
        service_index: 0,
        number: 0x0102,
    };
    assert!(matches!(
        session.read_blocks(&[Block {
            service_index: 1,
            ..block
        }]),
        Err(AesError::ServiceIndex(1))
    ));
    assert_eq!(session.read_blocks(&[block])?, [[0xa5; 16]]);
    session.write_blocks(&[(block, [0x5a; 16])])?;
    assert!(matches!(
        session.read_blocks(&[block]),
        Err(AesError::TransactionNumber {
            sent: 5,
            received: 2
        })
    ));
    assert!(matches!(
        session.read_blocks(&[block]),
        Err(AesError::SessionUnavailable)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

fn type_three_attribute(block: [u8; 16]) -> Step {
    let mut reply = vec![0, 29, 7, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 1];
    reply.extend(block);
    command(
        0xa0,
        &[
            0xc8, 0, 16, 6, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0x0b, 0, 1, 0x80, 0,
        ],
        &reply,
    )
}

fn type_three_update(block: u8, data: [u8; 16], status: [u8; 2]) -> Step {
    let mut request = vec![
        0xc8, 0, 32, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 9, 0, 1, 0x80, block,
    ];
    request.extend(data);
    command(
        0xa0,
        &request,
        &[0, 12, 9, 1, 2, 3, 4, 5, 6, 7, 8, status[0], status[1]],
    )
}

#[test]
fn type_three_ndef_uses_the_ndef_system_and_publishes_length_last() -> Result<(), Box<dyn Error>> {
    let attribute = [0x10, 1, 1, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 3, 0, 0x18];
    let started = [0x10, 1, 1, 0, 2, 0, 0, 0, 0, 0x0f, 1, 0, 0, 3, 0, 0x27];
    let published = [0x10, 1, 1, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 17, 0, 0x26];
    let mut old_reply = vec![0, 29, 7, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 1];
    old_reply.extend([0x32; 16]);
    let mut last_block = [0; 16];
    last_block[0] = 0x5a;
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 1, 0, 0x12, 0xfc, 0, 0], &poll_response()),
        type_three_attribute(attribute),
        command(
            0xa0,
            &[
                0xc8, 0, 16, 6, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0x0b, 0, 1, 0x80, 1,
            ],
            &old_reply,
        ),
        type_three_attribute(attribute),
        type_three_update(0, started, [0, 0]),
        type_three_update(1, [0x5a; 16], [0, 0]),
        type_three_update(2, last_block, [0, 0]),
        type_three_update(0, published, [0, 0]),
    ]);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    let mut tag = reader
        .poll_type3(BitRate::Kbps212, timeout()?)?
        .ok_or("Type 3 tag absent")?;
    assert_eq!(tag.read_ndef()?, [0x32; 3]);
    tag.write_ndef(&[0x5a; 17])?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_three_ndef_preserves_update_progress_and_detects_the_write_flag()
-> Result<(), Box<dyn Error>> {
    let attribute = [0x10, 1, 1, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 3, 0, 0x18];
    let started = [0x10, 1, 1, 0, 2, 0, 0, 0, 0, 0x0f, 1, 0, 0, 3, 0, 0x27];
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 1, 0, 0x12, 0xfc, 0, 0], &poll_response()),
        type_three_attribute(attribute),
        type_three_attribute(attribute),
        type_three_update(0, started, [0, 0]),
        type_three_update(1, [0; 16], [0, 0]),
        type_three_update(2, [0; 16], [1, 0xa2]),
        type_three_attribute(started),
    ]);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    let mut tag = reader
        .poll_type3(BitRate::Kbps212, timeout()?)?
        .ok_or("Type 3 tag absent")?;
    assert!(matches!(
        tag.write_ndef(&[0; 33]),
        Err(ndef::WriteError::Preparation(ndef::Error::Capacity {
            requested: 33,
            available: 32
        }))
    ));
    assert!(matches!(
        tag.write_ndef(&[0; 17]),
        Err(ndef::WriteError::Update {
            stage: ndef::UpdateStage::Data,
            acknowledged_bytes: 16,
            cause: ndef::Error::Exchange(ReaderError::FelicaResponse(CardError::Status {
                flag1: 1,
                flag2: 0xa2,
            })),
        })
    ));
    assert!(matches!(tag.read_ndef(), Err(ndef::Error::WriteInProgress)));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn felica_424_selects_card_and_exchanges_discovery_and_write_packets() -> Result<(), Box<dyn Error>>
{
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.extend([
        idle_receiver(),
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
        Err(ReaderError::FelicaRequest(CardError::Length { .. }))
    ));
    assert!(matches!(
        card.write_without_encryption(9, &[write]),
        Err(ReaderError::FelicaResponse(CardError::Status {
            flag1: 1,
            flag2: 0xa2
        }))
    ));
    card.write_without_encryption(9, &[write])?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn felica_write_length_errors_distinguish_request_rejection_from_sent_command()
-> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.push(idle_receiver());
    steps.push(command(
        0x4a,
        &[1, 2, 0, 0x12, 0x34, 1, 0],
        &poll_response(),
    ));
    let mut args = vec![0xc8, 0, 32, 0x08];
    args.extend(IDENTITY);
    args.extend([1, 9, 0, 1, 0x80, 1]);
    args.extend([0x5a; 16]);
    let mut reply = vec![0; 262];
    reply[1] = 255;
    steps.push(command(0xa0, &args, &reply));

    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    let mut card = reader
        .poll_felica(BitRate::Kbps424, poll_request()?, timeout()?)?
        .ok_or("expected FeliCa card")?;
    let block = BlockWrite {
        block: 256,
        data: [0x5a; 16],
    };
    assert!(matches!(
        card.write_without_encryption(9, &[block; 13]),
        Err(ReaderError::FelicaRequest(CardError::Length {
            expected: 255,
            actual: 261
        }))
    ));
    assert_eq!(journal.borrow().remaining, 1);
    let block = BlockWrite { block: 1, ..block };
    assert!(matches!(
        card.write_without_encryption(9, &[block]),
        Err(ReaderError::FelicaResponse(CardError::Length {
            expected: 255,
            actual: 261
        }))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn felica_request_response_reports_mode_and_distinguishes_absence() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    let mut args = vec![0xc8, 0, 10, 0x04];
    args.extend(IDENTITY);
    let answer = |mode: &[u8]| {
        let mut reply = vec![0, u8::try_from(10 + mode.len()).unwrap_or(0), 0x05];
        reply.extend(IDENTITY);
        reply.extend_from_slice(mode);
        reply
    };
    let mut other = answer(&[0]);
    other[3] = 9;
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 2, 0, 0x12, 0x34, 1, 0], &poll_response()),
        command(0xa0, &args, &answer(&[2])),
        command(0xa0, &args, &answer(&[])),
        command(0xa0, &args, &other),
        command(0xa0, &args, &[1]),
    ]);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    let mut card = reader
        .poll_felica(BitRate::Kbps424, poll_request()?, timeout()?)?
        .ok_or("expected FeliCa card")?;
    assert_eq!(card.request_response()?, 2);
    assert!(matches!(
        card.request_response(),
        Err(ReaderError::FelicaResponse(CardError::Length {
            expected: 11,
            actual: 10
        }))
    ));
    assert!(matches!(
        card.request_response(),
        Err(ReaderError::FelicaResponse(
            CardError::IdentityMismatch { .. }
        ))
    ));
    assert!(matches!(
        card.request_response(),
        Err(ReaderError::RfStatus(1))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn raw_felica_exchanges_opaque_packets_after_selection() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    let packet = [4, 0xe0, 0x32, 0xc1];
    let raw_response = [0, 3, 0xa0, 0x12];
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 2, 0, 0x12, 0x34, 1, 0], &poll_response()),
        command(0xa0, &[0xc8, 0, 4, 0xe0, 0x32, 0xc1], &raw_response),
        command(0xa0, &[0xc8, 0, 4, 0xe0, 0x32, 0xc1], &[0, 5, 1]),
    ]);
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    {
        let mut raw = reader
            .poll_felica(BitRate::Kbps424, poll_request()?, timeout()?)?
            .ok_or("expected FeliCa card")?
            .into_raw();
        assert!(matches!(
            raw.exchange_packet(&[3, 0]),
            Err(ReaderError::FelicaRequest(CardError::Length { .. }))
        ));
        assert_eq!(raw.exchange_packet(&packet)?, raw_response[1..]);
        assert!(matches!(
            raw.exchange_packet(&packet),
            Err(ReaderError::FelicaResponse(CardError::Length { .. }))
        ));
    }
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
    assert_eq!(info.configuration.model().word(), 0x0131);
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
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    // The second poll reuses the successfully applied RF mode. A request-data
    // field can be absent even when request code 1 was sent.
    steps.push(idle_receiver());
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
    steps.push(idle_receiver());
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
fn rejected_rf_retry_setting_is_not_published() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    let retry = steps
        .iter()
        .position(|s| s.request == Request::Command(0x32, vec![4, 0]))
        .ok_or("missing RF retry setting")?;
    steps.truncate(retry + 1);
    steps[retry].answer = Answer::Data(vec![0]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    assert!(matches!(
        reader.initialize(),
        Err(ReaderError::Response("RF retry response length"))
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
    steps.push(idle_receiver());
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
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    // 1500ms rounds to 2000ms in 1C, whose parameter is (2000-10)/10=199.
    steps.push(command(0x1c, &[0x80, 0xc7, 0], &[]));
    steps.push(idle_receiver());
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
    steps.push(idle_receiver());
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
    steps.push(idle_receiver());
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
    steps.push(idle_receiver());
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

fn poll_iso_dep(
    reader: &mut Reader<Script>,
) -> Result<Option<TypeBCard<'_, Script>>, Box<dyn Error>> {
    match reader.poll_type_b(PollOptions::default(), timeout()?)? {
        Some(TypeBSelection::IsoDep(card)) => Ok(Some(card)),
        Some(TypeBSelection::Frame(_)) => Err("expected an ISO-DEP selection".into()),
        None => Ok(None),
    }
}

fn type_b_exchange_steps(activation: &[u8]) -> Vec<Step> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(true));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 3, 0, 1], activation));
    steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps
}

#[test]
fn type_b_nad_and_timeout_recovery_use_only_the_current_rf_block() -> Result<(), Box<dyn Error>> {
    let mut activation = type_b_response();
    activation[13] |= 2;
    let mut steps = type_b_exchange_steps(&activation);
    steps.extend([
        command(0xa0, &[11, 0, 0x06, 0x21, 0xa4], &[1]),
        command(0xa0, &[11, 0, 0xb2], &[0, 0x16, 0x12, 0xab]),
        command(0xa0, &[11, 0, 0xa3], &[1]),
        command(0xa0, &[11, 0, 0xa3], &[0, 0x03, 0x90, 0]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(isodep::NodeAddress::from_byte(0x88).is_err());
    let options = PollOptions {
        node_address: Some(isodep::NodeAddress::from_byte(0x21)?),
        ..PollOptions::default()
    };
    let Some(TypeBSelection::IsoDep(mut card)) = reader.poll_type_b(options, timeout()?)? else {
        return Err("expected ISO-DEP activation".into());
    };
    assert_eq!(card.exchange_apdu(&[0xa4])?, [0xab, 0x90, 0]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_rf_timeout_budget_preserves_uncertain_progress() -> Result<(), Box<dyn Error>> {
    let mut steps = type_b_exchange_steps(&type_b_response());
    steps.extend([
        command(0xa0, &[11, 0, 2, 0xa4], &[1]),
        command(0xa0, &[11, 0, 0xb2], &[1]),
        command(0xa0, &[11, 0, 0xb2], &[1]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = poll_iso_dep(&mut reader)?.ok_or("expected ISO-DEP activation")?;
    let error = card
        .exchange_apdu(&[0xa4])
        .err()
        .ok_or("expected RF timeout")?;
    assert!(matches!(
        error.cause,
        isodep::Cause::RecoveryExhausted(ReaderError::RfStatus(1))
    ));
    assert_eq!(error.progress.attempted_application_bytes, 1);
    assert_eq!(error.progress.acknowledged_application_bytes, 0);
    assert_eq!(error.progress.frames, 3);
    assert!(matches!(
        card.exchange_apdu(&[0xa4]),
        Err(isodep::Error {
            cause: isodep::Cause::SessionInvalid,
            ..
        })
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_a_exchange_timeout_is_independent_of_the_polling_wait() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(
        0x4a,
        &[1, 0],
        &[1, 7, 4, 0, 0x20, 4, 1, 2, 3, 4, 3, 0x20, 0x40],
    ));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0x40, &[7, 0, 0xa4, 4, 0], &[0, 0x90, 0]));
    steps.push(command(0x40, &[7, 0, 0xb0, 0, 0], &[0, 0x6a, 0x82]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    card.set_exchange_timeout(RfTimeout::new(Duration::from_millis(3280))?);
    assert_eq!(card.exchange_apdu(&[0, 0xa4, 4, 0])?, [0x90, 0]);
    assert_eq!(card.exchange_apdu(&[0, 0xb0, 0, 0])?, [0x6a, 0x82]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn raw_type_a_recovers_pending_fragments_before_sending_another_command()
-> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(
        0x4a,
        &[1, 0],
        &[1, 7, 4, 0, 0x20, 4, 1, 2, 3, 4, 3, 0x20, 0x40],
    ));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]));
    steps.push(command(0x40, &[7, 0, 0xa4, 4, 0], &[0x40, 0x90, 0]));
    steps.push(command(0x40, &[7], &[0xc0, 0x11]));
    steps.push(command(0x40, &[7], &[0, 0x22]));
    steps.push(command(0x40, &[7, 0x30, 0], &[0x0d]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    assert_eq!(card.observation().uid(), &[1, 2, 3, 4]);
    assert_eq!(card.target(), 7);
    let mut card = card.into_raw();
    let before = journal.borrow().requests.len();
    assert!(matches!(
        card.exchange(&vec![0; 263]),
        Err(TargetExchangeError::InputLength {
            maximum: 262,
            actual: 263
        })
    ));
    assert!(card.receive_continuation()?.is_none());
    assert_eq!(journal.borrow().requests.len(), before);
    let reply = card.exchange(&[0, 0xa4, 4, 0])?;
    assert_eq!(reply.status, 0x40);
    assert_eq!(reply.data, [0x90, 0]);
    let before = journal.borrow().requests.len();
    assert!(matches!(
        card.exchange(&[0x30, 0]),
        Err(TargetExchangeError::ResponsePending)
    ));
    assert_eq!(journal.borrow().requests.len(), before);
    let reply = card
        .receive_continuation()?
        .ok_or("expected second fragment")?;
    assert_eq!(reply.status, 0xc0);
    assert_eq!(reply.data, [0x11]);
    assert!(matches!(
        card.exchange(&[0x30, 0]),
        Err(TargetExchangeError::ResponsePending)
    ));
    let reply = card
        .receive_continuation()?
        .ok_or("expected final fragment")?;
    assert_eq!(reply.status, 0);
    assert_eq!(reply.data, [0x22]);
    assert!(card.receive_continuation()?.is_none());
    assert!(matches!(
        card.exchange(&[0x30, 0]),
        Err(TargetExchangeError::Exchange(ReaderError::RfStatus(0x0d)))
    ));
    let before = journal.borrow().requests.len();
    assert!(matches!(
        card.exchange(&[0x30, 0]),
        Err(TargetExchangeError::SessionInvalid)
    ));
    assert_eq!(journal.borrow().requests.len(), before);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn incomplete_raw_type_a_response_requires_reader_recovery() -> Result<(), Box<dyn Error>> {
    for read_continuation in [false, true] {
        let mut steps = initialization(&ab_config_image());
        steps.extend(ab_mode(false));
        steps.extend([
            idle_receiver(),
            command(0x4a, &[1, 0], &type_a_response(7)),
            command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
            command(0x40, &[7, 0xa4], &[0x40, 0x11]),
        ]);
        if read_continuation {
            steps.push(command(0x40, &[7], &[1]));
        }
        steps.extend(initialization(&ab_config_image()));
        steps.extend(ab_mode(false));
        steps.push(idle_receiver());
        steps.push(command(0x4a, &[1, 0], &[0]));
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        {
            let mut card = reader
                .poll_type_a(timeout()?)?
                .ok_or("expected NFC-A card")?
                .into_raw();
            assert_eq!(card.exchange(&[0xa4])?.status, 0x40);
            if read_continuation {
                assert!(matches!(
                    card.receive_continuation(),
                    Err(TargetExchangeError::Exchange(ReaderError::RfStatus(1)))
                ));
                assert!(matches!(
                    card.exchange(&[0xa4]),
                    Err(TargetExchangeError::SessionInvalid)
                ));
            }
        }
        let before = journal.borrow().requests.len();
        assert!(matches!(reader.rf_off(), Err(ReaderError::NotInitialized)));
        assert!(matches!(
            reader.poll_type_a(timeout()?),
            Err(ReaderError::NotInitialized)
        ));
        assert_eq!(journal.borrow().requests.len(), before);
        reader.initialize()?;
        assert!(reader.poll_type_a(timeout()?)?.is_none());
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn raw_type_a_stops_collecting_at_the_fragment_limit() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &[7, 0xa4], &[0x40]),
    ]);
    steps.extend((1..256).map(|_| command(0x40, &[7], &[0x40])));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut raw = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?
        .into_raw();
    raw.exchange(&[0xa4])?;
    for _ in 1..256 {
        assert_eq!(
            raw.receive_continuation()?
                .ok_or("expected fragment")?
                .status,
            0x40
        );
    }
    assert!(matches!(
        raw.receive_continuation(),
        Err(TargetExchangeError::FragmentLimit)
    ));
    assert!(matches!(
        raw.exchange(&[0xa4]),
        Err(TargetExchangeError::SessionInvalid)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn failed_field_cycle_does_not_grant_a_new_typed_selection() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &[7, 0xa4], &[0]),
        command(0x32, &[1, 0], &[1]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?
        .into_raw()
        .exchange(&[0xa4])?;
    assert!(matches!(
        reader.poll_type_a(timeout()?),
        Err(ReaderError::Response("RF off response length"))
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
    let mut card = poll_iso_dep(&mut reader)?.ok_or("expected NFC-B card")?;
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
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &[0]));
    steps.extend(ab_mode(true));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 3, 0, 1], &[0]));
    steps.extend(mode_configuration());
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(reader.poll_type_a(timeout()?)?.is_none());
    assert!(
        reader
            .poll_type_b(PollOptions::default(), timeout()?)?
            .is_none()
    );
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
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
    steps.push(command(8, &[0x63, 3, 0x8b], &[1]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(matches!(
        reader.poll_type_b(PollOptions::default(), timeout()?),
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
        let mut card = poll_iso_dep(&mut reader)?.ok_or("expected NFC-B card")?;
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
    let mut card = poll_iso_dep(&mut reader)?.ok_or("expected NFC-B card")?;
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
        let mut card = poll_iso_dep(&mut reader)?.ok_or("expected NFC-B card")?;
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
fn type_b_repeats_unchained_i_block_when_timeout_recovery_acknowledges_loss()
-> Result<(), Box<dyn Error>> {
    let mut steps = type_b_exchange_steps(&type_b_response());
    steps.extend([
        command(0xa0, &[11, 0, 2, 0xa4], &[1]),
        command(0xa0, &[11, 0, 0xb2], &[0, 0xa3]),
        command(0xa0, &[11, 0, 2, 0xa4], &[0, 2, 0x90, 0]),
        command(0xa0, &[11, 0, 3, 0xb0], &[0, 3, 0x90, 0]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = poll_iso_dep(&mut reader)?.ok_or("expected NFC-B card")?;
    assert_eq!(card.exchange_apdu(&[0xa4])?, [0x90, 0]);
    assert_eq!(card.exchange_apdu(&[0xb0])?, [0x90, 0]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_unchained_timeout_recovery_rejects_ack_with_matching_number() -> Result<(), Box<dyn Error>>
{
    let mut steps = type_b_exchange_steps(&type_b_response());
    steps.extend([
        command(0xa0, &[11, 0, 2, 0xa4], &[1]),
        command(0xa0, &[11, 0, 0xb2], &[0, 0xa2]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = poll_iso_dep(&mut reader)?.ok_or("expected NFC-B card")?;
    let error = card
        .exchange_apdu(&[0xa4])
        .err()
        .ok_or("expected invalid ACK")?;
    assert!(matches!(error.cause, isodep::Cause::InvalidBlock(_)));
    assert_eq!(error.progress.frames, 2);
    assert_eq!(error.progress.acknowledged_application_bytes, 0);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_presence_probe_keeps_numbering_and_silence_revokes_the_session()
-> Result<(), Box<dyn Error>> {
    let mut steps = type_b_exchange_steps(&type_b_response());
    steps.extend([
        command(0xa0, &[11, 0, 0xb2], &[0, 0xa3]),
        command(0xa0, &[11, 0, 2, 0xa4], &[0, 2, 0x90, 0]),
        command(0xa0, &[11, 0, 0xb3], &[1]),
        command(0xa0, &[11, 0, 0xb3], &[1]),
        command(0xa0, &[11, 0, 0xb3], &[1]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = poll_iso_dep(&mut reader)?.ok_or("expected NFC-B card")?;
    card.check_presence()?;
    assert_eq!(card.exchange_apdu(&[0xa4])?, [0x90, 0]);
    let error = card
        .check_presence()
        .err()
        .ok_or("expected an unanswered probe")?;
    assert!(matches!(
        error,
        isodep::PresenceError::NoResponse(ReaderError::RfStatus(1))
    ));
    let before = journal.borrow().requests.len();
    assert!(matches!(
        card.exchange_apdu(&[0xa4]),
        Err(isodep::Error {
            cause: isodep::Cause::SessionInvalid,
            ..
        })
    ));
    assert_eq!(journal.borrow().requests.len(), before);
    assert_eq!(journal.borrow().remaining, 0);
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
    let mut card = poll_iso_dep(&mut reader)?.ok_or("expected NFC-B card")?;
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
        steps.push(idle_receiver());
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
        steps.push(idle_receiver());
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
            let mut card = poll_iso_dep(&mut reader)?.ok_or("expected NFC-B card")?;
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
            reader.poll_type_b(PollOptions::default(), timeout()?),
            Err(ReaderError::NotInitialized)
        ));
        assert_eq!(journal.borrow().requests.len(), count);
        reader.initialize()?;
        assert_eq!(
            poll_iso_dep(&mut reader)?
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
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
    steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0xa0, &[11, 0, 2, 0xa4], &[0, 2, 0x90, 0]));
    // Polling restores its own timer without reapplying the unchanged RF mode.
    // The APDU then restores 1C while retaining the successful selector.
    steps.push(command(0x1c, &[0x80, 0x63, 0], &[]));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
    steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0xa0, &[11, 0, 2, 0xb0], &[0, 2, 0xab, 0x90, 0]));
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(7)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[7, 0xa4], &[0, 0x90, 0]));
    steps.extend(ab_mode(true));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
    steps.push(command(8, &[0x63, 3, 0x8b], &[0]));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0xa0, &[11, 0, 2, 0xa4], &[0, 2, 0x90, 0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert_eq!(
        poll_iso_dep(&mut reader)?
            .ok_or("expected first NFC-B card")?
            .exchange_apdu(&[0xa4])?,
        [0x90, 0]
    );
    assert_eq!(
        poll_iso_dep(&mut reader)?
            .ok_or("expected reselected NFC-B card")?
            .exchange_apdu(&[0xb0])?,
        [0xab, 0x90, 0]
    );
    assert_eq!(
        reader
            .poll_type_a(RfTimeout::new(Duration::from_millis(500))?)?
            .ok_or("expected NFC-A card")?
            .exchange_apdu(&[0xa4])?,
        [0x90, 0]
    );
    assert_eq!(
        poll_iso_dep(&mut reader)?
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
        steps.push(idle_receiver());
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
            poll_iso_dep(&mut reader)?
                .ok_or("expected NFC-B card")?
                .exchange_apdu(&[0xa4])?,
            [0x90, 0]
        );
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn alternate_type_b_profile_exchanges_a_proprietary_target_command() -> Result<(), Box<dyn Error>> {
    let mut response = type_b_response();
    response[12] = 0x50; // ATQB protocol type 0, FSCI5.
    let mut image = ab_config_image();
    image[0xcf..=0xd1].copy_from_slice(&[0xa1, 0xa2, 0xa3]);
    let mut steps = initialization(&image);
    steps.extend([
        command(0x1c, &[0x80, 0x63, 0], &[]),
        command(0x32, &[5, 0, 0, 4], &[]),
        command(0x32, &[0x81, 0x8f], &[]),
        command(
            0x32,
            &[0x0a, 0x41, 0xa1, 0x42, 0xa2, 0x43, 0xa3, 16, 17, 18, 19, 20],
            &[],
        ),
        command(0x32, &[0x0c, 0xa1, 0xa2, 0xa3], &[]),
        command(8, &[0x63, 0x0d, 0], &[0]),
        idle_receiver(),
        command(0x4a, &[1, 3, 0x12, 1], &response),
        command(8, &[0x63, 3, 0x8b], &[0]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &[9, 0x42, 0x43], &[0, 0xa5]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let options = PollOptions {
        profile: RfProfile::Alternate,
        afi: 0x12,
        node_address: None,
    };
    let Some(TypeBSelection::Frame(mut card)) = reader.poll_type_b(options, timeout()?)? else {
        return Err("expected a frame selection".into());
    };
    assert!(matches!(
        card.exchange(&[0; 64]),
        Err(TargetExchangeError::InputLength {
            maximum: 63,
            actual: 64
        })
    ));
    assert_eq!(card.exchange(&[0x42, 0x43])?.data, [0xa5]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_frame_response_that_cannot_complete_revokes_the_selection() -> Result<(), Box<dyn Error>>
{
    let mut response = type_b_response();
    response[12] = 0x50; // ATQB protocol type 0, FSCI5.
    // A further fragment and an absent status both leave the reader's
    // continuation state unknown.
    for reply in [vec![0x40, 0xa5], vec![]] {
        let mut steps = initialization(&ab_config_image());
        steps.extend(ab_mode(true));
        steps.extend([
            idle_receiver(),
            command(0x4a, &[1, 3, 0, 1], &response),
            command(8, &[0x63, 3, 0x8b], &[0]),
            command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
            command(0x40, &[9, 0x42], &reply),
        ]);
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        let Some(TypeBSelection::Frame(mut card)) =
            reader.poll_type_b(PollOptions::default(), timeout()?)?
        else {
            return Err("expected a frame selection".into());
        };
        let first = card.exchange(&[0x42]);
        assert!(match reply.as_slice() {
            [0x40, ..] => matches!(first, Ok(ref r) if r.status == 0x40),
            _ => matches!(
                first,
                Err(TargetExchangeError::Exchange(ReaderError::Response(_)))
            ),
        });
        assert!(matches!(
            card.exchange(&[0x43]),
            Err(TargetExchangeError::SessionInvalid)
        ));
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

fn type_a_response(target: u8) -> Vec<u8> {
    vec![1, target, 4, 0, 0x20, 4, 1, 2, 3, 4, 3, 0x20, 0x40]
}

#[test]
fn type_a_apdu_continuation_sends_no_second_application_command() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &[7, 0xa4], &[0x40, 0x11]),
        command(0x40, &[7], &[0, 0x22, 0x90, 0]),
        command(0x40, &[7, 0xb0], &[0x40, 0x33]),
        command(0x40, &[7], &[1]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    assert_eq!(card.exchange_apdu(&[0xa4])?, [0x11, 0x22, 0x90, 0]);
    let error = card
        .exchange_apdu(&[0xb0])
        .err()
        .ok_or("expected continuation failure")?;
    assert!(matches!(
        error.cause,
        isodep::Cause::Transport(ReaderError::RfStatus(1))
    ));
    assert_eq!(error.partial_response, [0x33]);
    assert_eq!(error.progress.attempted_application_bytes, 1);
    assert_eq!(error.progress.frames, 2);
    assert!(matches!(
        card.exchange_apdu(&[0xb0]),
        Err(isodep::Error {
            cause: isodep::Cause::SessionInvalid,
            ..
        })
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn mifare_classic_authority_is_limited_to_the_authenticated_sector() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    let mut write = vec![7, 0xa0, 130];
    write.extend([0x5a; 16]);
    let mut read_response = vec![0];
    read_response.extend([0x44; 16]);
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &[1, 7, 4, 0, 0x18, 7, 1, 2, 3, 4, 5, 6, 7]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &[7, 0x61, 129, 1, 2, 3, 4, 5, 6, 4, 5, 6, 7], &[0]),
        command(0x40, &[7, 0x30, 143], &read_response),
        command(0x40, &write, &[0x0b]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    let mut sector =
        card.authenticate_mifare_classic(129, mifare::KeyKind::B, &[1, 2, 3, 4, 5, 6])?;
    assert!(matches!(
        sector.read_block(144),
        Err(mifare::Error::Block(144))
    ));
    assert_eq!(sector.read_block(143)?, [0x44; 16]);
    assert!(matches!(
        sector.write_block(130, &[0x5a; 16]),
        Err(mifare::Error::Exchange(TargetExchangeError::Exchange(
            ReaderError::RfStatus(0x0b)
        )))
    ));
    assert!(matches!(
        sector.read_block(143),
        Err(mifare::Error::AuthenticationLost)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_one_ndef_uses_rid_rall_and_byte_writes() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    let mut memory = [0; 120];
    memory[..4].copy_from_slice(&[1, 2, 3, 4]);
    memory[8..18].copy_from_slice(&[0xe1, 0x10, 0x0e, 0, 3, 3, 0xd0, 0, 0, 0xfe]);
    memory[112..114].copy_from_slice(&[1, 0x60]);
    let mut reply = vec![0, 0x11, 0x48];
    reply.extend(memory);
    let read = [7, 0, 0, 0, 1, 2, 3, 4];
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 4], &[1, 7, 0, 0x0c, 1, 2, 3, 4]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(
            0x40,
            &[7, 0x78, 0, 0, 0, 0, 0, 0],
            &[0, 0x11, 0x48, 1, 2, 3, 4],
        ),
        command(0x40, &read, &reply),
        command(0x40, &read, &reply),
    ]);
    for (address, data) in [
        (13, 0),
        (14, 0xd5),
        (15, 0),
        (16, 1),
        (17, 0x42),
        (18, 0xfe),
        (13, 4),
    ] {
        steps.push(command(
            0x40,
            &[7, 0x53, address, data, 1, 2, 3, 4],
            &[0, address, data],
        ));
    }
    reply[3 + 112] |= 4; // Lock block 2, which includes the end of the replacement.
    steps.push(command(0x40, &read, &reply));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut tag = reader.poll_type1(timeout()?)?.ok_or("Type 1 tag absent")?;
    assert_eq!(tag.uid(), [1, 2, 3, 4]);
    assert_eq!(tag.read_ndef()?.as_deref(), Some([0xd0, 0, 0].as_slice()));
    tag.write_ndef(&[0xd5, 0, 1, 0x42])?;
    assert!(matches!(
        tag.write_ndef(&[0xd5, 0, 1, 0x42]),
        Err(ndef::WriteError::Preparation(ndef::Error::WriteAccess))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_one_pending_fragment_requires_reinitialization() -> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    for status in [0x40, 0x41] {
        let mut steps = initialization(&configuration);
        steps.extend(ab_mode(false));
        steps.extend([
            idle_receiver(),
            command(0x4a, &[1, 4], &[1, 7, 0, 0x0c, 1, 2, 3, 4]),
            command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
            command(
                0x40,
                &[7, 0x78, 0, 0, 0, 0, 0, 0],
                &[0, 0x11, 0x48, 1, 2, 3, 4],
            ),
            command(0x40, &[7, 0, 0, 0, 1, 2, 3, 4], &[status, 0x11, 0x48]),
        ]);
        steps.extend(initialization(&configuration));
        steps.extend(ab_mode(false));
        steps.push(idle_receiver());
        steps.push(command(0x4a, &[1, 0], &type_a_response(7)));

        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        {
            let mut tag = reader.poll_type1(timeout()?)?.ok_or("Type 1 tag absent")?;
            assert!(matches!(
                tag.read_ndef(),
                Err(ndef::Error::Exchange(TargetExchangeError::Exchange(
                    ReaderError::RfStatus(actual)
                ))) if actual == status
            ));
            assert!(matches!(
                tag.read_ndef(),
                Err(ndef::Error::Exchange(TargetExchangeError::SessionInvalid))
            ));
        }
        assert!(matches!(
            reader.poll_type_a(timeout()?),
            Err(ReaderError::NotInitialized)
        ));
        reader.initialize()?;
        assert!(reader.poll_type_a(timeout()?)?.is_some());
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn type_one_dynamic_memory_is_rejected_before_read_or_write() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 4], &[1, 7, 0, 0x0c, 1, 2, 3, 4]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(
            0x40,
            &[7, 0x78, 0, 0, 0, 0, 0, 0],
            &[0, 0x12, 0x48, 1, 2, 3, 4],
        ),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut tag = reader.poll_type1(timeout()?)?.ok_or("Type 1 tag absent")?;
    assert!(matches!(
        tag.read_ndef(),
        Err(ndef::Error::UnsupportedMapping)
    ));
    assert!(matches!(
        tag.write_ndef(&[0xd0, 0, 0]),
        Err(ndef::WriteError::Preparation(
            ndef::Error::UnsupportedMapping
        ))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn passive_dep_owns_activation_and_one_response_at_a_time() -> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    let mut steps = initialization(&configuration);
    steps.extend([
        command(8, &[0x63, 0x0b, 0x80], &[0]),
        command(0x32, &[0x82, 8, 2, 8], &[]),
        command(0x12, &[0x18], &[]),
        command(8, &[0x63, 1, 0x7b], &[0]),
        command(8, &[0x63, 2, 0xb0], &[0]),
        command(8, &[0x63, 3, 0xb0], &[0]),
        command(8, &[0x63, 0x0d, 8], &[0]),
        command(
            0x8c,
            &[
                2, 1, 1, 0x31, 0x32, 0x33, 0x40, 1, 0xfe, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0xfe, 0x31, 0x32, 0x33,
                0x34, 0x35, 0x36, 0, 0,
            ],
            &[
                0x10, 19, 0xd4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 2, 0x46, 0x66,
            ],
        ),
        command(0x92, &[0x46, 0x66, 0x6d], &[0]),
        command(0x86, &[], &[0xc0, 0x12, 0x11]),
        command(0x86, &[], &[0, 0x22]),
        command(0x94, &[0x12; 60], &[0]),
        command(0x8e, &[0x12; 2], &[0]),
        command(0x86, &[], &[0x40, 0x44]),
        command(0x86, &[], &[0x01]),
    ]);
    steps.extend(initialization(&configuration));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let mut target = reader.listen_passive_dep(*b"123456", b"Ffm", timeout()?)?;
    assert_eq!(target.initiator().rate, DepRate::Kbps212);
    assert_eq!(target.initiator().general_bytes, [0x46, 0x66]);
    {
        let mut request = target.receive(timeout()?)?;
        assert_eq!(request.payload(), [0x11, 0x22]);
        assert_eq!(request.node_address(), Some(0x12));
        assert!(matches!(
            request.respond(&[0; MAX_DEP_MESSAGE_BYTES + 1]),
            Err(DepError::MessageLength(_))
        ));
        request.respond(&[0x12; 61])?;
        assert!(matches!(
            request.respond(&[0x33]),
            Err(DepError::SessionUnavailable)
        ));
    }
    assert!(matches!(
        target.receive(timeout()?),
        Err(DepError::Transfer {
            attempted: 0, accepted: 0, received,
            cause: DepTransferCause::Status(1),
        }) if received.payload == [0x44]
    ));
    assert!(matches!(
        target.receive(timeout()?),
        Err(DepError::SessionUnavailable)
    ));
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn stalled_receiver_is_restarted_before_activation() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.extend([
        command(6, &[0x63, 0x37, 0x63, 0x31], &[0x08, 0x2c]),
        command(8, &[0x63, 0x31, 0x28, 0x63, 0x31, 0x20], &[0, 0]),
        command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]),
        idle_receiver(),
        command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    for _ in 0..2 {
        assert!(
            reader
                .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
                .is_none()
        );
    }
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn failed_receiver_restart_sends_no_activation() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        command(6, &[0x63, 0x37, 0x63, 0x31], &[0x08, 0]),
        command(8, &[0x63, 0x31, 0x08, 0x63, 0x31, 0], &[0, 5]),
        command(6, &[0x63, 0x37, 0x63, 0x31], &[0]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(matches!(
        reader.poll_type_a(timeout()?),
        Err(ReaderError::RegisterStatus(5))
    ));
    assert!(matches!(
        reader.poll_type1(timeout()?),
        Err(TargetExchangeError::Preparation(ReaderError::Response(_)))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn passive_dep_at_106_kbps_prepares_target_registers_and_restores_parameters()
-> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    let mut steps = initialization(&configuration);
    steps.extend([
        command(8, &[0x63, 0x0b, 0x80], &[0]),
        command(0x32, &[0x82, 8, 2, 8], &[]),
        command(0x12, &[0x18], &[]),
        command(8, &[0x63, 1, 0x7b], &[0]),
        command(8, &[0x63, 2, 0xb0], &[0]),
        command(8, &[0x63, 3, 0xb0], &[0]),
        command(8, &[0x63, 0x0d, 8], &[0]),
        command(
            0x8c,
            &[
                2, 1, 1, 0x31, 0x32, 0x33, 0x40, 1, 0xfe, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0xfe, 0x31, 0x32, 0x33,
                0x34, 0x35, 0x36, 0, 0,
            ],
            &[
                0, 19, 0xd4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 2, 0x46, 0x66,
            ],
        ),
        command(8, &[0x63, 0x0d, 0], &[0]),
        command(8, &[0x63, 1, 0x3b], &[0]),
        command(0x92, &[], &[0]),
    ]);
    steps.extend(initialization(&configuration));
    steps.extend(ab_mode(false));
    steps.extend([idle_receiver(), command(0x4a, &[1, 0], &type_a_response(7))]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let target = reader.listen_passive_dep(*b"123456", &[], timeout()?)?;
    assert_eq!(target.initiator().rate, DepRate::Kbps106);
    target.finish()?;
    let card = reader.poll_type_a(timeout()?)?.ok_or("NFC-A card absent")?;
    assert!(card.observation().ats().is_some());
    let parameters: Vec<Vec<u8>> = journal
        .borrow()
        .requests
        .iter()
        .filter_map(|request| match request {
            Request::Command(0x12, args) => Some(args.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(parameters, [[0x1c], [0x18], [0x1c]]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn initialization_restores_reception_setting_left_by_a_212_kbps_target()
-> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    let mut steps = initialization(&configuration);
    steps.extend([
        command(8, &[0x63, 0x0b, 0x80], &[0]),
        command(0x32, &[0x82, 8, 2, 8], &[]),
        command(0x12, &[0x18], &[]),
        command(8, &[0x63, 1, 0x7b], &[0]),
        command(8, &[0x63, 2, 0xb0], &[0]),
        command(8, &[0x63, 3, 0xb0], &[0]),
        command(8, &[0x63, 0x0d, 8], &[0]),
        command(
            0x8c,
            &[
                2, 1, 1, 0x31, 0x32, 0x33, 0x40, 1, 0xfe, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0xfe, 0x31, 0x32, 0x33,
                0x34, 0x35, 0x36, 0, 0,
            ],
            &[0x10, 17, 0xd4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0],
        ),
        command(0x92, &[], &[0]),
    ]);
    // Finishing the 212 kbps target, then the initiator's own initialization.
    steps.extend(initialization(&configuration));
    steps.extend(initialization(&configuration));
    steps.extend([
        command(0x12, &[0x1c], &[]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x32, &[5, 0, 0, 0], &[]),
        command(
            0x56,
            &[0, 0, 0],
            &[0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 8, 0],
        ),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let target = reader.listen_passive_dep(*b"123456", &[], timeout()?)?;
    assert_eq!(target.initiator().rate, DepRate::Kbps212);
    target.finish()?;
    reader.activate_dep(
        DepActivation {
            mode: DepMode::Passive,
            rate: DepRate::Kbps106,
            nfcid3: None,
            general_bytes: &[],
            node_address: None,
        },
        timeout()?,
    )?;
    let journal = journal.borrow();
    let activation = journal
        .requests
        .iter()
        .position(|request| matches!(request, Request::Command(0x56, _)))
        .ok_or("NFC-DEP activation not sent")?;
    let reception = journal.requests[..activation]
        .iter()
        .rev()
        .find_map(|request| match request {
            Request::Command(8, args) if args.starts_with(&[0x63, 0x0d]) => Some(args.clone()),
            _ => None,
        });
    assert_eq!(reception, Some(vec![0x63, 0x0d, 0]));
    assert_eq!(journal.remaining, 0);
    Ok(())
}

#[test]
fn dep_initiator_uses_meta_chaining_and_retains_partial_failure() -> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    let mut steps = initialization(&configuration);
    let mut first = vec![0x41, 0x31];
    first.extend([0xa5; 59]);
    steps.extend([
        command(0x12, &[0x1d], &[]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x32, &[5, 0, 0, 0], &[]),
        command(
            0x56,
            &[1, 1, 4, 0x46, 0x66, 0x6d],
            &[0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 8, 3, 0x46],
        ),
        command(0x40, &first, &[0]),
        command(0x40, &[1, 0xa5, 0xa5], &[0xc0, 0x31, 0xab]),
        command(0x40, &[1], &[0, 0xcd]),
        command(0x40, &[1, 0x31, 0x22], &[0xc0, 0x31, 0xef]),
        command(0x40, &[1], &[0x01]),
    ]);
    steps.extend(initialization(&configuration));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let mut link = reader.activate_dep(
        DepActivation {
            mode: DepMode::Active,
            rate: DepRate::Kbps212,
            nfcid3: None,
            general_bytes: b"Ffm",
            node_address: Some(0x31),
        },
        timeout()?,
    )?;
    assert_eq!(link.peer().general_bytes, b"F");
    let reply = link.exchange(&[0xa5; 61])?;
    assert_eq!(reply.node_address, Some(0x31));
    assert_eq!(reply.payload, [0xab, 0xcd]);
    assert!(matches!(
        link.exchange(&[0x22]),
        Err(DepError::Transfer {
            attempted: 1, accepted: 1, received,
            cause: DepTransferCause::Status(1),
        }) if received.payload == [0xef] && received.node_address == Some(0x31)
    ));
    assert!(matches!(
        link.exchange(&[]),
        Err(DepError::SessionUnavailable)
    ));
    link.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_two_target_serves_read_only_ndef_and_halts() -> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    let mut steps = initialization(&configuration);
    let mut activation = [0; 35];
    activation[..7].copy_from_slice(&[0, 4, 0, 1, 2, 3, 0]);
    steps.extend([
        command(8, &[0x03, 0x28, 0x59], &[0]),
        command(8, &[0x63, 1, 0x3f], &[0]),
        command(0x8c, &activation, &[0, 0x30, 3]),
        command(
            0x90,
            &[
                0xe1, 0x10, 6, 0x0f, 3, 4, 0xd5, 0, 1, 0x42, 0xfe, 0, 0, 0, 0, 0,
            ],
            &[0],
        ),
        command(0x88, &[], &[0, 0xa2, 4, 0, 0, 0, 0]),
        command(0x88, &[], &[0, 0x30, 15]),
        command(
            0x90,
            &[0, 0, 0, 0, 8, 1, 2, 3, 8, 0, 0, 0, 0, 0, 0xff, 0xff],
            &[0],
        ),
        command(0x88, &[], &[0, 0x50, 0]),
    ]);
    steps.extend(initialization(&configuration));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    assert!(matches!(
        reader.listen_type2_ndef([1, 2, 3], &[0xd5, 0, 1], timeout()?),
        Err(Type2EmulationError::Message(_))
    ));
    assert!(matches!(
        reader.listen_type2_ndef([1, 2, 3], &[0; 47], timeout()?),
        Err(Type2EmulationError::MessageLength(47))
    ));
    let mut tag = reader.listen_type2_ndef([1, 2, 3], &[0xd5, 0, 1, 0x42], timeout()?)?;
    assert_eq!(tag.serve_next(timeout()?)?, Type2Event::Read(3));
    assert_eq!(
        tag.serve_next(timeout()?)?,
        Type2Event::Ignored(vec![0xa2, 4, 0, 0, 0, 0])
    );
    assert_eq!(tag.serve_next(timeout()?)?, Type2Event::Read(15));
    assert_eq!(tag.serve_next(timeout()?)?, Type2Event::Halted);
    assert!(matches!(
        tag.serve_next(timeout()?),
        Err(Type2EmulationError::SessionUnavailable)
    ));
    tag.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_two_ndef_read_skips_reserved_bytes_in_the_message() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &[1, 7, 4, 0, 0, 7, 1, 2, 3, 4, 5, 6, 7]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(
            0x40,
            &[7, 0x30, 0],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0x10, 6, 0],
        ),
        // Memory Control TLV excludes byte 26, inside the NDEF value.
        command(
            0x40,
            &[7, 0x30, 4],
            &[
                0, 2, 3, 0x62, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0xff, 0x44, 0xfe, 0, 0, 0,
            ],
        ),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    assert_eq!(
        card.read_type2_ndef()?.as_deref(),
        Some([0x11, 0x22, 0x33, 0x44].as_slice())
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

fn type_two_before_sector_select() -> Vec<Step> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    let selection = &[1, 7, 4, 0, 0, 7, 1, 2, 3, 4, 5, 6, 7];
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], selection),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(
            0x40,
            &[7, 0x30, 0],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0x10, 127, 0],
        ),
    ]);
    for address in (4..=248u8).step_by(4) {
        steps.push(command(0x40, &[7, 0x30, address], &[0; 17]));
    }
    let mut last_window = [0; 17];
    last_window[15..].copy_from_slice(&[3, 4]);
    steps.extend([
        command(0x40, &[7, 0x30, 252], &last_window),
        command(0x40, &[7, 0xc2, 0xff], &[0, 0x0a]),
    ]);
    steps
}

#[test]
fn type_two_ndef_switches_sectors_and_resets_the_field_before_reselection()
-> Result<(), Box<dyn Error>> {
    let mut steps = type_two_before_sector_select();
    steps.extend([
        command(0x40, &[7, 1, 0, 0, 0], &[1]),
        command(
            0x40,
            &[7, 0x30, 0],
            &[0, 0xd5, 0, 1, 0x42, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        command(0x32, &[1, 0], &[]),
    ]);
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &[0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader.poll_type_a(timeout()?)?.ok_or("Type 2 tag absent")?;
    assert_eq!(card.read_type2_ndef()?, Some(vec![0xd5, 0, 1, 0x42]));
    assert!(reader.poll_type_a(timeout()?)?.is_none());
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_two_ndef_revokes_selection_on_sector_select_nak() -> Result<(), Box<dyn Error>> {
    let mut steps = type_two_before_sector_select();
    steps.push(command(0x40, &[7, 1, 0, 0, 0], &[0, 0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader.poll_type_a(timeout()?)?.ok_or("Type 2 tag absent")?;
    assert!(matches!(
        card.read_type2_ndef(),
        Err(ndef::Error::Type2Nak(0))
    ));
    assert!(matches!(
        card.read_type2_ndef(),
        Err(ndef::Error::Exchange(TargetExchangeError::SessionInvalid))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_two_ndef_write_preserves_reserved_bytes_and_publishes_length_last()
-> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &[1, 7, 4, 0, 0, 7, 1, 2, 3, 4, 5, 6, 7]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(
            0x40,
            &[7, 0x30, 0],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0x10, 6, 0],
        ),
        command(
            0x40,
            &[7, 0x30, 4],
            &[
                0, 2, 3, 0x62, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0xff, 0x44, 0xfe, 0, 0, 0,
            ],
        ),
        command(0x40, &[7, 0xa2, 5, 2, 3, 0, 0x11], &[0, 0x0a]),
        command(0x40, &[7, 0xa2, 5, 2, 3, 0, 0xd5], &[0, 0x0a]),
        command(0x40, &[7, 0xa2, 6, 0, 1, 0xff, 0x42], &[0, 0x0a]),
        command(0x40, &[7, 0xa2, 7, 0xfe, 0, 0, 0], &[0, 0x0a]),
        command(0x40, &[7, 0xa2, 5, 2, 3, 4, 0xd5], &[0]),
        command(
            0x40,
            &[7, 0x30, 5],
            &[
                0, 2, 3, 4, 0xd5, 0, 1, 0xff, 0x42, 0xfe, 0, 0, 0, 0, 0, 0, 0,
            ],
        ),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader.poll_type_a(timeout()?)?.ok_or("Type 2 tag absent")?;
    card.write_type2_ndef(&[0xd5, 0, 1, 0x42])?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_two_capacity_ends_at_the_data_area_including_reserved_bytes() -> Result<(), Box<dyn Error>>
{
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &[1, 7, 4, 0, 0, 7, 1, 2, 3, 4, 5, 6, 7]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        // A 48-byte data area spans bytes 16..64 and reserves byte 26.
        command(
            0x40,
            &[7, 0x30, 0],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0x10, 6, 0],
        ),
        command(
            0x40,
            &[7, 0x30, 4],
            &[
                0, 2, 3, 0x62, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0xff, 0x44, 0xfe, 0, 0, 0,
            ],
        ),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader.poll_type_a(timeout()?)?.ok_or("Type 2 tag absent")?;
    // Bytes 23..64 hold 41 addresses, one of them reserved.
    assert!(matches!(
        card.write_type2_ndef(&[0; 41]),
        Err(ndef::WriteError::Preparation(ndef::Error::Capacity {
            requested: 41,
            available: 40,
        }))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_two_ndef_write_stops_on_nak_without_publishing() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &[1, 7, 4, 0, 0, 7, 1, 2, 3, 4, 5, 6, 7]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(
            0x40,
            &[7, 0x30, 0],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0x10, 6, 0],
        ),
        command(
            0x40,
            &[7, 0x30, 4],
            &[0, 3, 3, 0xd0, 0, 0, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        command(0x40, &[7, 0xa2, 4, 3, 0, 0xd0, 0], &[0, 0x0a]),
        command(0x40, &[7, 0xa2, 4, 3, 0, 0xd5, 0], &[0, 0x0a]),
        command(0x40, &[7, 0xa2, 5, 1, 0x42, 0xfe, 0], &[0, 5]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader.poll_type_a(timeout()?)?.ok_or("Type 2 tag absent")?;
    assert!(matches!(
        card.write_type2_ndef(&[0xd5, 0, 1, 0x42]),
        Err(ndef::WriteError::Update {
            stage: ndef::UpdateStage::Data,
            acknowledged_bytes: 2,
            cause: ndef::Error::Type2Nak(5)
        })
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn typed_type_two_read_reselects_after_raw_sector_change() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    let activation = [1, 7, 4, 0, 0, 7, 1, 2, 3, 4, 5, 6, 7];
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &activation),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &[7, 0xc2, 0xff], &[0]),
        // The second SECTOR SELECT packet can take effect without a reply.
        command(0x40, &[7, 1, 0, 0, 0], &[1]),
        command(0x32, &[1, 0], &[]),
    ]);
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &activation),
        command(
            0x40,
            &[7, 0x30, 0],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0x10, 6, 0],
        ),
        command(
            0x40,
            &[7, 0x30, 4],
            &[0, 3, 3, 0xd0, 0, 0, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    {
        let mut raw = reader
            .poll_type_a(timeout()?)?
            .ok_or("expected NFC-A card")?
            .into_raw();
        raw.exchange(&[0xc2, 0xff])?;
        assert!(matches!(
            raw.exchange(&[1, 0, 0, 0]),
            Err(TargetExchangeError::Exchange(ReaderError::RfStatus(1)))
        ));
    }
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    assert_eq!(card.read_type2_ndef()?, Some(vec![0xd0, 0, 0]));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_four_ndef_read_selects_files_and_checks_apdu_status() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    let select = [7, 0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0];
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &select, &[0, 0x90, 0]),
        command(0x40, &[7, 0, 0xa4, 0, 0x0c, 2, 0xe1, 3], &[0, 0x90, 0]),
        command(
            0x40,
            &[7, 0, 0xb0, 0, 0, 7],
            &[0, 0, 15, 0x20, 0, 15, 0, 15, 0x90, 0],
        ),
        command(
            0x40,
            &[7, 0, 0xb0, 0, 7, 8],
            &[0, 4, 6, 0xe1, 4, 0, 0x80, 0, 0xff, 0x90, 0],
        ),
        command(0x40, &[7, 0, 0xa4, 0, 0x0c, 2, 0xe1, 4], &[0, 0x90, 0]),
        command(0x40, &[7, 0, 0xb0, 0, 0, 2], &[0, 0, 3, 0x90, 0]),
        command(0x40, &[7, 0, 0xb0, 0, 2, 3], &[0, 0xd0, 0, 0, 0x90, 0]),
        command(0x40, &select, &[0, 0x6a, 0x82]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    assert_eq!(card.read_type4_ndef()?, [0xd0, 0, 0]);
    assert!(matches!(
        card.read_type4_ndef(),
        Err(ndef::Error::Status(0x6a82))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

fn type_four_file_selection(write_access: u8) -> [Step; 5] {
    [
        command(
            0x40,
            &[7, 0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0],
            &[0, 0x90, 0],
        ),
        command(0x40, &[7, 0, 0xa4, 0, 0x0c, 2, 0xe1, 3], &[0, 0x90, 0]),
        command(
            0x40,
            &[7, 0, 0xb0, 0, 0, 7],
            &[0, 0, 15, 0x20, 0, 15, 0, 3, 0x90, 0],
        ),
        command(
            0x40,
            &[7, 0, 0xb0, 0, 7, 8],
            &[0, 4, 6, 0xe1, 4, 0, 6, 0, write_access, 0x90, 0],
        ),
        command(0x40, &[7, 0, 0xa4, 0, 0x0c, 2, 0xe1, 4], &[0, 0x90, 0]),
    ]
}

#[test]
fn type_four_ndef_write_checks_access_and_capacity_then_publishes_nlen()
-> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
    ]);
    steps.extend(type_four_file_selection(0xff));
    steps.extend(type_four_file_selection(0));
    steps.extend(type_four_file_selection(0));
    steps.extend([
        command(0x40, &[7, 0, 0xd6, 0, 0, 2, 0, 0], &[0, 0x90, 0]),
        command(0x40, &[7, 0, 0xd6, 0, 2, 3, 0xd5, 0, 1], &[0, 0x90, 0]),
        command(0x40, &[7, 0, 0xd6, 0, 5, 1, 0x42], &[0, 0x90, 0]),
        command(0x40, &[7, 0, 0xd6, 0, 0, 2, 0, 4], &[0, 0x90, 0]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("Type 4A card absent")?;
    assert!(matches!(
        card.write_type4_ndef(&[0xd0, 0, 0]),
        Err(ndef::WriteError::Preparation(ndef::Error::WriteAccess))
    ));
    assert!(matches!(
        card.write_type4_ndef(&[0; 5]),
        Err(ndef::WriteError::Preparation(ndef::Error::Capacity {
            requested: 5,
            available: 4
        }))
    ));
    card.write_type4_ndef(&[0xd5, 0, 1, 0x42])?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_four_extended_ndef_uses_offset_objects_and_publishes_enlen() -> Result<(), Box<dyn Error>> {
    fn select_extended() -> [Step; 5] {
        [
            command(
                0x40,
                &[7, 0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0],
                &[0, 0x90, 0],
            ),
            command(0x40, &[7, 0, 0xa4, 0, 0x0c, 2, 0xe1, 3], &[0, 0x90, 0]),
            command(
                0x40,
                &[7, 0, 0xb0, 0, 0, 7],
                &[0, 0, 17, 0x30, 0, 255, 0, 255, 0x90, 0],
            ),
            command(
                0x40,
                &[7, 0, 0xb0, 0, 7, 10],
                &[0, 6, 8, 0xe1, 4, 0, 0x20, 0, 0, 0, 0, 0x90, 0],
            ),
            command(0x40, &[7, 0, 0xa4, 0, 0x0c, 2, 0xe1, 4], &[0, 0x90, 0]),
        ]
    }
    let message = vec![0x5a; 0x8000];
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
    ]);
    steps.extend(select_extended());
    steps.push(command(
        0x40,
        &[7, 0, 0xd6, 0, 0, 4, 0, 0, 0, 0],
        &[0, 0x90, 0],
    ));
    for (index, chunk) in message.chunks(127).enumerate() {
        let [_, a, b, c] = (4 + index as u32 * 127).to_be_bytes();
        let mut request = vec![
            7,
            0,
            0xd7,
            0,
            0,
            chunk.len() as u8 + 7,
            0x54,
            3,
            a,
            b,
            c,
            0x53,
            chunk.len() as u8,
        ];
        request.extend_from_slice(chunk);
        steps.push(command(0x40, &request, &[0, 0x90, 0]));
    }
    steps.push(command(
        0x40,
        &[7, 0, 0xd6, 0, 0, 4, 0, 0, 0x80, 0],
        &[0, 0x90, 0],
    ));
    steps.extend(select_extended());
    steps.push(command(
        0x40,
        &[7, 0, 0xb0, 0, 0, 4],
        &[0, 0, 0, 0x80, 0, 0x90, 0],
    ));
    for (index, chunk) in message.chunks(127).enumerate() {
        let [_, a, b, c] = (4 + index as u32 * 127).to_be_bytes();
        let mut reply = vec![0, 0x53, chunk.len() as u8];
        reply.extend_from_slice(chunk);
        reply.extend([0x90, 0]);
        steps.push(command(
            0x40,
            &[7, 0, 0xb1, 0, 0, 5, 0x54, 3, a, b, c, chunk.len() as u8 + 2],
            &reply,
        ));
    }
    steps.extend(select_extended());
    steps.push(command(
        0x40,
        &[7, 0, 0xb0, 0, 0, 4],
        &[0, 0, 0x10, 0, 0, 0x90, 0],
    ));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("Type 4A card absent")?;
    card.write_type4_ndef(&message)?;
    assert_eq!(card.read_type4_ndef()?, message);
    assert!(matches!(
        card.read_type4_ndef(),
        Err(ndef::Error::Capacity {
            requested: 1_048_576,
            available: 1_048_572
        })
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_four_rejects_reserved_ndef_file_identifiers_before_selecting_them()
-> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
    ]);
    let reserved_ids = [
        [0xe1, 3], // The Capability Container itself.
        [0, 0],
        [0x3f, 0],
        [0x3f, 0xff],
        [0xe1, 2],
        [0xff, 0xff],
    ];
    for [hi, lo] in reserved_ids {
        let [app, cc, header, _, _] = type_four_file_selection(0);
        steps.extend([
            app,
            cc,
            header,
            command(
                0x40,
                &[7, 0, 0xb0, 0, 7, 8],
                &[0, 4, 6, hi, lo, 0, 0x80, 0, 0, 0x90, 0],
            ),
        ]);
    }
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("Type 4A card absent")?;
    for _ in reserved_ids {
        assert!(matches!(
            card.write_type4_ndef(&[]),
            Err(ndef::WriteError::Preparation(ndef::Error::Layout(
                "Type 4 NDEF file identifier"
            )))
        ));
    }
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_four_b_ndef_write_fits_each_apdu_within_the_card_buffer() -> Result<(), Box<dyn Error>> {
    let mut activation = type_b_response();
    activation[15] = 0x10; // FSC=64 and MBLI=1 permit 64 command bytes.
    let mut steps = type_b_exchange_steps(&activation);
    let exchanges: [(&[u8], &[u8]); 6] = [
        (&[0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0], &[]),
        (&[0, 0xa4, 0, 0x0c, 2, 0xe1, 3], &[]),
        (&[0, 0xb0, 0, 0, 7], &[0, 15, 0x20, 0, 15, 0, 0xff]),
        (&[0, 0xb0, 0, 7, 8], &[4, 6, 0xe1, 4, 0, 0x80, 0, 0]),
        (&[0, 0xa4, 0, 0x0c, 2, 0xe1, 4], &[]),
        (&[0, 0xd6, 0, 0, 2, 0, 0], &[]),
    ];
    for (index, (apdu, data)) in exchanges.into_iter().enumerate() {
        let pcb = if index % 2 == 0 { 2 } else { 3 };
        let request = [&[11, 0, pcb][..], apdu].concat();
        let response = [&[0, pcb][..], data, &[0x90, 0]].concat();
        steps.push(command(0xa0, &request, &response));
    }
    let mut message = [0x42; 60];
    message[..3].copy_from_slice(&[0xd5, 0, 57]);
    let first_block = [&[11, 0, 0x12, 0, 0xd6, 0, 2, 59][..], &message[..56]].concat();
    steps.extend([
        command(0xa0, &first_block, &[0, 0xa2]),
        command(0xa0, &[11, 0, 3, 0x42, 0x42, 0x42], &[0, 3, 0x90, 0]),
        command(0xa0, &[11, 0, 2, 0, 0xd6, 0, 61, 1, 0x42], &[0, 2, 0x90, 0]),
        command(0xa0, &[11, 0, 3, 0, 0xd6, 0, 0, 2, 0, 60], &[0, 3, 0x90, 0]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = poll_iso_dep(&mut reader)?.ok_or("Type 4B card absent")?;
    card.write_type4_ndef(&message)?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_a_timeout_applies_the_official_500ms_selector_before_exchange() -> Result<(), Box<dyn Error>>
{
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(7)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[7, 0, 0xa4, 4, 0], &[0, 0x90, 0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let wait = RfTimeout::new(Duration::from_millis(500))?;
    let mut card = reader.poll_type_a(wait)?.ok_or("expected NFC-A card")?;
    assert_eq!(card.exchange_apdu(&[0, 0xa4, 4, 0])?, [0x90, 0]);
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
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(7)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0x40, &[7, 0xa4], &[0, 0x90, 0]));
    steps.push(command(0x40, &[7, 0xb0], &[0, 0x90, 0]));
    // Selection uses its requested wait, then command40 restores the effective
    // quantized timer. The successfully applied 32/02 selector is still valid.
    steps.push(command(0x1c, &[0x80, 0xc7, 0], &[]));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(9)));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0x40, &[9, 0xa4], &[0, 0x90, 0]));
    // A different timing step changes 32/02. RF-off retains that independent
    // setting; reset must invalidate it even if the next requested step matches.
    steps.push(command(0x1c, &[0x80, 0x63, 0], &[]));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(5)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[5, 0xa4], &[0, 0x90, 0]));
    steps.push(command(0x32, &[1, 0], &[]));
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(6)));
    steps.push(command(0x40, &[6, 0xa4], &[0, 0x90, 0]));
    // Reset revokes the selector; a later activation must program it again.
    steps.extend(initialization(&ab_config_image()));
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(3)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[3, 0xa4], &[0, 0x90, 0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let wait = RfTimeout::new(Duration::from_secs(2))?;
    {
        let mut card = reader.poll_type_a(wait)?.ok_or("expected NFC-A card")?;
        card.exchange_apdu(&[0xa4])?;
        card.exchange_apdu(&[0xb0])?;
    }
    reader
        .poll_type_a(wait)?
        .ok_or("expected NFC-A card")?
        .exchange_apdu(&[0xa4])?;
    let short_wait = RfTimeout::new(Duration::from_millis(500))?;
    reader
        .poll_type_a(short_wait)?
        .ok_or("expected NFC-A card")?
        .exchange_apdu(&[0xa4])?;
    reader.rf_off()?;
    reader
        .poll_type_a(short_wait)?
        .ok_or("expected NFC-A card")?
        .exchange_apdu(&[0xa4])?;
    reader.initialize()?;
    reader
        .poll_type_a(RfTimeout::new(Duration::from_millis(500))?)?
        .ok_or("expected NFC-A card")?
        .exchange_apdu(&[0xa4])?;
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
        steps.push(idle_receiver());
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
            .ok_or("expected NFC-A card")?
            .into_raw();
        let result = card.exchange(&[0xa4]);
        let error = match result {
            Err(TargetExchangeError::Exchange(error)) if lost_command == 0x40 => error,
            Err(TargetExchangeError::Preparation(error)) if lost_command != 0x40 => error,
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
            Err(TargetExchangeError::SessionInvalid)
        ));
        assert_eq!(journal.borrow().requests.len(), count);
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

// FALP fixtures, built from the packet layout independently of the crate.
const FALP_PROCESSING: [u8; 8] = [0, 0x10, 0, 5, 0, 6, 0, 7];
const INITIATOR_PORT: [u8; 2] = [0x34, 0x12];
const TARGET_PORT: [u8; 2] = [0x78, 0x56];
/// One-second waits encoded as half-millisecond ticks.
const SECOND: [u8; 2] = [0xd0, 0x07];
/// Speed1 receive timeout between two Speed1 readers at 424 kbps: 143 ms.
const RECEIVE_WAIT: [u8; 2] = [0x1e, 0x01];
/// The same timeout after a burst without data adds the peer's 200 ms
/// direction switch: 343 ms.
const SWITCH_WAIT: [u8; 2] = [0xae, 0x02];
/// Wait for the next block while the peer holds the turn: 3000 ms.
const DATA_WAIT: [u8; 2] = [0x70, 0x17];

fn falp_packet(pdu: &[u8]) -> Vec<u8> {
    let mut packet = vec![u8::try_from(pdu.len() + 1).unwrap_or(0)];
    packet.extend_from_slice(pdu);
    packet
}

fn falp_envelope(kind: u8, flag: u8, message: &[u8]) -> Vec<u8> {
    let mut pdu = vec![kind, TARGET_PORT[0], TARGET_PORT[1], flag];
    pdu.push(u8::try_from(message.len()).unwrap_or(0));
    pdu.extend_from_slice(message);
    falp_packet(&pdu)
}

fn falp_data(message: &[u8]) -> Vec<u8> {
    falp_envelope(0xbc, 1, message)
}

fn falp_farewell(reason: u16) -> Vec<u8> {
    let [high, low] = reason.to_be_bytes();
    falp_envelope(0xae, 0, &[7, 0, 0, high, low])
}

/// Speed1 parameters from 08 to 2C; `rf` adds the RF overhead and rate.
fn speed1_fields(rf: bool) -> Vec<u8> {
    let mut fields = vec![1, 0, 0, 0xf9, 0, 0, 0x0d, 0xac];
    if rf {
        fields.extend([11, 0, 6, 0x77, 0x46]);
    }
    fields.extend([14, 8, 0, 3, 0x84, 0]);
    for value in [20_000u32, 100_000, 20_000, 100_000, 200_000] {
        fields.extend(value.to_be_bytes());
    }
    fields.extend([0; 5]);
    fields
}

fn handshake_message(application: &[u8]) -> Vec<u8> {
    let mut message = vec![0, 0, 0, u8::try_from(application.len()).unwrap_or(0)];
    message.extend_from_slice(application);
    message.extend(speed1_fields(true));
    message
}

fn response_message() -> Vec<u8> {
    let mut message = vec![1, 0, 0];
    message.extend(speed1_fields(false));
    message
}

fn with_ticks(ticks: [u8; 2], packet: &[u8]) -> Vec<u8> {
    [ticks.as_slice(), packet].concat()
}

fn rf_frame(packet: &[u8]) -> Vec<u8> {
    [&[0], packet].concat()
}

fn answer(idm: [u8; 8]) -> Vec<u8> {
    let mut pdu = vec![0xab];
    pdu.extend(idm);
    pdu.extend([0, 0, 1]);
    pdu.extend(TARGET_PORT);
    falp_packet(&pdu)
}

fn propose(idm: [u8; 8], port: [u8; 2]) -> Vec<u8> {
    let mut pdu = vec![0xaa];
    pdu.extend(idm);
    pdu.extend(port);
    pdu.extend([0x4c, 4, 0, 0]);
    falp_packet(&pdu)
}

fn connected_initiator() -> Vec<Step> {
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 2, 0, 0x12, 0x34, 1, 0], &poll_response()),
        command(6, &FALP_PROCESSING, &[0, 0, 0, 0]),
        command(
            0xa0,
            &with_ticks(SECOND, &propose(IDENTITY, INITIATOR_PORT)),
            &rf_frame(&answer(IDENTITY)),
        ),
        command(
            0xa0,
            &with_ticks(SECOND, &falp_data(&handshake_message(b"A"))),
            &rf_frame(&falp_data(&response_message())),
        ),
    ]);
    steps
}

fn falp_connect(
    card: FelicaCard<'_, Script>,
) -> Result<FalpLink<'_, Script>, FalpError<io::Error>> {
    card.connect_falp(FalpConnect {
        profile: Profile::Speed1,
        application: b"A",
        port: 0x1234,
        propose_timeout: Duration::from_secs(1),
        handshake_timeout: Duration::from_secs(1),
    })
}

fn sent(packet: &[u8]) -> Step {
    command(0xa0, &with_ticks([0, 0], packet), &[1])
}

fn received(wait: [u8; 2], message: &[u8]) -> Step {
    command(0xa0, &wait, &rf_frame(&falp_data(message)))
}

#[test]
fn falp_initiator_connects_exchanges_turns_and_closes() -> Result<(), Box<dyn Error>> {
    let mut steps = connected_initiator();
    steps.extend([
        sent(&falp_data(&[3, 0, 0, b'h', b'i'])),
        received(RECEIVE_WAIT, &[3, 0, 0, b'y', b'o']),
        // An unanswered switch is sent again before the peer's empty turn.
        sent(&falp_data(&[3, 0, 1])),
        command(0xa0, &SWITCH_WAIT, &[1]),
        sent(&falp_data(&[3, 0, 1])),
        received(SWITCH_WAIT, &[3, 0, 1]),
        sent(&falp_farewell(0)),
    ]);
    steps.extend(initialization(&config_image()));
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    let card = reader
        .poll_felica(BitRate::Kbps424, poll_request()?, timeout()?)?
        .ok_or("expected FALP target")?;
    let mut link = falp_connect(card)?;
    assert_eq!(
        link.exchange(b"hi")?,
        FalpTurn::Exchanged {
            sent: 2,
            received: b"yo".to_vec()
        }
    );
    assert_eq!(
        link.exchange(&[])?,
        FalpTurn::Exchanged {
            sent: 0,
            received: Vec::new()
        }
    );
    link.close()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn falp_initiator_requests_a_lost_block_before_delivering_in_order() -> Result<(), Box<dyn Error>> {
    let mut steps = connected_initiator();
    steps.extend([
        sent(&falp_data(&[3, 0, 0])),
        received(SWITCH_WAIT, &[2, 0, 0, b'a']),
        received(DATA_WAIT, &[3, 0, 2, b'c']),
        sent(&falp_data(&[5, 0, 1])),
        received(RECEIVE_WAIT, &[6, 0, 1, b'b']),
    ]);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    let card = reader
        .poll_felica(BitRate::Kbps424, poll_request()?, timeout()?)?
        .ok_or("expected FALP target")?;
    let mut link = falp_connect(card)?;
    assert_eq!(
        link.exchange(&[])?,
        FalpTurn::Exchanged {
            sent: 0,
            received: b"abc".to_vec()
        }
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn falp_initiator_reports_a_window_violation_after_sending_farewell() -> Result<(), Box<dyn Error>>
{
    let mut steps = connected_initiator();
    steps.extend([
        sent(&falp_data(&[3, 0, 0, b'x'])),
        received(RECEIVE_WAIT, &[2, 0x10, 0, b'a']),
        sent(&falp_farewell(0x101)),
    ]);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    let card = reader
        .poll_felica(BitRate::Kbps424, poll_request()?, timeout()?)?
        .ok_or("expected FALP target")?;
    let mut link = falp_connect(card)?;
    assert!(matches!(
        link.exchange(b"x"),
        Err(FalpError::Transfer {
            sent: 1,
            delivered: false,
            cause: TransferCause::Violation(Reason::WINDOW),
            ..
        })
    ));
    assert!(matches!(link.exchange(&[]), Err(FalpError::Unavailable)));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn falp_peer_farewell_ends_the_turn_with_its_reason() -> Result<(), Box<dyn Error>> {
    let mut steps = connected_initiator();
    steps.extend([
        sent(&falp_data(&[3, 0, 0])),
        command(0xa0, &SWITCH_WAIT, &rf_frame(&falp_farewell(0x104))),
    ]);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    let card = reader
        .poll_felica(BitRate::Kbps424, poll_request()?, timeout()?)?
        .ok_or("expected FALP target")?;
    let mut link = falp_connect(card)?;
    assert_eq!(
        link.exchange(&[])?,
        FalpTurn::Closed {
            sent: 0,
            delivered: false,
            received: Vec::new(),
            reason: Some(Reason::LOSS)
        }
    );
    assert!(matches!(link.exchange(&[]), Err(FalpError::Unavailable)));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

const TARGET_IDM: [u8; 8] = [2, 0xfe, 1, 2, 3, 4, 5, 6];

fn falp_listen_steps(application: &[u8]) -> Vec<Step> {
    let mut steps = initialization(&config_image());
    steps.push(command(6, &FALP_PROCESSING, &[0, 0, 0, 0]));
    let mut args = vec![0, 0, 1, 1, 2, 3, 0];
    args.extend(TARGET_IDM);
    args.extend([0, 0x22, 3, 3, 3, 3, 3, 3, 0xfe, 0xe2]);
    args.extend([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x55]);
    steps.push(command(
        0x8c,
        &args,
        &[[0x22].as_slice(), &propose(TARGET_IDM, TARGET_PORT)].concat(),
    ));
    steps.push(command(
        0xa0,
        &with_ticks(SECOND, &answer(TARGET_IDM)),
        &rf_frame(&falp_data(&handshake_message(application))),
    ));
    steps
}

fn falp_listen(
    reader: &mut Reader<Script>,
) -> Result<FalpAccepted<'_, Script>, FalpError<io::Error>> {
    reader.listen_falp(
        FalpListen {
            profile: Profile::Speed1,
            identity: [1, 2, 3, 4, 5, 6],
            applications: &[b"A"],
            handshake_timeout: Duration::from_secs(1),
        },
        RfTimeout::new(Duration::from_secs(1)).map_err(|_| FalpError::TimeoutRange)?,
    )
}

#[test]
fn falp_target_accepts_handshake_and_receives_the_first_burst() -> Result<(), Box<dyn Error>> {
    let mut steps = falp_listen_steps(b"A");
    steps.extend([
        command(0x90, &falp_data(&response_message()), &[0]),
        command(0x88, &[], &rf_frame(&falp_data(&[3, 0, 0, b'h', b'i']))),
    ]);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    let accepted = falp_listen(&mut reader)?;
    assert_eq!(
        accepted.turn,
        FalpTurn::Exchanged {
            sent: 0,
            received: b"hi".to_vec()
        }
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn falp_target_rejects_an_unregistered_application_with_a_farewell() -> Result<(), Box<dyn Error>> {
    let mut steps = falp_listen_steps(b"B");
    steps.push(command(0x90, &falp_farewell(0x105), &[0]));
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    assert!(matches!(
        falp_listen(&mut reader),
        Err(FalpError::Violation(Reason::APPLICATION))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}
