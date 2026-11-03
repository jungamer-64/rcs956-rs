//! Scripted transport behavior tests through the production transaction API.

use rcs956::{
    transport::{Failure, Link, Progress, TransactionError, Transport},
    wire,
};
use std::{cell::RefCell, collections::VecDeque, error::Error, io, rc::Rc, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(1);
const FIRMWARE_REQUEST: [u8; 9] = [0, 0, 0xff, 2, 0xfe, 0xd4, 2, 0x2a, 0];
const FIRMWARE_RESPONSE: [u8; 13] = [0, 0, 0xff, 6, 0xfa, 0xd5, 3, 0x32, 1, 6, 7, 0xe8, 0];

#[derive(Debug)]
enum Read {
    Bytes(Vec<u8>),
    Error(io::ErrorKind),
}

#[derive(Debug)]
enum Write {
    Complete,
    Short(usize),
    Error(io::ErrorKind),
}

#[derive(Debug, Default)]
struct Journal {
    writes: Vec<Vec<u8>>,
    reads: usize,
    recoveries: usize,
}

#[derive(Debug)]
struct Script {
    reads: VecDeque<Read>,
    writes: VecDeque<Write>,
    journal: Rc<RefCell<Journal>>,
}

impl Script {
    fn new(reads: impl IntoIterator<Item = Read>) -> (Self, Rc<RefCell<Journal>>) {
        let journal = Rc::new(RefCell::new(Journal::default()));
        (
            Self {
                reads: reads.into_iter().collect(),
                writes: VecDeque::new(),
                journal: Rc::clone(&journal),
            },
            journal,
        )
    }
}

impl Transport for Script {
    fn write(&mut self, frame: &[u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero(), "expired request reached the backend");
        self.journal.borrow_mut().writes.push(frame.to_vec());
        match self.writes.pop_front().unwrap_or(Write::Complete) {
            Write::Complete => Ok(frame.len()),
            Write::Short(n) => Ok(n),
            Write::Error(kind) => Err(io::Error::new(kind, "scripted write failure")),
        }
    }

    fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero(), "expired read reached the backend");
        self.journal.borrow_mut().reads += 1;
        match self.reads.pop_front() {
            Some(Read::Bytes(bytes)) => {
                let capacity = buffer.len();
                let output = buffer.get_mut(..bytes.len()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("scripted chunk exceeds {capacity}"),
                    )
                })?;
                output.copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            Some(Read::Error(kind)) => Err(io::Error::new(kind, "scripted read failure")),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected backend read",
            )),
        }
    }

    fn recover(&mut self) -> io::Result<()> {
        self.journal.borrow_mut().recoveries += 1;
        Ok(())
    }
}

fn acknowledged_response() -> Vec<u8> {
    [wire::ACK.as_slice(), FIRMWARE_RESPONSE.as_slice()].concat()
}

#[test]
fn coalesced_ack_response_completes_one_transaction() -> Result<(), Box<dyn Error>> {
    let (script, journal) = Script::new([Read::Bytes(acknowledged_response())]);
    let mut link = Link::new(script);
    let response = link.command(2, &[], TIMEOUT)?;
    assert_eq!(response.command, 3);
    assert_eq!(response.data, [0x32, 1, 6, 7]);
    assert_eq!(journal.borrow().writes, [FIRMWARE_REQUEST.to_vec()]);
    assert_eq!(journal.borrow().reads, 1);
    Ok(())
}

#[test]
fn fragmented_ack_and_response_preserve_buffered_bytes() -> Result<(), Box<dyn Error>> {
    let (script, journal) = Script::new([
        Read::Bytes(wire::ACK[..2].to_vec()),
        Read::Bytes([&wire::ACK[2..], &FIRMWARE_RESPONSE[..4]].concat()),
        Read::Bytes(FIRMWARE_RESPONSE[4..].to_vec()),
    ]);
    let mut link = Link::new(script);
    assert_eq!(link.command(2, &[], TIMEOUT)?.data, [0x32, 1, 6, 7]);
    assert_eq!(journal.borrow().reads, 3);
    assert_eq!(journal.borrow().writes.len(), 1);
    Ok(())
}

#[test]
fn ack_loss_is_not_replayed_and_requires_explicit_recovery() -> Result<(), Box<dyn Error>> {
    let (script, journal) = Script::new([
        Read::Error(io::ErrorKind::TimedOut),
        Read::Bytes(acknowledged_response()),
    ]);
    let mut link = Link::new(script);
    let result = link.command(2, &[], TIMEOUT);
    assert!(
        matches!(&result, Err(TransactionError { progress: Progress::Sent, failure: Failure::Io(error) }) if error.kind() == io::ErrorKind::TimedOut),
        "{result:?}"
    );
    assert_eq!(
        journal.borrow().writes.len(),
        1,
        "ACK loss must not replay the command"
    );
    let result = link.command(2, &[], TIMEOUT);
    assert!(matches!(
        result,
        Err(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::RecoveryRequired
        })
    ));
    assert_eq!(journal.borrow().writes.len(), 1);
    link.recover()?;
    assert_eq!(journal.borrow().recoveries, 1);
    assert_eq!(link.command(2, &[], TIMEOUT)?.command, 3);
    assert_eq!(journal.borrow().writes.len(), 2);
    Ok(())
}

#[test]
fn response_loss_preserves_acknowledged_progress_without_replay() {
    let (script, journal) = Script::new([
        Read::Bytes(wire::ACK.to_vec()),
        Read::Error(io::ErrorKind::TimedOut),
    ]);
    let mut link = Link::new(script);
    let result = link.command(2, &[], TIMEOUT);
    assert!(
        matches!(&result, Err(TransactionError { progress: Progress::Acknowledged, failure: Failure::Io(error) }) if error.kind() == io::ErrorKind::TimedOut),
        "{result:?}"
    );
    assert_eq!(journal.borrow().writes.len(), 1);
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::RecoveryRequired
        })
    ));
}

#[test]
fn response_mismatch_preserves_ack_progress_and_poison() {
    let wrong = [0, 0, 0xff, 2, 0xfe, 0xd5, 0x19, 0x12, 0];
    let (script, journal) = Script::new([Read::Bytes(
        [wire::ACK.as_slice(), wrong.as_slice()].concat(),
    )]);
    let mut link = Link::new(script);
    let result = link.command(2, &[], TIMEOUT);
    assert!(matches!(
        result,
        Err(TransactionError {
            progress: Progress::Acknowledged,
            failure: Failure::ResponseCommand {
                expected: 3,
                actual: 0x19
            }
        })
    ));
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::RecoveryRequired
        })
    ));
    assert_eq!(journal.borrow().writes.len(), 1);
}

#[test]
fn short_write_and_write_error_preserve_uncertain_send_progress() {
    for outcome in [Write::Short(3), Write::Error(io::ErrorKind::BrokenPipe)] {
        let (mut script, journal) = Script::new([]);
        script.writes.push_back(outcome);
        let mut link = Link::new(script);
        let result = link.command(2, &[], TIMEOUT);
        assert!(matches!(
            result,
            Err(TransactionError {
                progress: Progress::Sending,
                failure: Failure::ShortWrite {
                    requested: 9,
                    transferred: 3
                } | Failure::Io(_)
            })
        ));
        assert_eq!(journal.borrow().writes.len(), 1);
        assert_eq!(journal.borrow().reads, 0);
        assert!(matches!(
            link.command(2, &[], TIMEOUT),
            Err(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::RecoveryRequired
            })
        ));
    }
}

#[test]
fn nak_and_reader_error_are_not_data_responses() {
    let cases = [
        (wire::NAK.to_vec(), Progress::Sent),
        (
            [wire::ACK.as_slice(), &[0, 0, 0xff, 1, 0xff, 0x7f, 0x81, 0]].concat(),
            Progress::Acknowledged,
        ),
    ];
    for (bytes, expected_progress) in cases {
        let (script, journal) = Script::new([Read::Bytes(bytes)]);
        let mut link = Link::new(script);
        let result = link.command(2, &[], TIMEOUT);
        assert!(
            matches!(&result, Err(TransactionError { progress, failure: Failure::Nak | Failure::ReaderError }) if *progress == expected_progress),
            "{result:?}"
        );
        assert_eq!(journal.borrow().writes.len(), 1);
    }
}

#[test]
fn extra_bytes_after_response_poison_the_stream() {
    let mut bytes = acknowledged_response();
    bytes.extend_from_slice(&wire::NAK);
    let (script, journal) = Script::new([Read::Bytes(bytes)]);
    let mut link = Link::new(script);
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            progress: Progress::Acknowledged,
            failure: Failure::TrailingData
        })
    ));
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::RecoveryRequired
        })
    ));
    assert_eq!(journal.borrow().writes.len(), 1);
}

#[test]
fn host_ack_is_an_out_only_operation() -> Result<(), Box<dyn Error>> {
    let (script, journal) = Script::new([Read::Bytes(acknowledged_response())]);
    let mut link = Link::new(script);
    link.host_ack(TIMEOUT)?;
    assert_eq!(journal.borrow().reads, 0);
    assert_eq!(journal.borrow().writes, [wire::ACK.to_vec()]);
    assert_eq!(link.command(2, &[], TIMEOUT)?.command, 3);
    Ok(())
}

#[test]
fn input_rejection_keeps_a_never_sent_stream_reusable() -> Result<(), Box<dyn Error>> {
    let (script, journal) = Script::new([Read::Bytes(acknowledged_response())]);
    let mut link = Link::new(script);
    let result = link.command(2, &[0; 264], TIMEOUT);
    assert!(matches!(
        result,
        Err(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::Frame(wire::FrameError::PayloadTooLarge { length: 266 })
        })
    ));
    assert!(journal.borrow().writes.is_empty());
    assert_eq!(link.command(2, &[], TIMEOUT)?.command, 3);
    Ok(())
}

#[test]
fn zero_duration_never_starts_a_device_effect() {
    let (script, journal) = Script::new([]);
    let mut link = Link::new(script);
    assert!(matches!(
        link.command(2, &[], Duration::ZERO),
        Err(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::Deadline
        })
    ));
    assert!(matches!(
        link.host_ack(Duration::ZERO),
        Err(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::Deadline
        })
    ));
    assert!(journal.borrow().writes.is_empty());
}
