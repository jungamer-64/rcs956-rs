//! Scripted transport behavior tests through the production transaction API.

use rcs956::{
    transport::{Failure, Link, Progress, TransactionError, Transport},
    wire,
};
use std::{cell::RefCell, collections::VecDeque, error::Error, io, rc::Rc, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(1);
const FIRMWARE_REQUEST: [u8; 9] = [0, 0, 0xff, 2, 0xfe, 0xd4, 2, 0x2a, 0];
const FIRMWARE_RESPONSE: [u8; 13] = [0, 0, 0xff, 6, 0xfa, 0xd5, 3, 0x32, 1, 6, 7, 0xe8, 0];
const RESET_RESPONSE: [u8; 9] = [0, 0, 0xff, 2, 0xfe, 0xd5, 0x19, 0x12, 0];

#[derive(Debug)]
enum Read {
    Bytes(Vec<u8>),
    Error(io::ErrorKind),
    OversizedLength,
}

#[derive(Debug)]
enum Write {
    Complete,
    Reported(usize),
    Error(io::ErrorKind),
}

#[derive(Debug, Default)]
struct Journal {
    writes: Vec<Vec<u8>>,
    read_timeouts: Vec<Duration>,
    recoveries: usize,
    elapsed: Duration,
}

#[derive(Debug)]
struct Script {
    reads: VecDeque<Read>,
    read_delays: VecDeque<Duration>,
    writes: VecDeque<Write>,
    recovery_results: VecDeque<Result<(), io::ErrorKind>>,
    journal: Rc<RefCell<Journal>>,
}

impl Script {
    fn new(reads: impl IntoIterator<Item = Read>) -> (Self, Rc<RefCell<Journal>>) {
        let journal = Rc::new(RefCell::new(Journal::default()));
        (
            Self {
                reads: reads.into_iter().collect(),
                read_delays: VecDeque::new(),
                writes: VecDeque::new(),
                recovery_results: VecDeque::new(),
                journal: Rc::clone(&journal),
            },
            journal,
        )
    }
}

impl Transport for Script {
    type Error = io::Error;

    fn monotonic_time(&self) -> Duration {
        self.journal.borrow().elapsed
    }

    fn wait(&mut self, duration: Duration) {
        self.journal.borrow_mut().elapsed += duration;
    }

    fn write(&mut self, frame: &[u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero(), "expired request reached the backend");
        self.journal.borrow_mut().writes.push(frame.to_vec());
        match self.writes.pop_front().unwrap_or(Write::Complete) {
            Write::Complete => Ok(frame.len()),
            Write::Reported(n) => Ok(n),
            Write::Error(kind) => Err(io::Error::new(kind, "scripted write failure")),
        }
    }

    fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero(), "expired read reached the backend");
        {
            let mut journal = self.journal.borrow_mut();
            journal.read_timeouts.push(timeout);
            journal.elapsed += self.read_delays.pop_front().unwrap_or_default();
        }
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
            Some(Read::OversizedLength) => Ok(buffer.len() + 1),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected backend read",
            )),
        }
    }

    fn recover(&mut self) -> io::Result<()> {
        self.journal.borrow_mut().recoveries += 1;
        self.recovery_results
            .pop_front()
            .unwrap_or(Ok(()))
            .map_err(|kind| io::Error::new(kind, "scripted pipe recovery failure"))
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
    assert_eq!(journal.borrow().read_timeouts.len(), 1);
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
    assert_eq!(
        journal.borrow().read_timeouts,
        [20, 20, 998].map(Duration::from_millis)
    );
    assert_eq!(journal.borrow().writes.len(), 1);
    Ok(())
}

#[test]
fn ack_loss_is_not_replayed_and_requires_explicit_recovery() -> Result<(), Box<dyn Error>> {
    let (script, journal) = Script::new([
        Read::Error(io::ErrorKind::TimedOut),
        Read::Bytes([wire::ACK.as_slice(), RESET_RESPONSE.as_slice()].concat()),
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
    assert_eq!(journal.borrow().recoveries, 2);
    assert_eq!(journal.borrow().writes[1], wire::ACK);
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            failure: Failure::RecoveryRequired,
            ..
        })
    ));
    link.reset(TIMEOUT)?.commit()?;
    assert_eq!(link.command(2, &[], TIMEOUT)?.command, 3);
    assert_eq!(journal.borrow().writes.len(), 5);
    Ok(())
}

#[test]
fn recovery_rejects_a_stale_same_command_response_at_the_reset_barrier()
-> Result<(), Box<dyn Error>> {
    let (script, journal) = Script::new([
        Read::Error(io::ErrorKind::TimedOut),
        Read::Bytes(acknowledged_response()),
    ]);
    let mut link = Link::new(script);
    assert!(link.command(2, &[], TIMEOUT).is_err());
    link.recover()?;
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            failure: Failure::RecoveryRequired,
            ..
        })
    ));
    assert!(matches!(
        link.reset(TIMEOUT),
        Err(TransactionError {
            progress: Progress::Acknowledged,
            failure: Failure::ResponseCommand {
                expected: 0x19,
                actual: 3
            },
        })
    ));
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            failure: Failure::RecoveryRequired,
            ..
        })
    ));
    assert_eq!(journal.borrow().writes.len(), 3);
    Ok(())
}

#[test]
fn recovery_and_reset_ack_failures_preserve_poison_and_progress() -> Result<(), Box<dyn Error>> {
    let (mut script, journal) = Script::new([]);
    script
        .recovery_results
        .push_back(Err(io::ErrorKind::NotConnected));
    let mut link = Link::new(script);
    assert!(matches!(
        link.recover(),
        Err(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::Io(_)
        })
    ));
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            failure: Failure::RecoveryRequired,
            ..
        })
    ));
    assert!(journal.borrow().writes.is_empty());

    let (mut script, journal) = Script::new([]);
    script.writes.push_back(Write::Reported(3));
    let mut link = Link::new(script);
    assert!(matches!(
        link.recover(),
        Err(TransactionError {
            progress: Progress::Sending,
            failure: Failure::ShortWrite {
                requested: 6,
                transferred: 3
            }
        })
    ));
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            failure: Failure::RecoveryRequired,
            ..
        })
    ));
    assert_eq!(journal.borrow().writes, [wire::ACK.to_vec()]);

    let (mut script, journal) = Script::new([]);
    script
        .recovery_results
        .extend([Ok(()), Err(io::ErrorKind::NotConnected)]);
    let mut link = Link::new(script);
    assert!(matches!(
        link.recover(),
        Err(TransactionError {
            progress: Progress::Sent,
            failure: Failure::Io(_)
        })
    ));
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            failure: Failure::RecoveryRequired,
            ..
        })
    ));
    assert_eq!(journal.borrow().writes, [wire::ACK.to_vec()]);

    let (mut script, journal) = Script::new([Read::Bytes(
        [wire::ACK.as_slice(), RESET_RESPONSE.as_slice()].concat(),
    )]);
    script
        .writes
        .extend([Write::Complete, Write::Complete, Write::Reported(2)]);
    let mut link = Link::new(script);
    link.recover()?;
    assert!(matches!(
        link.reset(TIMEOUT)?.commit(),
        Err(TransactionError {
            progress: Progress::Sending,
            failure: Failure::ShortWrite {
                requested: 6,
                transferred: 2
            }
        })
    ));
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            failure: Failure::RecoveryRequired,
            ..
        })
    ));
    assert_eq!(journal.borrow().writes.len(), 3);
    Ok(())
}

#[test]
fn reset_commit_waits_before_admitting_the_next_command() -> Result<(), Box<dyn Error>> {
    let (script, journal) = Script::new([
        Read::Bytes([wire::ACK.as_slice(), RESET_RESPONSE.as_slice()].concat()),
        Read::Bytes(acknowledged_response()),
    ]);
    let mut link = Link::new(script);
    let commit = link.reset(TIMEOUT)?;
    let start = journal.borrow().elapsed;
    commit.commit()?;
    assert!(journal.borrow().elapsed >= start + Duration::from_millis(10));
    assert_eq!(journal.borrow().writes[1], wire::ACK);
    link.command(2, &[], TIMEOUT)?;
    assert_eq!(journal.borrow().writes.len(), 3);
    Ok(())
}

#[test]
fn an_uncommitted_reset_requires_recovery() -> Result<(), Box<dyn Error>> {
    let (script, journal) = Script::new([Read::Bytes(
        [wire::ACK.as_slice(), RESET_RESPONSE.as_slice()].concat(),
    )]);
    let mut link = Link::new(script);
    drop(link.reset(TIMEOUT)?);
    for result in [
        link.command(2, &[], TIMEOUT).map(|_| ()),
        link.reset(TIMEOUT).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::RecoveryRequired,
            })
        ));
    }
    assert_eq!(journal.borrow().writes.len(), 1);
    Ok(())
}

#[test]
fn ordinary_commands_cannot_send_reset_or_an_unanswerable_command() -> Result<(), Box<dyn Error>> {
    let (script, journal) = Script::new([Read::Bytes(acknowledged_response())]);
    let mut link = Link::new(script);
    for (command, args) in [(0x18, [1].as_slice()), (0x18, &[]), (0xff, &[])] {
        assert!(matches!(
            link.command(command, args, TIMEOUT),
            Err(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::UnsupportedCommand(actual),
            }) if actual == command
        ));
    }
    assert!(journal.borrow().writes.is_empty());
    assert_eq!(link.command(2, &[], TIMEOUT)?.command, 3);
    Ok(())
}

#[test]
fn malformed_reset_response_cannot_authorize_the_commit_ack() -> Result<(), Box<dyn Error>> {
    let reset_with_body = [0, 0, 0xff, 3, 0xfd, 0xd5, 0x19, 1, 0x11, 0];
    let (script, journal) = Script::new([Read::Bytes(
        [wire::ACK.as_slice(), reset_with_body.as_slice()].concat(),
    )]);
    let mut link = Link::new(script);
    link.recover()?;
    assert!(matches!(
        link.reset(TIMEOUT),
        Err(TransactionError {
            progress: Progress::Acknowledged,
            failure: Failure::ResetResponseLength(1),
        })
    ));
    for result in [
        link.reset(TIMEOUT).map(|_| ()),
        link.command(2, &[], TIMEOUT).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::RecoveryRequired,
            })
        ));
    }
    assert_eq!(journal.borrow().writes.len(), 2);
    Ok(())
}

#[test]
fn coalesced_response_cannot_extend_the_ack_deadline() {
    let (mut script, journal) = Script::new([Read::Bytes(acknowledged_response())]);
    script.read_delays.push_back(Duration::from_millis(21));
    let mut link = Link::new(script);
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            progress: Progress::Sent,
            failure: Failure::Deadline,
        })
    ));
    assert_eq!(journal.borrow().writes.len(), 1);
}

#[test]
fn a_complete_response_must_arrive_before_the_command_deadline() -> Result<(), Box<dyn Error>> {
    for read_us in [499, 500, 600] {
        let (mut script, journal) = Script::new([
            Read::Bytes(wire::ACK.to_vec()),
            Read::Bytes(FIRMWARE_RESPONSE.to_vec()),
        ]);
        script.read_delays = [Duration::ZERO, Duration::from_micros(read_us)].into();
        let mut link = Link::new(script);
        let result = link.command(2, &[], Duration::from_micros(2500));
        if read_us < 500 {
            assert_eq!(result?.data, [0x32, 1, 6, 7]);
        } else {
            assert!(matches!(
                result,
                Err(TransactionError {
                    progress: Progress::Acknowledged,
                    failure: Failure::Deadline,
                })
            ));
            assert!(matches!(
                link.command(2, &[], TIMEOUT),
                Err(TransactionError {
                    progress: Progress::NotSent,
                    failure: Failure::RecoveryRequired,
                })
            ));
        }
        assert_eq!(journal.borrow().writes.len(), 1);
    }
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
fn incomplete_or_misreported_write_preserves_uncertain_send_progress() {
    for outcome in [
        Write::Reported(3),
        Write::Reported(10),
        Write::Error(io::ErrorKind::BrokenPipe),
    ] {
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
                } | Failure::TransmitLength {
                    requested: 9,
                    reported: 10
                } | Failure::Io(_)
            })
        ));
        assert_eq!(journal.borrow().writes.len(), 1);
        assert!(journal.borrow().read_timeouts.is_empty());
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
    for result in [
        link.command(2, &[], Duration::ZERO).map(|_| ()),
        link.reset(Duration::ZERO).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::Deadline
            })
        ));
    }
    assert!(journal.borrow().writes.is_empty());
}

#[test]
fn deadline_expiry_after_the_send_gap_preserves_sent_progress() {
    let (script, journal) = Script::new([]);
    let mut link = Link::new(script);
    assert!(matches!(
        link.command(2, &[], Duration::from_millis(2)),
        Err(TransactionError {
            progress: Progress::Sent,
            failure: Failure::Deadline
        })
    ));
    assert_eq!(journal.borrow().writes, [FIRMWARE_REQUEST]);
    assert!(journal.borrow().read_timeouts.is_empty());
}

#[test]
fn read_count_beyond_capacity_is_a_backend_contract_failure() {
    let (script, journal) = Script::new([Read::OversizedLength]);
    let mut link = Link::new(script);
    assert!(matches!(
        link.command(2, &[], TIMEOUT),
        Err(TransactionError {
            progress: Progress::Sent,
            failure: Failure::ReceiveLength { capacity, reported }
        }) if reported == capacity + 1
    ));
    assert_eq!(journal.borrow().writes, [FIRMWARE_REQUEST]);
}

#[test]
fn transaction_errors_describe_the_failure_and_its_phase() -> Result<(), Box<dyn Error>> {
    let (script, _) = Script::new([Read::Bytes(wire::NAK.to_vec())]);
    let mut link = Link::new(script);
    let error = link.command(2, &[], TIMEOUT).err().ok_or("expected NAK")?;
    assert_eq!(error.to_string(), "reader returned NAK before ACK");
    let error = link
        .command(2, &[], TIMEOUT)
        .err()
        .ok_or("expected poison")?;
    assert_eq!(error.to_string(), "stream requires recovery before sending");
    Ok(())
}
