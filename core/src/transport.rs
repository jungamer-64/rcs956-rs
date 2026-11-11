//! Exclusive command transactions over a bounded byte transport.

use crate::wire::{self, Direction, Frame, FrameError};
use alloc::vec::Vec;
use core::{error, fmt, time::Duration};

/// Backend transfer contract. Reads return initialized bytes only; each operation
/// must finish or cancel and reap its I/O before returning. A write error may have
/// sent bytes, so callers must not assume that an error means zero device effects.
pub trait Transport: fmt::Debug {
    /// Backend failure, preserved in transaction errors.
    type Error: error::Error;

    /// Elapsed time since a fixed epoch for this transport. Values must be
    /// nondecreasing and account for transfers and waits.
    fn monotonic_time(&self) -> Duration;
    /// Block for at least the requested duration, including reader settle times.
    fn wait(&mut self, duration: Duration);
    /// Send one frame, including USB ZLP termination when needed.
    fn write(&mut self, frame: &[u8], timeout: Duration) -> Result<usize, Self::Error>;
    /// Receive at most `buffer.len()` bytes within the backend's timeout policy.
    /// Returning zero bytes ends the transaction with [`Failure::Deadline`].
    fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<usize, Self::Error>;
    /// Clear transport stalls and cached bytes. This does not cancel a reader
    /// firmware command or establish whether a prior card operation executed.
    fn recover(&mut self) -> Result<(), Self::Error>;
}

/// Last externally visible phase reached by a failed transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// No send was attempted.
    NotSent,
    /// A send was attempted; the device outcome may be unknown.
    Sending,
    /// Complete host frame sent; ACK has not been observed.
    Sent,
    /// ACK received; a matching response is still needed.
    Acknowledged,
}

/// Machine-readable failure independent of display text.
#[derive(Debug)]
pub enum Failure<E> {
    /// Host validation or reader frame validation failed.
    Frame(FrameError),
    /// OS/device transport failure.
    Io(E),
    /// A prior failed transaction requires explicit recovery.
    RecoveryRequired,
    /// Finite host deadline expired.
    Deadline,
    /// A short host transfer cannot establish command completion.
    ShortWrite {
        /// Requested bytes.
        requested: usize,
        /// Confirmed bytes.
        transferred: usize,
    },
    /// The backend reported more bytes than the supplied buffer could hold.
    ReceiveLength {
        /// Available buffer bytes.
        capacity: usize,
        /// Reported bytes.
        reported: usize,
    },
    /// Reader returned NAK instead of ACK.
    Nak,
    /// Reader returned the special 7F error frame.
    ReaderError,
    /// Frame was valid but occurred in the wrong transaction phase.
    UnexpectedFrame,
    /// [`Link::command`] cannot transact this request command: reset (`18`)
    /// requires [`Link::reset`], and `FF` has no response command.
    UnsupportedCommand(u8),
    /// The response was for a different command.
    ResponseCommand {
        /// Expected response command.
        expected: u8,
        /// Received response command.
        actual: u8,
    },
    /// Reset must return an empty response body. Holds the received body length.
    ResetResponseLength(usize),
    /// A valid response was followed by unconsumed bytes.
    TrailingData,
}

/// Transaction failure plus progress. Any value other than `NotSent` may carry
/// device effects, even if ACK was not seen.
#[derive(Debug)]
pub struct TransactionError<E> {
    /// Phase reached before failure.
    pub progress: Progress,
    /// Specific reason for failure.
    pub failure: Failure<E>,
}
impl<E: fmt::Debug> fmt::Display for TransactionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.failure {
            Failure::Frame(_) => f.write_str("invalid frame")?,
            Failure::Io(_) => f.write_str("transport I/O failed")?,
            Failure::RecoveryRequired => f.write_str("stream requires recovery")?,
            Failure::Deadline => f.write_str("host deadline expired")?,
            Failure::ShortWrite {
                requested,
                transferred,
            } => write!(f, "short write of {transferred} of {requested} bytes")?,
            Failure::ReceiveLength { capacity, reported } => {
                write!(
                    f,
                    "backend reported {reported} bytes for a {capacity}-byte buffer"
                )?;
            }
            Failure::Nak => f.write_str("reader returned NAK")?,
            Failure::ReaderError => f.write_str("reader returned an error frame")?,
            Failure::UnexpectedFrame => {
                f.write_str("unexpected frame for the transaction phase")?
            }
            Failure::UnsupportedCommand(command) => {
                write!(
                    f,
                    "command {command:02X} cannot be sent as an ordinary command"
                )?;
            }
            Failure::ResponseCommand { expected, actual } => {
                write!(f, "response command {actual:02X}, expected {expected:02X}")?;
            }
            Failure::ResetResponseLength(length) => {
                write!(f, "reset response has {length} body bytes")?;
            }
            Failure::TrailingData => f.write_str("unconsumed bytes followed the response")?,
        }
        f.write_str(match self.progress {
            Progress::NotSent => " before sending",
            Progress::Sending => " while sending",
            Progress::Sent => " before ACK",
            Progress::Acknowledged => " after ACK",
        })
    }
}
impl<E: error::Error + 'static> error::Error for TransactionError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.failure {
            Failure::Frame(error) => Some(error),
            Failure::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// Owned command response, with the direction and response command removed.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    /// Matched response command (request + 1).
    pub command: u8,
    /// Command-specific bytes. These do not always begin with a status byte.
    pub data: Vec<u8>,
}

/// Owner of a single, serialized command stream.
#[derive(Debug)]
pub struct Link<T: Transport> {
    transport: T,
    state: StreamState,
}
#[derive(Debug, PartialEq, Eq)]
enum StreamState {
    Ready,
    RecoveryRequired,
    NeedsReset,
}

const RESET: u8 = 0x18;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Deadline(Duration);

impl Deadline {
    fn after(now: Duration, timeout: Duration) -> Option<Self> {
        now.checked_add(timeout).map(Self)
    }

    fn remaining(self, now: Duration) -> Option<Duration> {
        self.0.checked_sub(now).filter(|wait| !wait.is_zero())
    }
}

impl<T: Transport> Link<T> {
    /// Take ownership of a newly opened transport without sending data.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: StreamState::Ready,
        }
    }

    /// Send one command and return its matching response. No automatic replay.
    ///
    /// # Errors
    ///
    /// ACK and response bytes must be returned by the backend before their
    /// respective deadlines. Backend completion itself may take longer.
    /// A failed transaction after the first write attempt requires recovery.
    /// Reset (`18`) is admitted only through [`Link::reset`], and `FF` has no
    /// response command; both are rejected with [`Failure::UnsupportedCommand`].
    pub fn command(
        &mut self,
        command: u8,
        args: &[u8],
        timeout: Duration,
    ) -> Result<Response, TransactionError<T::Error>> {
        if self.state != StreamState::Ready {
            return Err(not_sent(Failure::RecoveryRequired));
        }
        if command == RESET {
            return Err(not_sent(Failure::UnsupportedCommand(command)));
        }
        let expected = command
            .checked_add(1)
            .ok_or(not_sent(Failure::UnsupportedCommand(command)))?;
        let data = self.transact(command, expected, args, timeout)?;
        self.state = StreamState::Ready;
        Ok(Response {
            command: expected,
            data,
        })
    }

    /// Send reset (`18 01`) and require its empty response. The returned
    /// commit must send the host ACK before the link admits commands; dropping
    /// it leaves the link requiring [`Link::recover`].
    ///
    /// # Errors
    ///
    /// Admitted when the link is ready or [`Link::recover`] completed. Failures
    /// follow [`Link::command`]; a nonempty body is
    /// [`Failure::ResetResponseLength`] and is never committed.
    pub fn reset(
        &mut self,
        timeout: Duration,
    ) -> Result<ResetCommit<'_, T>, TransactionError<T::Error>> {
        if !matches!(self.state, StreamState::Ready | StreamState::NeedsReset) {
            return Err(not_sent(Failure::RecoveryRequired));
        }
        let data = self.transact(RESET, RESET + 1, &[1], timeout)?;
        if !data.is_empty() {
            return Err(TransactionError {
                progress: Progress::Acknowledged,
                failure: Failure::ResetResponseLength(data.len()),
            });
        }
        Ok(ResetCommit { link: self })
    }

    /// Run one admitted transaction. The stream stays in `RecoveryRequired`
    /// from the first write until the caller publishes the next state.
    fn transact(
        &mut self,
        command: u8,
        expected: u8,
        args: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, TransactionError<T::Error>> {
        if timeout.is_zero() {
            return Err(not_sent(Failure::Deadline));
        }
        let frame = wire::encode(command, args).map_err(|e| not_sent(Failure::Frame(e)))?;
        let deadline = Deadline::after(self.transport.monotonic_time(), timeout)
            .ok_or(not_sent(Failure::Deadline))?;
        let remaining = deadline
            .remaining(self.transport.monotonic_time())
            .ok_or(not_sent(Failure::Deadline))?;
        // Set the failure state before starting the first externally visible effect.
        self.state = StreamState::RecoveryRequired;
        let sent = self
            .transport
            .write(&frame, remaining)
            .map_err(|e| TransactionError {
                progress: Progress::Sending,
                failure: Failure::Io(e),
            })?;
        if sent != frame.len() {
            return Err(TransactionError {
                progress: Progress::Sending,
                failure: Failure::ShortWrite {
                    requested: frame.len(),
                    transferred: sent,
                },
            });
        }
        self.wait(Duration::from_millis(2));
        let ack_deadline =
            Deadline::after(self.transport.monotonic_time(), Duration::from_millis(20))
                .map_or(deadline, |ack| ack.min(deadline));
        let mut pending = Vec::with_capacity(PENDING_CAPACITY);
        let mut progress = Progress::Sent;
        loop {
            let phase_deadline = if progress == Progress::Sent {
                ack_deadline
            } else {
                deadline
            };
            let packet = next_frame(&mut self.transport, &mut pending, phase_deadline)
                .map_err(|failure| TransactionError { progress, failure })?;
            match wire::parse(&packet, Direction::Reader).map_err(|e| TransactionError {
                progress,
                failure: Failure::Frame(e),
            })? {
                Frame::Ack if progress == Progress::Sent => progress = Progress::Acknowledged,
                Frame::Nak => {
                    return Err(TransactionError {
                        progress,
                        failure: Failure::Nak,
                    });
                }
                Frame::ReaderError => {
                    return Err(TransactionError {
                        progress,
                        failure: Failure::ReaderError,
                    });
                }
                Frame::Data {
                    command: actual,
                    data,
                } if progress == Progress::Acknowledged => {
                    if actual != expected {
                        return Err(TransactionError {
                            progress,
                            failure: Failure::ResponseCommand { expected, actual },
                        });
                    }
                    if !pending.is_empty() {
                        return Err(TransactionError {
                            progress,
                            failure: Failure::TrailingData,
                        });
                    }
                    return Ok(data.to_vec());
                }
                Frame::Ack | Frame::Data { .. } => {
                    return Err(TransactionError {
                        progress,
                        failure: Failure::UnexpectedFrame,
                    });
                }
            }
        }
    }

    fn send_host_ack(&mut self, timeout: Duration) -> Result<(), TransactionError<T::Error>> {
        self.state = StreamState::RecoveryRequired;
        let n = self
            .transport
            .write(&wire::ACK, timeout)
            .map_err(|e| TransactionError {
                progress: Progress::Sending,
                failure: Failure::Io(e),
            })?;
        if n != wire::ACK.len() {
            return Err(TransactionError {
                progress: Progress::Sending,
                failure: Failure::ShortWrite {
                    requested: wire::ACK.len(),
                    transferred: n,
                },
            });
        }
        Ok(())
    }

    /// Clear pipe state, cancel an unfinished reader command with an out-of-band
    /// ACK, wait 10ms, then discard cached input again. The wait also covers an
    /// uncertain preceding reset commit. Only [`Link::reset`] is admitted
    /// afterwards, followed by its committed host ACK.
    /// This never determines whether a preceding card operation executed.
    pub fn recover(&mut self) -> Result<(), TransactionError<T::Error>> {
        self.state = StreamState::RecoveryRequired;
        self.transport
            .recover()
            .map_err(|e| not_sent(Failure::Io(e)))?;
        self.send_host_ack(Duration::from_secs(1))?;
        self.wait(Duration::from_millis(10));
        self.transport.recover().map_err(|e| TransactionError {
            progress: Progress::Sent,
            failure: Failure::Io(e),
        })?;
        self.state = StreamState::NeedsReset;
        Ok(())
    }

    pub(crate) fn wait(&mut self, duration: Duration) {
        self.transport.wait(duration);
    }
}

/// Reset whose empty response was received but whose host ACK is not yet sent.
/// The link admits no other operation while this value borrows it.
#[must_use = "the reset stays uncommitted and the link unusable until commit sends the host ACK"]
#[derive(Debug)]
pub struct ResetCommit<'a, T: Transport> {
    link: &'a mut Link<T>,
}

impl<T: Transport> ResetCommit<'_, T> {
    /// Send the host ACK that commits the reset, then wait 10ms before the link
    /// admits commands.
    ///
    /// # Errors
    ///
    /// A zero timeout sends nothing and leaves the link requiring recovery. A
    /// failed or short ACK write leaves the commit uncertain and also requires
    /// [`Link::recover`].
    pub fn commit(self, timeout: Duration) -> Result<(), TransactionError<T::Error>> {
        if timeout.is_zero() {
            return Err(not_sent(Failure::Deadline));
        }
        self.link.send_host_ack(timeout)?;
        self.link.wait(Duration::from_millis(10));
        self.link.state = StreamState::Ready;
        Ok(())
    }
}

fn not_sent<E>(failure: Failure<E>) -> TransactionError<E> {
    TransactionError {
        progress: Progress::NotSent,
        failure,
    }
}

/// Bytes read per backend call; one call can hold a complete frame.
const READ_CHUNK: usize = wire::MAX_FRAME;
/// `pending` holds less than one frame before each read, so it never exceeds
/// an incomplete frame plus one chunk.
const PENDING_CAPACITY: usize = wire::MAX_FRAME - 1 + READ_CHUNK;

fn next_frame<T: Transport>(
    transport: &mut T,
    pending: &mut Vec<u8>,
    deadline: Deadline,
) -> Result<Vec<u8>, Failure<T::Error>> {
    loop {
        if let Some(length) = wire::frame_length(pending).map_err(Failure::Frame)?
            && pending.len() >= length
        {
            return Ok(pending.drain(..length).collect());
        }
        let remaining = deadline
            .remaining(transport.monotonic_time())
            .ok_or(Failure::Deadline)?;
        let mut buffer = [0u8; READ_CHUNK];
        let n = transport
            .read(&mut buffer, remaining)
            .map_err(Failure::Io)?;
        // Admit only bytes from a read that completed before the deadline.
        if n == 0 || deadline.remaining(transport.monotonic_time()).is_none() {
            return Err(Failure::Deadline);
        }
        let bytes = buffer.get(..n).ok_or(Failure::ReceiveLength {
            capacity: buffer.len(),
            reported: n,
        })?;
        pending.extend_from_slice(bytes);
    }
}
