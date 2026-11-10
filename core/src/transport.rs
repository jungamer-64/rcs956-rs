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
        write!(f, "transaction {:?}: {:?}", self.progress, self.failure)
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
    ResetCommitPending,
}

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
    /// Reset (`18 01`) requires an empty response before a host ACK can commit it.
    pub fn command(
        &mut self,
        command: u8,
        args: &[u8],
        timeout: Duration,
    ) -> Result<Response, TransactionError<T::Error>> {
        let is_reset = command == 0x18 && args == [1];
        if self.state != StreamState::Ready && !(self.state == StreamState::NeedsReset && is_reset)
        {
            return Err(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::RecoveryRequired,
            });
        }
        if timeout.is_zero() {
            return Err(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::Deadline,
            });
        }
        let frame = wire::encode(command, args).map_err(|e| TransactionError {
            progress: Progress::NotSent,
            failure: Failure::Frame(e),
        })?;
        let expected = command.checked_add(1).ok_or(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::UnexpectedFrame,
        })?;
        let deadline =
            Deadline::after(self.transport.monotonic_time(), timeout).ok_or(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::Deadline,
            })?;
        let remaining =
            deadline
                .remaining(self.transport.monotonic_time())
                .ok_or(TransactionError {
                    progress: Progress::NotSent,
                    failure: Failure::Deadline,
                })?;
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
        let mut pending = Vec::with_capacity(600);
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
                    let next_state = if is_reset {
                        if !data.is_empty() {
                            return Err(TransactionError {
                                progress,
                                failure: Failure::ResetResponseLength(data.len()),
                            });
                        }
                        StreamState::ResetCommitPending
                    } else {
                        StreamState::Ready
                    };
                    let response = Response {
                        command: actual,
                        data: data.to_vec(),
                    };
                    self.state = next_state;
                    return Ok(response);
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

    /// Send a host ACK without expecting another ACK. A reset response must be
    /// committed with this ACK; the link waits 10ms before admitting commands.
    pub fn host_ack(&mut self, timeout: Duration) -> Result<(), TransactionError<T::Error>> {
        if !matches!(
            self.state,
            StreamState::Ready | StreamState::ResetCommitPending
        ) {
            return Err(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::RecoveryRequired,
            });
        }
        if timeout.is_zero() {
            return Err(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::Deadline,
            });
        }
        let reset_commit = self.state == StreamState::ResetCommitPending;
        self.send_host_ack(timeout)?;
        if reset_commit {
            self.wait(Duration::from_millis(10));
        }
        self.state = StreamState::Ready;
        Ok(())
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
    /// uncertain preceding reset commit. Only reset (`18 01`) is
    /// admitted afterwards, followed by its response and committed host ACK.
    /// This never determines whether a preceding card operation executed.
    pub fn recover(&mut self) -> Result<(), TransactionError<T::Error>> {
        self.state = StreamState::RecoveryRequired;
        self.transport.recover().map_err(|e| TransactionError {
            progress: Progress::NotSent,
            failure: Failure::Io(e),
        })?;
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
        let mut buffer = [0u8; 300];
        let n = transport
            .read(&mut buffer, remaining)
            .map_err(Failure::Io)?;
        if n == 0 || deadline.remaining(transport.monotonic_time()).is_none() {
            return Err(Failure::Deadline);
        }
        let bytes = buffer.get(..n).ok_or(Failure::ReceiveLength {
            capacity: buffer.len(),
            reported: n,
        })?;
        if pending.len() + n > 600 {
            return Err(Failure::TrailingData);
        }
        pending.extend_from_slice(bytes);
    }
}
