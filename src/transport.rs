//! Exclusive command transactions over a bounded byte transport.
#![forbid(unsafe_code)]

use crate::wire::{self, Direction, Frame, FrameError};
use std::{
    fmt, io, thread,
    time::{Duration, Instant},
};

/// Backend transfer contract. Reads return initialized bytes only; each operation
/// must finish or cancel and reap its I/O before returning. A write error may have
/// sent bytes, so callers must not assume that an error means zero device effects.
pub trait Transport: fmt::Debug {
    /// Send one frame, including USB ZLP termination when needed.
    fn write(&mut self, frame: &[u8], timeout: Duration) -> io::Result<usize>;
    /// Receive at most `buffer.len()` bytes within the backend's timeout policy.
    fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> io::Result<usize>;
    /// Clear transport stalls and cached bytes. This does not cancel a reader
    /// firmware command or establish whether a prior card operation executed.
    fn recover(&mut self) -> io::Result<()>;
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
pub enum Failure {
    /// Host validation or reader frame validation failed.
    Frame(FrameError),
    /// OS/device transport failure.
    Io(io::Error),
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
    /// A valid response was followed by unconsumed bytes.
    TrailingData,
}

/// Transaction failure plus progress. Any value other than `NotSent` may carry
/// device effects, even if ACK was not seen.
#[derive(Debug)]
pub struct TransactionError {
    /// Phase reached before failure.
    pub progress: Progress,
    /// Specific reason for failure.
    pub failure: Failure,
}
impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transaction {:?}: {:?}", self.progress, self.failure)
    }
}
impl std::error::Error for TransactionError {}

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

impl<T: Transport> Link<T> {
    /// Take ownership of a newly opened transport without sending data.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: StreamState::Ready,
        }
    }

    /// Send one command and return its matching response. No automatic replay.
    pub fn command(
        &mut self,
        command: u8,
        args: &[u8],
        timeout: Duration,
    ) -> Result<Response, TransactionError> {
        if self.state != StreamState::Ready
            && !(self.state == StreamState::NeedsReset && command == 0x18 && args == [1]) {
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
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::Deadline,
            })?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
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
        thread::sleep(Duration::from_millis(2));
        let ack_deadline = Instant::now()
            .checked_add(Duration::from_millis(20))
            .map_or(deadline, |a| a.min(deadline));
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
                    let response = Response {
                        command: actual,
                        data: data.to_vec(),
                    };
                    self.state = if command == 0x18 && args == [1] {
                        StreamState::ResetCommitPending
                    } else {
                        StreamState::Ready
                    };
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
    pub fn host_ack(&mut self, timeout: Duration) -> Result<(), TransactionError> {
        if !matches!(self.state, StreamState::Ready | StreamState::ResetCommitPending) {
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
        if reset_commit { thread::sleep(Duration::from_millis(10)); }
        self.state = StreamState::Ready;
        Ok(())
    }

    fn send_host_ack(&mut self, timeout: Duration) -> Result<(), TransactionError> {
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
    /// ACK, wait 1ms, then discard cached input again. Only reset (`18 01`) is
    /// admitted afterwards, followed by its response and committed host ACK.
    /// This never determines whether a preceding card operation executed.
    pub fn recover(&mut self) -> Result<(), TransactionError> {
        self.state = StreamState::RecoveryRequired;
        self.transport.recover().map_err(|e| TransactionError { progress: Progress::NotSent, failure: Failure::Io(e) })?;
        self.send_host_ack(Duration::from_secs(1))?;
        thread::sleep(Duration::from_millis(1));
        self.transport.recover().map_err(|e| TransactionError { progress: Progress::Sent, failure: Failure::Io(e) })?;
        self.state = StreamState::NeedsReset;
        Ok(())
    }
}

fn next_frame<T: Transport>(
    transport: &mut T,
    pending: &mut Vec<u8>,
    deadline: Instant,
) -> Result<Vec<u8>, Failure> {
    loop {
        if let Some(length) = wire::frame_length(pending).map_err(Failure::Frame)?
            && pending.len() >= length
        {
            return Ok(pending.drain(..length).collect());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(Failure::Deadline)?;
        let mut buffer = [0u8; 300];
        let n = transport
            .read(&mut buffer, remaining)
            .map_err(Failure::Io)?;
        if n == 0 {
            return Err(Failure::Deadline);
        }
        let bytes = buffer.get(..n).ok_or_else(|| {
            Failure::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "backend exceeded receive capacity",
            ))
        })?;
        if pending.len() + n > 600 {
            return Err(Failure::TrailingData);
        }
        pending.extend_from_slice(bytes);
    }
}
