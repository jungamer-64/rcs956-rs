//! Bounded ISO-DEP block exchange for the RC-S956 NFC-B path.
//!
//! CRC belongs to the reader. The block engine owns sequencing, CID, chaining
//! and WTX; the caller owns each synchronous RF transfer and classifies RF
//! timeouts. RF recovery requests a block within the same APDU exchange.
use alloc::vec::Vec;
use core::{error, fmt, time::Duration};

/// Local APDU size limit, before applying limits of the selected session.
pub const MAX_APDU_BYTES: usize = 65_535;
const MAX_RESPONSE: usize = 65_536;
const MAX_FRAMES: usize = 2048;
const MAX_WTX: usize = 32;
const MAX_RETRANSMISSIONS: usize = 2;
const MAX_BLOCK_WAIT: Duration = block_frame_wait(14);

pub(crate) fn frame_size(index: u8) -> Option<u16> {
    [16, 24, 32, 40, 48, 64, 96, 128, 256]
        .get(usize::from(index))
        .copied()
}

pub(crate) fn frame_wait(index: u8) -> Duration {
    // ISO-DEP FWT = 4096 carrier periods at 13.56 MHz, rounded upward to ns.
    Duration::from_nanos((4_096_000_000_000u64 * (1u64 << index)).div_ceil(13_560_000))
}

pub(crate) const fn block_frame_wait(index: u8) -> Duration {
    Duration::from_micros(330 * (1u64 << index))
}

/// Activation parameters cannot establish the supported block profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterError {
    /// Unsupported frame capacity, including CRC.
    FrameSize(u16),
    /// CID must be absent or lie in 1..=14.
    Cid(u8),
    /// Reserved node address encoding.
    Nad(u8),
    /// The selected card did not advertise NAD support.
    NadUnsupported,
    /// Base wait must be positive and at most the FWI14 reader wait.
    Wait,
}
impl fmt::Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl error::Error for ParameterError {}

/// ISO-DEP node address with validated source and destination fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeAddress(u8);

impl NodeAddress {
    /// Decode the NAD byte. Bits 4 and 8 and equal nonzero endpoints are reserved.
    pub fn from_byte(value: u8) -> Result<Self, ParameterError> {
        if value & 0x88 != 0 || (value != 0 && value & 7 == value >> 4) {
            return Err(ParameterError::Nad(value));
        }
        Ok(Self(value))
    }

    fn reply(self) -> u8 {
        self.0.rotate_left(4)
    }
}

/// Finite per-APDU policy exhausted before the next operation is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Budget {
    /// Synchronous RF transfers, including WTX and block retransmissions.
    Frames,
    /// WTX requests accepted during this exchange.
    WaitExtensions,
    /// Protocol-requested duplicate block transfers.
    Retransmissions,
    /// Accumulated response application bytes.
    ResponseBytes,
}

/// Why an APDU could not complete; transport failures retain their native type.
#[derive(Debug)]
pub enum Cause<E> {
    /// Reader setup or an RF exchange invalidated this selected session.
    SessionInvalid,
    /// The selected target did not complete ISO-DEP activation.
    ActivationRequired,
    /// Application input exceeds the local or advertised card buffer limit.
    /// No RF was attempted; the session remains reusable.
    InputLength {
        /// Supplied application bytes.
        actual: usize,
        /// Effective maximum after local and card limits are combined.
        maximum: usize,
    },
    /// Reader setup failed before any application block was attempted.
    Preparation(E),
    /// A transfer failed; its application effect can be uncertain.
    Transport(E),
    /// The RF timeout recovery budget is exhausted. The last failure is preserved.
    RecoveryExhausted(E),
    /// A block violates the selected profile or current protocol phase.
    InvalidBlock(&'static str),
    /// The target requested deselection.
    Deselected,
    /// A finite protocol policy was exhausted.
    Budget(Budget),
}

/// Application progress observed during one APDU, separate from RF frame count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    /// Largest application prefix included in a transfer attempt, not proof of delivery.
    pub attempted_application_bytes: usize,
    /// Prefix acknowledged by a valid R-ACK or the first response I-block.
    pub acknowledged_application_bytes: usize,
    /// Valid response application bytes accumulated before completion or failure.
    pub received_application_bytes: usize,
    /// Transfer callback invocations, including unsuccessful ones.
    pub frames: usize,
}

/// A failed exchange, with its partial response and uncertain-effect boundary.
#[derive(Debug)]
pub struct Error<E> {
    /// Machine-readable failure classification.
    pub cause: Cause<E>,
    /// Observed progress; an error never implies the APDU had no effect.
    pub progress: Progress,
    /// Valid response bytes accumulated before failure, without duplicate blocks.
    pub partial_response: Vec<u8>,
}
impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl<E: error::Error + 'static> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.cause {
            Cause::Preparation(error)
            | Cause::Transport(error)
            | Cause::RecoveryExhausted(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
enum State {
    Active(u8),
    Invalid,
}

#[derive(Debug)]
pub(crate) struct Session {
    state: State,
    maximum_frame_bytes: usize,
    maximum_receive_bytes: usize,
    maximum_application_bytes: usize,
    cid: Option<u8>,
    nad: Option<NodeAddress>,
    wait: Duration,
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    Sending { end: usize, more: bool },
    Receiving { previous_was_first: bool },
}

#[derive(Clone, Copy)]
enum Outbound {
    Information,
    Acknowledge,
    RequestRetransmission,
    WaitExtension(u8),
}

impl Session {
    pub(crate) fn new(
        size: u16,
        receive_size: u16,
        cid: Option<u8>,
        wait: Duration,
        card_buffer: Option<usize>,
        nad: Option<NodeAddress>,
    ) -> Result<Self, ParameterError> {
        for size in [size, receive_size] {
            if !(0..=8).any(|index| frame_size(index) == Some(size)) {
                return Err(ParameterError::FrameSize(size));
            }
        }
        if let Some(cid) = cid
            && !(1..=14).contains(&cid)
        {
            return Err(ParameterError::Cid(cid));
        }
        if wait.is_zero() || wait > MAX_BLOCK_WAIT {
            return Err(ParameterError::Wait);
        }
        Ok(Self {
            state: State::Active(0),
            maximum_frame_bytes: usize::from(size.min(64)) - 2,
            maximum_receive_bytes: usize::from(receive_size.min(64)) - 2,
            maximum_application_bytes: card_buffer.unwrap_or(MAX_APDU_BYTES).min(MAX_APDU_BYTES),
            cid,
            nad,
            wait,
        })
    }

    fn frame(&self, pcb: u8, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len() + 2);
        result.push(pcb | if self.cid.is_some() { 8 } else { 0 });
        if let Some(cid) = self.cid {
            result.push(cid);
        }
        result.extend_from_slice(data);
        result
    }

    fn first_capacity(&self) -> usize {
        self.capacity() - usize::from(self.nad.is_some())
    }

    fn capacity(&self) -> usize {
        self.maximum_frame_bytes - 1 - usize::from(self.cid.is_some())
    }

    fn frame_budget_capacity(&self) -> usize {
        self.first_capacity() + (MAX_FRAMES - 1) * self.capacity()
    }

    pub(crate) fn maximum_apdu_bytes(&self) -> usize {
        self.maximum_application_bytes
            .min(self.frame_budget_capacity())
    }

    fn first_i_block(&self, pcb: u8, data: &[u8]) -> Vec<u8> {
        if let Some(address) = self.nad {
            let mut block = self.frame(pcb | 4, &[address.0]);
            block.extend_from_slice(data);
            block
        } else {
            self.frame(pcb, data)
        }
    }

    pub(crate) fn prepare<'s, 'a, E>(
        &'s mut self,
        apdu: &'a [u8],
    ) -> Result<PreparedExchange<'s, 'a>, Error<E>> {
        let number = match self.state {
            State::Active(number) => number,
            State::Invalid => {
                return Err(Error {
                    cause: Cause::SessionInvalid,
                    progress: Progress::default(),
                    partial_response: Vec::new(),
                });
            }
        };
        if apdu.is_empty() || apdu.len() > self.maximum_application_bytes {
            return Err(Error {
                cause: Cause::InputLength {
                    actual: apdu.len(),
                    maximum: self.maximum_application_bytes,
                },
                progress: Progress::default(),
                partial_response: Vec::new(),
            });
        }
        if apdu.len() > self.frame_budget_capacity() {
            return Err(Error {
                cause: Cause::Budget(Budget::Frames),
                progress: Progress::default(),
                partial_response: Vec::new(),
            });
        }
        self.state = State::Invalid;
        Ok(PreparedExchange {
            session: self,
            apdu,
            number,
        })
    }
}

/// Admitted input with exclusive session ownership through reader setup and RF.
/// Setup failure or abandonment invalidates the session without claiming any
/// application bytes were sent. Only a complete response restores reuse.
#[derive(Debug)]
pub(crate) struct PreparedExchange<'s, 'a> {
    session: &'s mut Session,
    apdu: &'a [u8],
    number: u8,
}

impl PreparedExchange<'_, '_> {
    pub(crate) fn exchange<E>(
        self,
        setup: Result<(), E>,
        recoverable: impl Fn(&E) -> bool,
        mut transmit: impl FnMut(&[u8], Duration) -> Result<Vec<u8>, E>,
    ) -> Result<Vec<u8>, Error<E>> {
        let Self {
            session,
            apdu,
            mut number,
        } = self;
        let mut progress = Progress::default();
        let mut output = Vec::new();
        if let Err(error) = setup {
            return Err(Error {
                cause: Cause::Preparation(error),
                progress,
                partial_response: output,
            });
        }
        let capacity = session.capacity();
        let first_end = apdu.len().min(session.first_capacity());
        let mut phase = Phase::Sending {
            end: first_end,
            more: first_end < apdu.len(),
        };
        let mut last_i = session.first_i_block(
            2 | number | if first_end < apdu.len() { 0x10 } else { 0 },
            &apdu[..first_end],
        );
        let mut outbound = Outbound::Information;
        let mut wait = session.wait;
        let mut extensions = 0;
        let mut retransmissions = 0;
        let result = (|| -> Result<(), Cause<E>> {
            loop {
                if progress.frames == MAX_FRAMES {
                    return Err(Cause::Budget(Budget::Frames));
                }
                progress.frames += 1;
                if let Phase::Sending { end, .. } = phase {
                    progress.attempted_application_bytes = end;
                }
                let transfer = match outbound {
                    Outbound::Information => transmit(&last_i, wait),
                    Outbound::Acknowledge => transmit(&session.frame(0xa2 | number, &[]), wait),
                    Outbound::RequestRetransmission => {
                        transmit(&session.frame(0xb2 | number, &[]), wait)
                    }
                    Outbound::WaitExtension(multiplier) => {
                        transmit(&session.frame(0xf2, &[multiplier]), wait)
                    }
                };
                let response = match transfer {
                    Ok(response) => response,
                    Err(error) if recoverable(&error) => {
                        if retransmissions == MAX_RETRANSMISSIONS {
                            return Err(Cause::RecoveryExhausted(error));
                        }
                        retransmissions += 1;
                        outbound = match phase {
                            Phase::Sending { .. } => Outbound::RequestRetransmission,
                            Phase::Receiving { .. } => Outbound::Acknowledge,
                        };
                        wait = session.wait;
                        continue;
                    }
                    Err(error) => return Err(Cause::Transport(error)),
                };
                wait = session.wait;
                if response.is_empty() || response.len() > session.maximum_receive_bytes {
                    return Err(Cause::InvalidBlock("RF block size"));
                }
                let pcb = response[0];
                let with_cid = pcb & 8 != 0;
                if with_cid != session.cid.is_some() {
                    return Err(Cause::InvalidBlock("CID presence"));
                }
                let header = 1 + usize::from(with_cid);
                if response.len() < header {
                    return Err(Cause::InvalidBlock("truncated CID"));
                }
                if let Some(cid) = session.cid
                    && (response[1] & 0x3f != cid)
                {
                    return Err(Cause::InvalidBlock("CID mismatch or reserved bits"));
                }
                let body = &response[header..];
                match pcb & 0xf7 {
                    0xf2 => {
                        if body.len() != 1 || !(1..=59).contains(&(body[0] & 0x3f)) {
                            return Err(Cause::InvalidBlock("WTX multiplier"));
                        }
                        if extensions == MAX_WTX {
                            return Err(Cause::Budget(Budget::WaitExtensions));
                        }
                        extensions += 1;
                        let multiplier = body[0] & 0x3f;
                        // Apply FWT_MAX in the same guarded reader units as the base wait.
                        wait = (session.wait * u32::from(multiplier)).min(MAX_BLOCK_WAIT);
                        outbound = Outbound::WaitExtension(multiplier);
                    }
                    0xc2 => return Err(Cause::Deselected),
                    0xb2 | 0xb3 => return Err(Cause::InvalidBlock("R-NAK from card")),
                    0xa2 | 0xa3 => {
                        if !body.is_empty() {
                            return Err(Cause::InvalidBlock("R-block data"));
                        }
                        let Phase::Sending { end, more } = phase else {
                            return Err(Cause::InvalidBlock("R-block during response"));
                        };
                        if pcb & 1 == number {
                            if !more {
                                return Err(Cause::InvalidBlock("R-ACK without command chaining"));
                            }
                            progress.acknowledged_application_bytes = end;
                            number ^= 1;
                            let next_end = (end + capacity).min(apdu.len());
                            phase = Phase::Sending {
                                end: next_end,
                                more: next_end < apdu.len(),
                            };
                            last_i = session.frame(
                                2 | number | if next_end < apdu.len() { 0x10 } else { 0 },
                                &apdu[end..next_end],
                            );
                            outbound = Outbound::Information;
                        } else {
                            // An unchained I-block may be repeated only when the
                            // card responds to our RF timeout recovery request.
                            if first_end == apdu.len()
                                && !matches!(outbound, Outbound::RequestRetransmission)
                            {
                                return Err(Cause::InvalidBlock("R-ACK for unchained command"));
                            }
                            if retransmissions == MAX_RETRANSMISSIONS {
                                return Err(Cause::Budget(Budget::Retransmissions));
                            }
                            retransmissions += 1;
                            outbound = Outbound::Information;
                        }
                    }
                    0x02 | 0x03 | 0x06 | 0x07 | 0x12 | 0x13 | 0x16 | 0x17 => {
                        if let Phase::Sending { more: true, .. } = phase {
                            return Err(Cause::InvalidBlock(
                                "response before command chain completed",
                            ));
                        }
                        let duplicate = pcb & 1 != number;
                        let first = match (phase, duplicate) {
                            (Phase::Sending { .. }, false) => true,
                            (Phase::Sending { .. }, true) => {
                                return Err(Cause::InvalidBlock("I-block number"));
                            }
                            (Phase::Receiving { previous_was_first }, true) => previous_was_first,
                            (Phase::Receiving { .. }, false) => false,
                        };
                        let expected_nad = session.nad.filter(|_| first).map(NodeAddress::reply);
                        let body = match (expected_nad, pcb & 4 != 0, body) {
                            (Some(expected), true, [actual, rest @ ..]) if *actual == expected => {
                                rest
                            }
                            (None, false, body) => body,
                            _ => return Err(Cause::InvalidBlock("NAD presence or address")),
                        };
                        if duplicate {
                            if retransmissions == MAX_RETRANSMISSIONS {
                                return Err(Cause::Budget(Budget::Retransmissions));
                            }
                            retransmissions += 1;
                            outbound = Outbound::Acknowledge;
                            continue;
                        }
                        progress.acknowledged_application_bytes = apdu.len();
                        if output.len() + body.len() > MAX_RESPONSE {
                            return Err(Cause::Budget(Budget::ResponseBytes));
                        }
                        output.extend_from_slice(body);
                        progress.received_application_bytes = output.len();
                        number ^= 1;
                        if pcb & 0x10 == 0 {
                            return Ok(());
                        }
                        phase = Phase::Receiving {
                            previous_was_first: first,
                        };
                        outbound = Outbound::Acknowledge;
                    }
                    _ => return Err(Cause::InvalidBlock("PCB")),
                }
            }
        })();
        match result {
            Ok(()) => {
                session.state = State::Active(number);
                Ok(output)
            }
            Err(cause) => Err(Error {
                cause,
                progress,
                partial_response: output,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, collections::VecDeque, vec};
    use std::io;

    fn session(size: u16, cid: Option<u8>) -> Result<Session, ParameterError> {
        Session::new(size, 64, cid, block_frame_wait(4), None, None)
    }

    #[test]
    fn command_and_response_chains_use_direction_specific_ack_numbers()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(16, None)?;
        let mut first = vec![0x12];
        first.extend_from_slice(&[0x55; 13]);
        let mut steps = VecDeque::from([
            (first, vec![0xa2]),
            (vec![3, 0x55], vec![0x13, 0xaa]),
            (vec![0xa2], vec![2, 0xbb]),
        ]);
        let result = link.prepare::<io::Error>(&[0x55; 14])?.exchange(
            Ok(()),
            |_| false,
            |frame, wait| {
                let (expected, reply) = steps
                    .pop_front()
                    .ok_or_else(|| io::Error::other("extra transfer"))?;
                assert_eq!(frame, expected);
                assert_eq!(wait, block_frame_wait(4));
                Ok::<_, io::Error>(reply)
            },
        )?;
        assert_eq!(result, [0xaa, 0xbb]);
        assert!(steps.is_empty());
        assert_eq!(
            link.prepare::<io::Error>(&[0x22])?.exchange(
                Ok(()),
                |_| false,
                |frame, _| {
                    assert_eq!(frame, [3, 0x22]);
                    Ok::<_, io::Error>(vec![3, 0x90, 0])
                }
            )?,
            [0x90, 0]
        );
        Ok(())
    }

    #[test]
    fn wtx_and_cid_are_echoed_with_a_separate_wait() -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(256, Some(3))?;
        let mut calls = 0;
        let reply = link.prepare::<io::Error>(&[0xa4])?.exchange(
            Ok(()),
            |_| false,
            |frame, wait| {
                calls += 1;
                match calls {
                    1 => {
                        assert_eq!(frame, [0x0a, 3, 0xa4]);
                        assert_eq!(wait, block_frame_wait(4));
                        Ok::<_, io::Error>(vec![0xfa, 3, 3])
                    }
                    _ => {
                        assert_eq!(frame, [0xfa, 3, 3]);
                        assert_eq!(wait, block_frame_wait(4) * 3);
                        Ok(vec![0x0a, 3, 0x90, 0])
                    }
                }
            },
        )?;
        assert_eq!(calls, 2);
        assert_eq!(reply, [0x90, 0]);
        Ok(())
    }

    #[test]
    fn chained_command_and_response_retry_only_the_current_block()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(16, None)?;
        let first = [&[0x12][..], &[0x55; 13]].concat();
        let mut steps = VecDeque::from([
            (first, vec![0xa2]),
            (vec![3, 0x55], vec![0xa2]),
            (vec![3, 0x55], vec![0x13, 0xaa]),
            (vec![0xa2], vec![0x13, 0xaa]),
            (vec![0xa2], vec![2, 0xbb]),
        ]);
        assert_eq!(
            link.prepare::<io::Error>(&[0x55; 14])?.exchange(
                Ok(()),
                |_| false,
                |frame, _| {
                    let (expected, reply) = steps
                        .pop_front()
                        .ok_or_else(|| io::Error::other("extra transfer"))?;
                    assert_eq!(frame, expected);
                    Ok::<_, io::Error>(reply)
                }
            )?,
            [0xaa, 0xbb]
        );
        assert!(steps.is_empty());
        Ok(())
    }

    #[test]
    fn empty_chained_information_advances_number_without_appending_duplicates()
    -> Result<(), Box<dyn std::error::Error>> {
        for (cid, steps) in [
            (
                None,
                vec![
                    (vec![2, 0xa4], vec![0x12]),
                    (vec![0xa3], vec![0x12]),
                    (vec![0xa3], vec![0x13]),
                    (vec![0xa2], vec![2, 0x90, 0]),
                ],
            ),
            (
                Some(3),
                vec![
                    (vec![0x0a, 3, 0xa4], vec![0x1a, 3]),
                    (vec![0xab, 3], vec![0x1a, 3]),
                    (vec![0xab, 3], vec![0x1b, 3]),
                    (vec![0xaa, 3], vec![0x0a, 3, 0x90, 0]),
                ],
            ),
        ] {
            let mut link = session(64, cid)?;
            let mut steps = VecDeque::from(steps);
            let result = link.prepare::<io::Error>(&[0xa4])?.exchange(
                Ok(()),
                |_| false,
                |frame, _| {
                    let (expected, response) = steps
                        .pop_front()
                        .ok_or_else(|| io::Error::other("extra RF block"))?;
                    assert_eq!(frame, expected);
                    Ok::<_, io::Error>(response)
                },
            )?;
            assert_eq!(result, [0x90, 0]);
            assert!(steps.is_empty());
        }
        Ok(())
    }

    #[test]
    fn transfer_failure_preserves_partial_response_and_invalidates_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(64, None)?;
        let mut calls = 0;
        let error = link
            .prepare::<io::Error>(&[0xa4])?
            .exchange(
                Ok(()),
                |_| false,
                |_, _| {
                    calls += 1;
                    if calls == 1 {
                        Ok(vec![0x12, 0xaa])
                    } else {
                        Err(io::Error::new(io::ErrorKind::TimedOut, "lost response"))
                    }
                },
            )
            .err()
            .ok_or("expected error")?;
        assert!(
            matches!(error.cause, Cause::Transport(ref e) if e.kind() == io::ErrorKind::TimedOut)
        );
        assert_eq!(
            error.progress,
            Progress {
                attempted_application_bytes: 1,
                acknowledged_application_bytes: 1,
                received_application_bytes: 1,
                frames: 2
            }
        );
        assert_eq!(error.partial_response, [0xaa]);
        let retry = link.prepare::<io::Error>(&[0xa4]);
        assert!(matches!(
            retry,
            Err(Error {
                cause: Cause::SessionInvalid,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn preflight_rejection_keeps_session_and_malformed_blocks_poison_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(64, None)?;
        assert!(matches!(
            link.prepare::<io::Error>(&[]),
            Err(Error {
                cause: Cause::InputLength { actual: 0, .. },
                ..
            })
        ));
        assert_eq!(
            link.prepare::<io::Error>(&[0xa4])?.exchange(
                Ok(()),
                |_| false,
                |_, _| Ok::<_, io::Error>(vec![2])
            )?,
            []
        );
        for reply in [
            vec![0xfa, 1, 1],
            vec![0xf2, 0],
            vec![0x06, 0],
            vec![0xa3, 0],
            vec![2; 63],
        ] {
            let mut link = session(64, None)?;
            assert!(matches!(
                link.prepare::<io::Error>(&[1])?.exchange(
                    Ok(()),
                    |_| false,
                    |_, _| Ok::<_, io::Error>(reply.clone())
                ),
                Err(Error {
                    cause: Cause::InvalidBlock(_),
                    ..
                })
            ));
            assert!(matches!(link.state, State::Invalid));
        }
        Ok(())
    }

    #[test]
    fn wait_extensions_and_retransmissions_have_finite_budgets()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(64, None)?;
        let error = link
            .prepare::<io::Error>(&[1])?
            .exchange(Ok(()), |_| false, |_, _| Ok::<_, io::Error>(vec![0xf2, 1]))
            .err()
            .ok_or("expected exhaustion")?;
        assert!(matches!(error.cause, Cause::Budget(Budget::WaitExtensions)));
        assert_eq!(error.progress.frames, 33);
        let mut link = session(16, None)?;
        let error = link
            .prepare::<io::Error>(&[1; 14])?
            .exchange(Ok(()), |_| false, |_, _| Ok::<_, io::Error>(vec![0xa3]))
            .err()
            .ok_or("expected exhaustion")?;
        assert!(matches!(
            error.cause,
            Cause::Budget(Budget::Retransmissions)
        ));
        assert_eq!(error.progress.frames, 3);
        Ok(())
    }

    #[test]
    fn frame_and_response_limits_preserve_their_partial_progress()
    -> Result<(), Box<dyn std::error::Error>> {
        for (body_length, expected) in [
            (0, Budget::Frames),
            (1, Budget::Frames),
            (61, Budget::ResponseBytes),
        ] {
            let mut link = session(64, None)?;
            let mut number = 0u8;
            let error = link
                .prepare::<io::Error>(&[1])?
                .exchange(
                    Ok(()),
                    |_| false,
                    |_, _| {
                        let mut reply = vec![0x12 | number];
                        number ^= 1;
                        reply.resize(body_length + 1, 0xaa);
                        Ok::<_, io::Error>(reply)
                    },
                )
                .err()
                .ok_or("expected exhaustion")?;
            assert!(matches!(error.cause, Cause::Budget(actual) if actual == expected));
            assert_eq!(
                error.partial_response.len(),
                error.progress.received_application_bytes
            );
            assert!(error.progress.acknowledged_application_bytes == 1);
            assert!(error.progress.received_application_bytes <= MAX_RESPONSE);
        }
        let mut link = session(16, None)?;
        let error = link
            .prepare::<io::Error>(&vec![0; MAX_APDU_BYTES])
            .err()
            .ok_or("expected admission failure")?;
        assert!(matches!(error.cause, Cause::Budget(Budget::Frames)));
        assert_eq!(error.progress.frames, 0);
        assert!(matches!(link.state, State::Active(0)));
        Ok(())
    }

    #[test]
    fn negotiated_receive_and_card_buffer_limits_are_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = Session::new(64, 32, None, block_frame_wait(4), Some(128), None)?;
        let error = link
            .prepare::<io::Error>(&[0; 129])
            .err()
            .ok_or("expected input rejection")?;
        assert!(matches!(
            error.cause,
            Cause::InputLength {
                actual: 129,
                maximum: 128
            }
        ));
        assert_eq!(error.progress.frames, 0);
        let error = link
            .prepare::<io::Error>(&[1])?
            .exchange(Ok(()), |_| false, |_, _| Ok::<_, io::Error>(vec![2; 31]))
            .err()
            .ok_or("expected receive limit")?;
        assert!(matches!(error.cause, Cause::InvalidBlock("RF block size")));
        Ok(())
    }
}
