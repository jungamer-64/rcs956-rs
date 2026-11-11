use super::{Error, Reader, RfTimeout, State};
use crate::{
    ndef::{Message, MessageError},
    transport::Transport,
};
use alloc::vec::Vec;
use core::{fmt, mem, time::Duration};

const CONTROL_WAIT: Duration = Duration::from_secs(1);
const MEMORY_BYTES: usize = 64;
const DATA_START: usize = 16;
const UID_PREFIX: u8 = 0x08;

/// Largest message in the emulated Type 2 tag's read-only data area.
pub const MAX_TYPE2_EMULATED_NDEF_BYTES: usize = MEMORY_BYTES - DATA_START - 2;

/// Error starting or operating the read-only Type 2 target.
#[derive(Debug)]
pub enum Type2EmulationError<E> {
    /// The proposed NDEF does not fit in the emulated memory.
    MessageLength(usize),
    /// The proposed bytes do not encode one complete NDEF message.
    Message(MessageError),
    /// Setup, reception or response failed at the reader boundary.
    Reader(Error<E>),
    /// Firmware activated a mode other than passive Type A at 106 kbps.
    Activation,
    /// Firmware returned malformed data.
    Layout,
    /// Firmware reported an RF or target status.
    Status(u8),
    /// The session has halted or been revoked by a failed exchange.
    SessionUnavailable,
}

impl<E: fmt::Debug> fmt::Display for Type2EmulationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Type2EmulationError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Message(error) => Some(error),
            Self::Reader(error) => Some(error),
            _ => None,
        }
    }
}

impl<E> From<Error<E>> for Type2EmulationError<E> {
    fn from(error: Error<E>) -> Self {
        Self::Reader(error)
    }
}

/// The disposition of one command received from a Type A reader.
#[derive(Debug, PartialEq, Eq)]
pub enum Type2Event {
    /// Replied with four pages beginning at the given page.
    Read(u8),
    /// No response was sent to this unsupported or malformed command.
    Ignored(Vec<u8>),
    /// The initiator halted the tag. Call [Type2Target::finish].
    Halted,
}

/// Exclusive passive target serving an immutable Type 2 memory image.
#[derive(Debug)]
pub struct Type2Target<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    memory: [u8; MEMORY_BYTES],
    state: TargetState,
}

#[derive(Debug)]
enum TargetState {
    FirstCommand(Vec<u8>),
    Waiting,
    Ended,
}

impl<T: Transport> Reader<T> {
    /// Expose an NDEF message as a read-only Type 2 target at 106 kbps.
    /// The UID is 08 followed by the supplied suffix. Initialization and
    /// activation change the firmware mode, which [Type2Target::finish] clears.
    pub fn listen_type2_ndef(
        &mut self,
        uid_suffix: [u8; 3],
        message: &[u8],
        timeout: RfTimeout,
    ) -> Result<Type2Target<'_, T>, Type2EmulationError<T::Error>> {
        let memory = memory_image(uid_suffix, message)?;
        self.initialize()?;
        self.state = State::NeedsInitialization;
        // The 106A target RF profile needs the ROM-07 receiver gain instead
        // of the value copied from EEPROM on some reader variants.
        self.write_register(0x0328, 0x59)?;
        // Disable automatic mode detection before firmware anticollision.
        self.write_register(0x6301, 0x3f)?;
        let [a, b, c] = uid_suffix;
        let mut args = [0; 35];
        args[..7].copy_from_slice(&[0, 4, 0, a, b, c, 0]);
        let activation = self.command(0x8c, &args, timeout.host_wait())?;
        let [0, command @ ..] = activation.as_slice() else {
            return Err(Type2EmulationError::Activation);
        };
        if command.is_empty() {
            return Err(Type2EmulationError::Layout);
        }
        Ok(Type2Target {
            reader: self,
            memory,
            state: TargetState::FirstCommand(command.to_vec()),
        })
    }
}

impl<T: Transport> Type2Target<'_, T> {
    /// Receive one command and reply if it is a READ within the emulated
    /// memory. READ wraps at the end of the static memory. An exchange
    /// failure revokes the target and can leave response delivery uncertain.
    pub fn serve_next(
        &mut self,
        timeout: RfTimeout,
    ) -> Result<Type2Event, Type2EmulationError<T::Error>> {
        let command = match mem::replace(&mut self.state, TargetState::Ended) {
            TargetState::FirstCommand(command) => command,
            TargetState::Waiting => {
                let response = self.reader.command(0x88, &[], timeout.host_wait())?;
                match response.as_slice() {
                    [0, command @ ..] if !command.is_empty() => command.to_vec(),
                    [status, ..] if *status != 0 => {
                        return Err(Type2EmulationError::Status(*status));
                    }
                    _ => return Err(Type2EmulationError::Layout),
                }
            }
            TargetState::Ended => return Err(Type2EmulationError::SessionUnavailable),
        };
        if command == [0x50, 0] {
            return Ok(Type2Event::Halted);
        }
        let event = match command.as_slice() {
            [0x30, page @ 0..=15] => {
                let start = usize::from(*page) * 4;
                let response: [u8; 16] =
                    core::array::from_fn(|index| self.memory[(start + index) % MEMORY_BYTES]);
                match self
                    .reader
                    .command(0x90, &response, CONTROL_WAIT)?
                    .as_slice()
                {
                    [0] => {}
                    [status] => return Err(Type2EmulationError::Status(*status)),
                    _ => return Err(Type2EmulationError::Layout),
                }
                Type2Event::Read(*page)
            }
            _ => Type2Event::Ignored(command),
        };
        self.state = TargetState::Waiting;
        Ok(event)
    }

    /// Stop emulation and return the reader to RF-off readiness.
    pub fn finish(self) -> Result<(), Error<T::Error>> {
        self.reader.initialize().map(|_| ())
    }
}

fn memory_image<E>(
    uid_suffix: [u8; 3],
    message: &[u8],
) -> Result<[u8; MEMORY_BYTES], Type2EmulationError<E>> {
    // The emulated area keeps the message within a one-byte TLV length.
    let length = u8::try_from(message.len())
        .ok()
        .filter(|_| message.len() <= MAX_TYPE2_EMULATED_NDEF_BYTES)
        .ok_or(Type2EmulationError::MessageLength(message.len()))?;
    if !message.is_empty() {
        Message::parse(message).map_err(Type2EmulationError::Message)?;
    }
    let [a, b, c] = uid_suffix;
    let mut memory = [0; MEMORY_BYTES];
    memory[..5].copy_from_slice(&[UID_PREFIX, a, b, c, UID_PREFIX ^ a ^ b ^ c]);
    memory[10..16].copy_from_slice(&[0xff, 0xff, 0xe1, 0x10, 6, 0x0f]);
    memory[16..18].copy_from_slice(&[3, length]);
    memory[18..18 + message.len()].copy_from_slice(message);
    if let Some(terminator) = memory.get_mut(18 + message.len()) {
        *terminator = 0xfe;
    }
    Ok(memory)
}
