use std::{rc::Rc, thread, time::Duration};

use rcs956::transport::Transport;
use rcs956_usb_abi as abi;

use super::{
    queue::{Queues, Request},
    status::{self, Status},
    usb::UsbTransport,
    worker::Control,
};

pub(crate) struct Frontend {
    transport: UsbTransport,
    queues: Queues,
    release: u16,
    control: Rc<Control>,
}

impl Frontend {
    pub(crate) fn new(
        transport: UsbTransport,
        queues: Queues,
        release: u16,
        control: Rc<Control>,
    ) -> Result<Self, Status> {
        Ok(Self {
            transport,
            queues,
            release,
            control,
        })
    }

    pub(crate) fn run(&mut self) {
        while !self.control.stopping() {
            if let Some(request) = self.queues.pop() {
                self.complete(request);
            } else {
                thread::park();
            }
        }
    }

    fn complete(&mut self, request: Request) {
        let result = request.decode().and_then(|(code, input, capacity)| {
            match Command::parse(code, &input, capacity)? {
                Command::Write { wait, bytes } => {
                    let count = self.transport.write(bytes, wait)?;
                    Ok((count as u32).to_le_bytes().to_vec())
                }
                Command::Read { wait, bytes } => {
                    let mut buffer = vec![0; bytes];
                    let count = self.transport.read(&mut buffer, wait)?;
                    if count > buffer.len() {
                        return Err(Status(status::DEVICE_PROTOCOL_ERROR));
                    }
                    buffer.truncate(count);
                    Ok(buffer)
                }
                Command::Recover => {
                    self.transport.recover()?;
                    Ok(Vec::new())
                }
                Command::DeviceRelease => Ok(self.release.to_le_bytes().to_vec()),
            }
        });
        match result {
            Ok(response) => request.reply(&response),
            Err(error) => request.fail(error),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Command<'a> {
    Write { wait: Duration, bytes: &'a [u8] },
    Read { wait: Duration, bytes: usize },
    Recover,
    DeviceRelease,
}

impl<'a> Command<'a> {
    fn parse(code: u32, input: &'a [u8], capacity: usize) -> Result<Self, Status> {
        let invalid = Status(status::INVALID_PARAMETER);
        match code {
            abi::WRITE => {
                let (wait, bytes) = abi::decode_timeout(input).ok_or(invalid)?;
                if bytes.len() > abi::MAX_TRANSFER {
                    return Err(invalid);
                }
                if capacity < abi::WORD {
                    return Err(Status(status::BUFFER_TOO_SMALL));
                }
                Ok(Self::Write { wait, bytes })
            }
            abi::READ => {
                let (wait, bytes) = abi::decode_timeout(input).ok_or(invalid)?;
                if !bytes.is_empty() || !(1..=abi::MAX_TRANSFER).contains(&capacity) {
                    return Err(invalid);
                }
                Ok(Self::Read {
                    wait,
                    bytes: capacity,
                })
            }
            abi::RECOVER if input.is_empty() && capacity == 0 => Ok(Self::Recover),
            abi::RECOVER => Err(invalid),
            abi::DEVICE_RELEASE if !input.is_empty() => Err(invalid),
            abi::DEVICE_RELEASE if capacity < abi::RELEASE => Err(Status(status::BUFFER_TOO_SMALL)),
            abi::DEVICE_RELEASE => Ok(Self::DeviceRelease),
            _ => Err(Status(status::NOT_SUPPORTED)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_parameters_are_validated_before_submission() {
        assert_eq!(
            Command::parse(abi::WRITE, &[10, 0, 0, 0, 0xa5], 4),
            Ok(Command::Write {
                wait: Duration::from_millis(10),
                bytes: &[0xa5],
            })
        );
        assert_eq!(
            Command::parse(abi::WRITE, &[10, 0, 0, 0, 0xa5], 3),
            Err(Status(status::BUFFER_TOO_SMALL))
        );
        assert_eq!(
            Command::parse(abi::READ, &[10, 0, 0, 0], 4096),
            Ok(Command::Read {
                wait: Duration::from_millis(10),
                bytes: 4096,
            })
        );
        assert_eq!(
            Command::parse(abi::READ, &[10, 0, 0, 0], 4097),
            Err(Status(status::INVALID_PARAMETER))
        );
        assert_eq!(Command::parse(abi::RECOVER, &[], 0), Ok(Command::Recover));
        assert_eq!(
            Command::parse(abi::RECOVER, &[0], 0),
            Err(Status(status::INVALID_PARAMETER))
        );
        assert_eq!(
            Command::parse(abi::DEVICE_RELEASE, &[], abi::RELEASE),
            Ok(Command::DeviceRelease)
        );
        assert_eq!(
            Command::parse(abi::DEVICE_RELEASE, &[], abi::RELEASE - 1),
            Err(Status(status::BUFFER_TOO_SMALL))
        );
        assert_eq!(
            Command::parse(abi::DEVICE_RELEASE, &[0], abi::RELEASE),
            Err(Status(status::INVALID_PARAMETER))
        );
    }
}
