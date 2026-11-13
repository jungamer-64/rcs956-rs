use super::{
    ActivationError, Error, Reader, ResponseTimeout, RfProtocol, RfTimeout, TargetExchangeError,
};
use crate::transport::Transport;
use alloc::vec::Vec;

/// A selected NFC-A Type 1 tag. Its UID is the four-byte command address
/// returned by RID; it is scoped to this selection.
/// If the reader reports a pending response fragment, reinitialize before
/// selecting another tag or sending another card command.
#[derive(Debug)]
pub struct Type1Tag<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    target: u8,
    timeout: ResponseTimeout,
    header_rom: [u8; 2],
    uid: [u8; 4],
}

impl<T: Transport> Reader<T> {
    /// Activate one legacy Type 1 target at 106 kbps and request its identity.
    /// A pending response fragment during identification requires reinitialization.
    pub fn poll_type1(
        &mut self,
        timeout: RfTimeout,
    ) -> Result<Option<Type1Tag<'_, T>>, TargetExchangeError<T::Error>> {
        self.configure_rf(RfProtocol::TypeA, timeout)
            .map_err(TargetExchangeError::Preparation)?;
        let selection = self
            .list_passive_target(&[1, 4], timeout.host_wait())
            .map_err(|error| match error {
                ActivationError::BeforeRequest(error) => TargetExchangeError::Preparation(error),
                ActivationError::Request(error) => TargetExchangeError::Exchange(error),
            })?;
        let target = match selection.as_slice() {
            [0] => return Ok(None),
            [1, target, _, _, _, _, _, _] if *target != 0 => *target,
            _ => {
                self.require_field_cycle();
                return Err(response_error("Type 1 selection layout"));
            }
        };
        let timeout = ResponseTimeout::for_request(timeout);
        let identity = match type1_exchange(self, target, timeout, &[0x78, 0, 0, 0, 0, 0, 0]) {
            Ok(identity) => identity,
            Err(error) => {
                self.require_field_cycle();
                return Err(error);
            }
        };
        let [hr0, hr1, a, b, c, d] = identity.as_slice() else {
            self.require_field_cycle();
            return Err(response_error("Type 1 RID layout"));
        };
        Ok(Some(Type1Tag {
            reader: self,
            target,
            timeout,
            header_rom: [*hr0, *hr1],
            uid: [*a, *b, *c, *d],
        }))
    }
}

impl<T: Transport> Type1Tag<'_, T> {
    /// Four UID bytes used to address this tag.
    pub fn uid(&self) -> [u8; 4] {
        self.uid
    }

    /// The header ROM returned by RID. HR0 distinguishes static and dynamic layouts.
    pub fn header_rom(&self) -> [u8; 2] {
        self.header_rom
    }

    pub(crate) fn read_static(&mut self) -> Result<[u8; 120], TargetExchangeError<T::Error>> {
        let reply = self.command(0, 0, 0)?;
        let [hr0, _, memory @ ..] = reply.as_slice() else {
            return Err(response_error("Type 1 RALL layout"));
        };
        if *hr0 != self.header_rom[0] || !memory.starts_with(&self.uid) {
            return Err(response_error("Type 1 RALL identity"));
        }
        memory
            .try_into()
            .map_err(|_| response_error("Type 1 RALL length"))
    }

    pub(crate) fn write_byte(
        &mut self,
        address: u8,
        value: u8,
    ) -> Result<(), TargetExchangeError<T::Error>> {
        let reply = self.command(0x53, address, value)?;
        if reply != [address, value] {
            return Err(response_error("Type 1 WRITE-E echo"));
        }
        Ok(())
    }

    fn command(
        &mut self,
        code: u8,
        address: u8,
        data: u8,
    ) -> Result<Vec<u8>, TargetExchangeError<T::Error>> {
        let [a, b, c, d] = self.uid;
        type1_exchange(
            self.reader,
            self.target,
            self.timeout,
            &[code, address, data, a, b, c, d],
        )
    }
}

fn type1_exchange<T: Transport>(
    reader: &mut Reader<T>,
    target: u8,
    timeout: ResponseTimeout,
    command: &[u8],
) -> Result<Vec<u8>, TargetExchangeError<T::Error>> {
    let response = reader.exchange_single_response(RfProtocol::TypeA, target, command, timeout)?;
    if response.status != 0 {
        return Err(TargetExchangeError::Exchange(Error::RfStatus(
            response.status,
        )));
    }
    Ok(response.data)
}

fn response_error<E>(reason: &'static str) -> TargetExchangeError<E> {
    TargetExchangeError::Exchange(Error::Response(reason))
}
