use super::{Error, Reader, ResponseTimeout, RfProtocol, RfTimeout, TypeAExchangeError};
use crate::transport::Transport;
use alloc::vec::Vec;

/// A selected NFC-A Type 1 tag. Its UID is the four-byte command address
/// returned by RID; it is scoped to this selection.
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
    pub fn poll_type1(
        &mut self,
        timeout: RfTimeout,
    ) -> Result<Option<Type1Tag<'_, T>>, TypeAExchangeError<T::Error>> {
        self.configure_rf(RfProtocol::TypeA, timeout)
            .map_err(TypeAExchangeError::Preparation)?;
        let selection = self
            .command(0x4a, &[1, 4], timeout.host_wait())
            .map_err(TypeAExchangeError::Exchange)?;
        let target = match selection.as_slice() {
            [0] => return Ok(None),
            [1, target, _, _, _, _, _, _] if *target != 0 => *target,
            _ => return Err(response_error("Type 1 selection layout")),
        };
        let timeout = ResponseTimeout::for_request(timeout);
        self.prepare_type_a_exchange(timeout)?;
        let identity = type1_exchange(self, target, timeout, &[0x78, 0, 0, 0, 0, 0, 0])?;
        let [hr0, hr1, a, b, c, d] = identity.as_slice() else {
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

    pub(crate) fn read_static(&mut self) -> Result<[u8; 120], TypeAExchangeError<T::Error>> {
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
    ) -> Result<(), TypeAExchangeError<T::Error>> {
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
    ) -> Result<Vec<u8>, TypeAExchangeError<T::Error>> {
        self.reader.prepare_type_a_exchange(self.timeout)?;
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
) -> Result<Vec<u8>, TypeAExchangeError<T::Error>> {
    let response = reader
        .exchange_target(target, command, timeout)
        .map_err(TypeAExchangeError::Exchange)?;
    if response.status != 0 {
        return Err(response_error("Type 1 reader status"));
    }
    Ok(response.data)
}

fn response_error<E>(reason: &'static str) -> TypeAExchangeError<E> {
    TypeAExchangeError::Exchange(Error::Response(reason))
}
