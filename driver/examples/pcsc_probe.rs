//! Exercise the installed reader through the Windows resource manager.

use std::{
    io,
    mem::size_of,
    ptr::{null, null_mut},
};

use rcs956::isodep::MAX_APDU_BYTES;
use windows_sys::Win32::Security::Credentials::{
    SCARD_IO_REQUEST, SCARD_LEAVE_CARD, SCARD_PROTOCOL_T1, SCARD_SCOPE_SYSTEM, SCARD_SHARE_SHARED,
    SCardConnectW, SCardDisconnect, SCardEstablishContext, SCardListReadersW, SCardReleaseContext,
    SCardStatusW, SCardTransmit,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(mode) = args.next() else {
        return Err("usage: pcsc_probe list | connect [APDU_HEX]".into());
    };
    let apdu = args.next().map(|hex| parse_apdu(&hex)).transpose()?;
    if args.next().is_some() || (mode == "list" && apdu.is_some()) {
        return Err("usage: pcsc_probe list | connect [APDU_HEX]".into());
    }
    let context = Context::open()?;
    let readers = context.readers()?;
    let names: Vec<_> = readers
        .split(|&code| code == 0)
        .take_while(|name| !name.is_empty())
        .collect();
    if mode == "list" {
        for name in names {
            println!("{}", String::from_utf16_lossy(name));
        }
        return Ok(());
    }
    if mode != "connect" {
        return Err("usage: pcsc_probe list | connect [APDU_HEX]".into());
    }
    let mut matching = names
        .into_iter()
        .filter(|name| String::from_utf16_lossy(name).contains("RC-S956"));
    let name = matching
        .next()
        .ok_or("RC-S956 is absent from SCardListReadersW")?;
    if matching.next().is_some() {
        return Err("more than one RC-S956 is registered".into());
    }
    let mut name = name.to_vec();
    name.push(0);
    let card = context.connect(&name)?;
    let atr = card.atr()?;
    println!("ATR: {}", hex(&atr));
    if let Some(apdu) = apdu {
        println!("Response: {}", hex(&card.transmit(&apdu)?));
    }
    card.disconnect()?;
    Ok(())
}

fn parse_apdu(hex: &str) -> Result<Vec<u8>, io::Error> {
    if !(8..=2 * MAX_APDU_BYTES).contains(&hex.len())
        || !hex.len().is_multiple_of(2)
        || !hex.is_ascii()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("expected a 4–{MAX_APDU_BYTES} byte hexadecimal APDU"),
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

struct Context(usize);

impl Context {
    fn open() -> io::Result<Self> {
        let mut context = 0;
        // SAFETY: Reserved inputs are null and the context out pointer is valid.
        check(unsafe { SCardEstablishContext(SCARD_SCOPE_SYSTEM, null(), null(), &mut context) })?;
        Ok(Self(context))
    }

    fn readers(&self) -> io::Result<Vec<u16>> {
        let mut len = 0;
        // SAFETY: The live context is used for a length-only query.
        check(unsafe { SCardListReadersW(self.0, null(), null_mut(), &mut len) })?;
        let mut data = vec![0; len as usize];
        // SAFETY: The output has the specified capacity of UTF-16 code units.
        check(unsafe { SCardListReadersW(self.0, null(), data.as_mut_ptr(), &mut len) })?;
        data.truncate(len as usize);
        Ok(data)
    }

    fn connect(&self, reader: &[u16]) -> io::Result<Card<'_>> {
        let mut handle = 0;
        let mut protocol = 0;
        // SAFETY: The caller supplies a nul-terminated name from this context,
        // and both output pointers are writable.
        check(unsafe {
            SCardConnectW(
                self.0,
                reader.as_ptr(),
                SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T1,
                &mut handle,
                &mut protocol,
            )
        })?;
        let card = Card {
            handle: Some(handle),
            _context: self,
        };
        if protocol != SCARD_PROTOCOL_T1 {
            return Err(io::Error::other("WinSCard did not select T=1"));
        }
        Ok(card)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: The context owns this handle and outlives all card connections.
        unsafe { SCardReleaseContext(self.0) };
    }
}

struct Card<'a> {
    handle: Option<usize>,
    _context: &'a Context,
}

impl Card<'_> {
    fn atr(&self) -> io::Result<Vec<u8>> {
        let handle = self
            .handle
            .ok_or_else(|| io::Error::other("card is disconnected"))?;
        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut state = 0;
        let mut protocol = 0;
        let mut atr = [0; 36];
        let mut atr_len = atr.len() as u32;
        // SAFETY: The handle is connected and all buffers have the given capacities.
        check(unsafe {
            SCardStatusW(
                handle,
                name.as_mut_ptr(),
                &mut name_len,
                &mut state,
                &mut protocol,
                atr.as_mut_ptr(),
                &mut atr_len,
            )
        })?;
        let atr = atr
            .get(..atr_len as usize)
            .ok_or_else(|| io::Error::other("invalid ATR length"))?;
        if atr.len() < 5 || atr[0] != 0x3b || atr[1..].iter().fold(0, |sum, &byte| sum ^ byte) != 0
        {
            return Err(io::Error::other("invalid contactless ATR"));
        }
        Ok(atr.to_vec())
    }

    fn transmit(&self, apdu: &[u8]) -> io::Result<Vec<u8>> {
        let handle = self
            .handle
            .ok_or_else(|| io::Error::other("card is disconnected"))?;
        let pci = SCARD_IO_REQUEST {
            dwProtocol: SCARD_PROTOCOL_T1,
            cbPciLength: size_of::<SCARD_IO_REQUEST>() as u32,
        };
        let mut data = vec![0; 65_536];
        let mut len = data.len() as u32;
        // SAFETY: The PCI and APDU are valid inputs and the response buffer is writable.
        check(unsafe {
            SCardTransmit(
                handle,
                &pci,
                apdu.as_ptr(),
                apdu.len() as u32,
                null_mut(),
                data.as_mut_ptr(),
                &mut len,
            )
        })?;
        if !(2..=data.len()).contains(&(len as usize)) {
            return Err(io::Error::other("invalid APDU response length"));
        }
        data.truncate(len as usize);
        Ok(data)
    }

    fn disconnect(mut self) -> io::Result<()> {
        let handle = self
            .handle
            .take()
            .ok_or_else(|| io::Error::other("card is disconnected"))?;
        // SAFETY: Ownership of the live card handle is consumed by the disconnect.
        check(unsafe { SCardDisconnect(handle, SCARD_LEAVE_CARD) })
    }
}

impl Drop for Card<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // SAFETY: This owns the remaining card handle after an earlier operation failed.
            unsafe { SCardDisconnect(handle, SCARD_LEAVE_CARD) };
        }
    }
}

fn check(status: i32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "WinSCard {:#010x}",
            status as u32
        )))
    }
}
