//! Command-line discovery and read-only hardware validation for RC-S956.
#![forbid(unsafe_code)]

use rcs956::{
    felica::PollRequest,
    reader::{Reader, RfTimeout},
    transport::Transport,
};
use std::{error::Error, time::Duration};

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
fn help() {
    println!(
        "rcs956 devices\nrcs956 probe [--path DEVICE_INTERFACE]\nrcs956 poll [--system FFFF] [--request 1] [--slots 0] [--timeout-ms 500] [--path PATH]\nrcs956 read --service HEX --blocks DECIMAL[,DECIMAL...] [poll options]\nrcs956 decode READER_FRAME_HEX\n\nHardware commands use an existing WinUSB binding. No driver installation or card writes.\nA read requires a service known to exist on the card. No automatic command retries."
    );
}
fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        help();
        return Ok(());
    };
    if matches!(command.as_str(), "--help" | "-h" | "help") {
        help();
        return Ok(());
    }
    if command == "decode" {
        let text = args.collect::<Vec<_>>().join(" ");
        let bytes = hex_bytes(&text)?;
        println!(
            "{:?}",
            rcs956::wire::parse(&bytes, rcs956::wire::Direction::Reader)?
        );
        return Ok(());
    }
    if command == "devices" {
        if args.next().is_some() {
            return Err("devices takes no options".into());
        }
        return list_devices();
    }
    if !matches!(command.as_str(), "probe" | "poll" | "read") {
        return Err(format!("unknown command: {command}").into());
    }
    let mut path = None;
    let mut system = 0xffff;
    let mut request = 1;
    let mut slots = 0;
    let mut timeout = 500u64;
    let mut service = None;
    let mut blocks = None;
    while let Some(key) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {key}"))?;
        match key.as_str() {
            "--path" => path = Some(value),
            "--system" => system = hex_u16(&value)?,
            "--request" => request = u8::try_from(hex_u16(&value)?)?,
            "--slots" => slots = u8::try_from(hex_u16(&value)?)?,
            "--timeout-ms" => timeout = value.parse()?,
            "--service" => service = Some(hex_u16(&value)?),
            "--blocks" => {
                blocks = Some(
                    value
                        .split(',')
                        .map(str::parse::<u16>)
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            _ => return Err(format!("unknown option: {key}").into()),
        }
    }
    if command == "read" && (service.is_none() || blocks.is_none()) {
        return Err("read requires --service and --blocks".into());
    }
    if blocks
        .as_ref()
        .is_some_and(|b| !(1..=12).contains(&b.len()))
    {
        return Err("read requires 1..12 block numbers".into());
    }
    if command != "read" && (service.is_some() || blocks.is_some()) {
        return Err("--service/--blocks require read".into());
    }
    let request = PollRequest::new(system, request, slots)?;
    let timeout = RfTimeout::new(Duration::from_millis(timeout))?;
    #[cfg(windows)]
    {
        let path = select_path(path)?;
        let usb = rcs956::windows::WinUsb::open(&path)?;
        println!("Interface: {path}");
        let mut reader = Reader::new(usb);
        let info = reader.initialize()?;
        println!(
            "Firmware: {}\nModel: {:04X}\nReader flags: {:02X}\nConfiguration: 256 bytes; signature/checksums passed",
            hex(&info.firmware),
            info.configuration.model(),
            info.flags
        );
        let result = if command == "probe" {
            Ok(())
        } else {
            card_operation(&mut reader, request, timeout, service, blocks.as_deref())
        };
        let shutdown = reader.rf_off();
        if let Err(e) = shutdown {
            eprintln!("RF-off completion: {e}");
            if result.is_ok() {
                return Err(e.into());
            }
        }
        result
    }
    #[cfg(not(windows))]
    {
        let _ = (path, request, timeout, service, blocks);
        Err("hardware binding is currently Windows WinUSB; portable library and codec are available".into())
    }
}

fn card_operation<T: Transport>(
    reader: &mut Reader<T>,
    request: PollRequest,
    timeout: RfTimeout,
    service: Option<u16>,
    blocks: Option<&[u16]>,
) -> Result<(), Box<dyn Error>> {
    let Some(mut card) = reader.poll_felica(request, timeout)? else {
        println!("No card");
        return Ok(());
    };
    let observation = card.observation();
    println!(
        "Target: {}\nIDm: {}\nPMm: {}",
        card.target(),
        observation.idm,
        hex(&observation.pmm)
    );
    if let Some(data) = observation.request_data {
        println!("Polling request data: {}", hex(&data));
    }
    if let (Some(service), Some(blocks)) = (service, blocks) {
        let response = card.read_without_encryption(service, blocks)?;
        for (block, data) in blocks.iter().zip(response.blocks()) {
            println!("Block {block}: {}", hex(data));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn list_devices() -> Result<(), Box<dyn Error>> {
    let devices = rcs956::windows::devices()?;
    if devices.is_empty() {
        println!("No present RC-S956 USB device (054C:02E1)");
        return Ok(());
    }
    for device in devices {
        println!(
            "{}\n  {}\n  Service: {}",
            device.instance, device.description, device.service
        );
        for path in device.paths {
            println!("  Interface: {path}");
        }
    }
    Ok(())
}
#[cfg(not(windows))]
fn list_devices() -> Result<(), Box<dyn Error>> {
    Err("Windows hardware discovery is unavailable on this platform".into())
}

#[cfg(windows)]
fn select_path(explicit: Option<String>) -> Result<String, Box<dyn Error>> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let devices = rcs956::windows::devices()?;
    if devices.is_empty() {
        return Err(
            "RC-S956 USB (054C:02E1) is not present; connect it to this PC, then run devices"
                .into(),
        );
    }
    let candidates: Vec<_> = devices
        .iter()
        .filter(|d| d.service.eq_ignore_ascii_case("winusb"))
        .flat_map(|d| d.paths.iter())
        .collect();
    match candidates.as_slice() {
        [path]=>Ok((*path).clone()),
        []=>Err(format!("reader is present, but no WinUSB interface is available (services: {}). OS driver rebinding is not performed by this tool",devices.iter().map(|d|d.service.as_str()).collect::<Vec<_>>().join(", ")).into()),
        _=>Err("multiple reader interfaces found; select one with --path".into()),
    }
}

fn hex_u16(s: &str) -> Result<u16, std::num::ParseIntError> {
    u16::from_str_radix(s.trim_start_matches("0x"), 16)
}
fn hex_bytes(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let digits: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) || !digits.is_ascii() {
        return Err("hex requires an even number of ASCII digits".into());
    }
    (0..digits.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&digits[n..n + 2], 16).map_err(Into::into))
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}
