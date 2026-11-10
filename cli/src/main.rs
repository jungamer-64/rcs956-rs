//! Command-line discovery and NFC communication for RC-S956.
#![forbid(unsafe_code)]

#[cfg(windows)]
use rcs956::windows::WinUsb;
#[cfg(windows)]
use rcs956_core::reader::{Reader, TypeBSelection};
use rcs956_core::{
    felica::{BitRate, BlockWrite, MAX_READ_BLOCKS, MAX_WRITE_BLOCKS, PollRequest},
    isodep::MAX_APDU_BYTES,
    nfcb::{PollOptions as TypeBPollOptions, RfProfile},
    reader::{MAX_TYPE_A_COMMAND_BYTES, RfTimeout},
    wire,
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
        "rcs956 devices\nrcs956 probe [--path DEVICE_INTERFACE]\nrcs956 poll [--type felica|a|b] [--timeout-ms 500] [--path PATH]\nFeliCa poll options: [--rate 212|424] [--system FFFF] [--request 1] [--slots 0]\nrcs956 read --service HEX --blocks DECIMAL[,DECIMAL...] [FeliCa poll options]\nrcs956 write --service HEX --block-data DECIMAL:HEX [--block-data DECIMAL:HEX ...] [FeliCa poll options]\nrcs956 systems [FeliCa poll options]\nrcs956 service-at --index DECIMAL [FeliCa poll options]\nrcs956 raw-felica --data LENGTH_PREFIXED_HEX [--data LENGTH_PREFIXED_HEX ...] [--rate 212|424]\nNFC-B options: [--b-profile standard|alternate] [--afi HEX]\nrcs956 exchange --type a|b|b-frame --data HEX [--timeout-ms 500] [--path PATH]\nrcs956 sequence --type a|b|b-frame --data HEX --data HEX [...] [--timeout-ms 500] [--path PATH]\nrcs956 decode READER_FRAME_HEX\n\nHardware commands require an existing WinUSB binding. exchange sends one caller-supplied card command (A) or ISO-DEP APDU (B) or a non-ISO-DEP card command (b-frame); sequence sends each supplied command in order within one card selection. Their effects belong to the caller. No automatic application-command replay."
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
        println!("{:?}", wire::parse(&bytes, wire::Direction::Reader)?);
        return Ok(());
    }
    if command == "devices" {
        if args.next().is_some() {
            return Err("devices takes no options".into());
        }
        return list_devices();
    }
    if !matches!(
        command.as_str(),
        "probe"
            | "poll"
            | "read"
            | "write"
            | "systems"
            | "service-at"
            | "raw-felica"
            | "exchange"
            | "sequence"
    ) {
        return Err(format!("unknown command: {command}").into());
    }
    let mut path = None;
    let mut system = 0xffff;
    let mut request = 1;
    let mut slots = 0;
    let mut timeout = 500u64;
    let mut service = None;
    let mut blocks = None;
    let mut writes = Vec::new();
    let mut index = None;
    let mut rate = None;
    let mut b_options = TypeBPollOptions::default();
    let mut b_options_specified = false;
    let mut technology = Technology::Felica;
    let mut data: Vec<Vec<u8>> = Vec::new();
    let mut felica_options = false;
    while let Some(key) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {key}"))?;
        match key.as_str() {
            "--path" => path = Some(value),
            "--system" => {
                system = hex_u16(&value)?;
                felica_options = true;
            }
            "--request" => {
                request = u8::try_from(hex_u16(&value)?)?;
                felica_options = true;
            }
            "--slots" => {
                slots = u8::try_from(hex_u16(&value)?)?;
                felica_options = true;
            }
            "--type" => technology = Technology::parse(&value)?,
            "--rate" => {
                rate = Some(match value.as_str() {
                    "212" => BitRate::Kbps212,
                    "424" => BitRate::Kbps424,
                    _ => return Err("--rate must be 212 or 424".into()),
                })
            }
            "--afi" => {
                b_options_specified = true;
                b_options.afi = u8::try_from(hex_u16(&value)?)?;
            }
            "--b-profile" => {
                b_options_specified = true;
                b_options.profile = match value.as_str() {
                    "standard" => RfProfile::Standard,
                    "alternate" => RfProfile::Alternate,
                    _ => return Err("--b-profile must be standard or alternate".into()),
                };
            }
            "--index" => index = Some(value.parse::<u16>()?),
            "--block-data" => {
                let (block, bytes) = value
                    .split_once(':')
                    .ok_or("--block-data requires DECIMAL:HEX")?;
                writes.push(BlockWrite {
                    block: block.parse()?,
                    data: hex_bytes(bytes)?
                        .try_into()
                        .map_err(|_| "--block-data requires 16 data bytes")?,
                });
            }
            "--data" => data.push(hex_bytes(&value)?),
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
        .is_some_and(|b| !(1..=MAX_READ_BLOCKS).contains(&b.len()))
    {
        return Err(format!("read requires 1..{MAX_READ_BLOCKS} block numbers").into());
    }
    if (service.is_some() && !matches!(command.as_str(), "read" | "write"))
        || (blocks.is_some() && command != "read")
        || (!writes.is_empty() && command != "write")
        || (index.is_some() && command != "service-at")
    {
        return Err("unexpected FeliCa operation option".into());
    }
    if command == "write" && (service.is_none() || !(1..=MAX_WRITE_BLOCKS).contains(&writes.len()))
    {
        return Err(format!(
            "write requires --service and 1..={MAX_WRITE_BLOCKS} --block-data options"
        )
        .into());
    }
    if command == "service-at" && index.is_none() {
        return Err("service-at requires --index".into());
    }
    if technology != Technology::Felica
        && (felica_options
            || rate.is_some()
            || matches!(
                command.as_str(),
                "read" | "write" | "systems" | "service-at" | "raw-felica"
            ))
    {
        return Err("FeliCa options and commands require --type felica".into());
    }
    if felica_options && command == "raw-felica" {
        return Err("raw-felica takes the full packet in --data".into());
    }
    if b_options_specified && !matches!(technology, Technology::TypeB | Technology::TypeBFrame) {
        return Err("--afi and --b-profile require --type b or b-frame".into());
    }
    validate_data_options(&command, technology, &data)?;
    let request = PollRequest::new(system, request, slots)?;
    let timeout = RfTimeout::new(Duration::from_millis(timeout))?;
    #[cfg(windows)]
    {
        let path = select_path(path)?;
        let usb = WinUsb::open(&path)?;
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
        } else if command == "raw-felica" {
            data.iter().try_for_each(|packet| {
                let response = reader.exchange_raw_felica(
                    rate.unwrap_or(BitRate::Kbps212),
                    packet,
                    timeout,
                )?;
                println!("Response: {}", hex(&response));
                Ok(())
            })
        } else {
            match technology {
                Technology::Felica => {
                    let operation = match (command.as_str(), service, blocks.as_deref(), index) {
                        ("read", Some(service), Some(blocks), _) => {
                            FelicaOperation::Read { service, blocks }
                        }
                        ("write", Some(service), _, _) => FelicaOperation::Write {
                            service,
                            blocks: &writes,
                        },
                        ("systems", _, _, _) => FelicaOperation::Systems,
                        ("service-at", _, _, Some(index)) => FelicaOperation::ServiceAt(index),
                        _ => FelicaOperation::Poll,
                    };
                    card_operation(
                        &mut reader,
                        rate.unwrap_or(BitRate::Kbps212),
                        request,
                        timeout,
                        operation,
                    )
                }
                Technology::TypeA => {
                    type_a_operation(&mut reader, timeout, &data, command == "sequence")
                }
                Technology::TypeB | Technology::TypeBFrame => type_b_operation(
                    &mut reader,
                    b_options,
                    timeout,
                    &data,
                    command == "sequence",
                    technology,
                ),
            }
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
        let _ = (path, request, timeout, service, blocks, technology, data);
        Err("hardware binding is currently Windows WinUSB; portable library and codec are available".into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Technology {
    Felica,
    TypeA,
    TypeB,
    TypeBFrame,
}
impl Technology {
    fn parse(input: &str) -> Result<Self, Box<dyn Error>> {
        match input {
            "felica" => Ok(Self::Felica),
            "a" => Ok(Self::TypeA),
            "b" => Ok(Self::TypeB),
            "b-frame" => Ok(Self::TypeBFrame),
            _ => Err("--type must be felica, a, b or b-frame".into()),
        }
    }
}

fn validate_data_options(
    command: &str,
    technology: Technology,
    data: &[Vec<u8>],
) -> Result<(), Box<dyn Error>> {
    match command {
        "exchange" if data.len() != 1 => {
            return Err("exchange requires exactly one --data".into());
        }
        "sequence" if data.is_empty() => {
            return Err("sequence requires at least one --data".into());
        }
        "raw-felica" => {
            if data.is_empty()
                || data
                    .iter()
                    .any(|packet| packet.len() < 2 || usize::from(packet[0]) != packet.len())
            {
                return Err(
                    "raw-felica requires one or more length-prefixed packets in --data".into(),
                );
            }
        }
        "exchange" | "sequence" => {
            for apdu in data {
                validate_exchange(technology, apdu)?;
            }
        }
        _ if !data.is_empty() => return Err("--data requires exchange or sequence".into()),
        _ => {}
    }
    Ok(())
}

fn validate_exchange(technology: Technology, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let maximum = match technology {
        Technology::TypeA => MAX_TYPE_A_COMMAND_BYTES,
        Technology::TypeB => MAX_APDU_BYTES,
        Technology::TypeBFrame => 63,
        Technology::Felica => {
            return Err("exchange and sequence require --type a, b or b-frame".into());
        }
    };
    if data.is_empty() || data.len() > maximum {
        return Err(format!("exchange requires 1..={maximum} bytes").into());
    }
    Ok(())
}

#[cfg(windows)]
fn type_a_operation(
    reader: &mut Reader<WinUsb>,
    timeout: RfTimeout,
    data: &[Vec<u8>],
    sequence: bool,
) -> Result<(), Box<dyn Error>> {
    let Some(mut card) = reader.poll_type_a(timeout)? else {
        println!("No NFC-A card");
        return Ok(());
    };
    let observation = card.observation();
    println!(
        "Target: {}\nSENS_RES: {}\nSEL_RES: {:02X}\nUID: {}",
        card.target(),
        hex(&observation.sens_res()),
        observation.sel_res(),
        hex(observation.uid())
    );
    if let Some(ats) = observation.ats() {
        println!("ATS: {}", hex(ats.bytes()));
    }
    for (index, apdu) in data.iter().enumerate() {
        if sequence {
            println!("APDU {}: {}", index + 1, hex(apdu));
        }
        let reply = card.exchange(apdu)?;
        println!(
            "Reader status: {:02X}\nResponse: {}",
            reply.status,
            hex(&reply.data)
        );
    }
    Ok(())
}

#[cfg(windows)]
fn type_b_operation(
    reader: &mut Reader<WinUsb>,
    options: TypeBPollOptions,
    timeout: RfTimeout,
    data: &[Vec<u8>],
    sequence: bool,
    technology: Technology,
) -> Result<(), Box<dyn Error>> {
    let Some(mut card) = reader.poll_type_b(options, timeout)? else {
        println!("No NFC-B card");
        return Ok(());
    };
    let observation = card.observation();
    println!(
        "Target: {}\nPUPI: {}\nATQB: {}\nATTRIB: {}",
        card.target_number(),
        hex(&observation.pupi()),
        hex(observation.atqb()),
        hex(observation.attrib_response())
    );
    for (index, apdu) in data.iter().enumerate() {
        if sequence {
            println!("APDU {}: {}", index + 1, hex(apdu));
        }
        let response = match (&mut card, technology) {
            (TypeBSelection::IsoDep(card), Technology::TypeB) => card.exchange_apdu(apdu)?,
            (TypeBSelection::Frame(card), Technology::TypeBFrame) => card.exchange(apdu)?.data,
            _ => {
                return Err("selected NFC-B protocol does not match the requested exchange".into());
            }
        };
        println!("Response: {}", hex(&response));
    }
    Ok(())
}

#[cfg(windows)]
enum FelicaOperation<'a> {
    Poll,
    Read {
        service: u16,
        blocks: &'a [u16],
    },
    Write {
        service: u16,
        blocks: &'a [BlockWrite],
    },
    Systems,
    ServiceAt(u16),
}

#[cfg(windows)]
fn card_operation(
    reader: &mut Reader<WinUsb>,
    rate: BitRate,
    request: PollRequest,
    timeout: RfTimeout,
    operation: FelicaOperation<'_>,
) -> Result<(), Box<dyn Error>> {
    let Some(mut card) = reader.poll_felica(rate, request, timeout)? else {
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
    match operation {
        FelicaOperation::Poll => {}
        FelicaOperation::Read { service, blocks } => {
            let response = card.read_without_encryption(service, blocks)?;
            for (block, data) in blocks.iter().zip(response.blocks()) {
                println!("Block {block}: {}", hex(data));
            }
        }
        FelicaOperation::Write { service, blocks } => {
            card.write_without_encryption(service, blocks)?;
            println!("Written blocks: {}", blocks.len());
        }
        FelicaOperation::Systems => {
            for code in card.request_system_codes()? {
                println!("System: {code:04X}");
            }
        }
        FelicaOperation::ServiceAt(index) => match card.search_service_code(index)? {
            Some(rcs956_core::felica::ServiceEntry::Service(code)) => {
                println!("Service: {code:04X}")
            }
            Some(rcs956_core::felica::ServiceEntry::Area { code, end }) => {
                println!("Area: {code:04X}..={end:04X}")
            }
            None => println!("End of service list"),
        },
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
            device.instance,
            device
                .description
                .as_deref()
                .unwrap_or("description not registered"),
            device.service.as_deref().unwrap_or("not bound")
        );
        for path in device.winusb_paths {
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
    match select_discovered_path(&devices) {
        Ok(path) => Ok(path.to_owned()),
        Err(SelectionError::NoDevice) => Err(
            "RC-S956 USB (054C:02E1) is not present; connect it to this PC, then run devices".into(),
        ),
        Err(SelectionError::NoWinUsbInterface) => Err(format!(
            "reader is present, but no registered WinUSB application interface is available (services: {}). OS driver rebinding is not performed by this tool",
            devices.iter().map(|d| d.service.as_deref().unwrap_or("not bound")).collect::<Vec<_>>().join(", ")
        ).into()),
        Err(SelectionError::MultipleReaders) => Err("multiple WinUSB readers found; select one with --path".into()),
    }
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
enum SelectionError {
    NoDevice,
    NoWinUsbInterface,
    MultipleReaders,
}

#[cfg(windows)]
fn select_discovered_path(devices: &[rcs956::windows::Device]) -> Result<&str, SelectionError> {
    if devices.is_empty() {
        return Err(SelectionError::NoDevice);
    }
    // Each Device is one PnP function. Multiple registered aliases do not make
    // that function multiple readers; enumeration sorts aliases deterministically.
    let mut functions = devices.iter().filter_map(|device| {
        device
            .service
            .as_deref()
            .filter(|service| service.eq_ignore_ascii_case("winusb"))
            .and_then(|_| device.winusb_paths.first())
    });
    let path = functions.next().ok_or(SelectionError::NoWinUsbInterface)?;
    if functions.next().is_some() {
        return Err(SelectionError::MultipleReaders);
    }
    Ok(path)
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
#[cfg(windows)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use rcs956::windows::Device;

    #[test]
    fn exchange_validation_happens_before_opening_a_device() {
        assert!(validate_exchange(Technology::Felica, &[0]).is_err());
        assert!(validate_exchange(Technology::TypeA, &[]).is_err());
        assert!(validate_exchange(Technology::TypeA, &[0; 262]).is_ok());
        assert!(validate_exchange(Technology::TypeA, &[0; 263]).is_err());
        assert!(validate_exchange(Technology::TypeB, &vec![0; 65_535]).is_ok());
        assert!(validate_exchange(Technology::TypeB, &vec![0; 65_536]).is_err());
        assert!(Technology::parse("invalid").is_err());
    }

    fn device(instance: &str, service: Option<&str>, paths: &[&str]) -> Device {
        Device {
            instance: instance.to_owned(),
            description: None,
            service: service.map(str::to_owned),
            winusb_paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        }
    }

    #[test]
    fn aliases_belong_to_one_function_and_other_services_are_not_candidates() {
        let devices = [
            device("reader-one", Some("WinUSB"), &["alias-a", "alias-b"]),
            device("reader-two", Some("sonyrcs956c"), &["native-path"]),
        ];
        assert_eq!(select_discovered_path(&devices), Ok("alias-a"));
    }

    #[test]
    fn separate_winusb_functions_require_selection() {
        let devices = [
            device("reader-one", Some("WinUSB"), &["alias-a", "alias-b"]),
            device("reader-two", Some("WinUSB"), &["alias-c"]),
        ];
        assert_eq!(
            select_discovered_path(&devices),
            Err(SelectionError::MultipleReaders)
        );
    }

    #[test]
    fn absence_and_present_without_application_interface_are_distinct() {
        assert_eq!(select_discovered_path(&[]), Err(SelectionError::NoDevice));
        for present in [
            device("reader", None, &[]),
            device("reader", Some("WinUSB"), &[]),
            device("reader", Some("sonyrcs956c"), &["native-path"]),
        ] {
            assert_eq!(
                select_discovered_path(&[present]),
                Err(SelectionError::NoWinUsbInterface)
            );
        }
    }
}

#[cfg(test)]
mod sequence_tests {
    use super::*;

    #[test]
    fn sequence_requires_apdus_and_type_a_or_b() {
        assert!(validate_data_options("sequence", Technology::TypeA, &[]).is_err());
        assert!(validate_data_options("sequence", Technology::Felica, &[vec![0]]).is_err());
        assert!(validate_data_options("sequence", Technology::TypeA, &[vec![0]]).is_ok());
        assert!(validate_data_options("sequence", Technology::TypeB, &[vec![0]]).is_ok());
    }

    #[test]
    fn exchange_retains_single_command_contract() {
        assert!(validate_data_options("exchange", Technology::TypeA, &[]).is_err());
        assert!(validate_data_options("exchange", Technology::TypeA, &[vec![1], vec![2]]).is_err());
        assert!(validate_data_options("exchange", Technology::TypeB, &[vec![1]]).is_ok());
        assert!(validate_data_options("poll", Technology::TypeA, &[vec![1]]).is_err());
    }

    #[test]
    fn sequence_checks_every_apdu_before_hardware() {
        let oversized = vec![vec![1], vec![2; 263]];
        assert!(validate_data_options("sequence", Technology::TypeA, &oversized).is_err());
        let empty = vec![vec![1], vec![]];
        assert!(validate_data_options("sequence", Technology::TypeB, &empty).is_err());
    }
}
