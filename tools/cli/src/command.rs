//! Command-line discovery and NFC communication for RC-S956.
#![forbid(unsafe_code)]

#[cfg(windows)]
use crate::windows::{self, Device, Usb};
#[cfg(windows)]
use rcs956::reader::{DepActivation, DepRate, Reader, Type2Event, TypeBSelection};
use rcs956::{
    felica::{BitRate, BlockWrite, MAX_READ_BLOCKS, MAX_WRITE_BLOCKS, PollRequest},
    isodep::MAX_APDU_BYTES,
    ndef::{Message, RecordType},
    nfcb::{PollOptions as TypeBPollOptions, RfProfile},
    reader::{
        DepMode, MAX_DEP_MESSAGE_BYTES, MAX_TYPE_A_COMMAND_BYTES, MAX_TYPE2_EMULATED_NDEF_BYTES,
        RfTimeout,
    },
    wire,
};
use std::{error::Error, time::Duration};

fn help() {
    println!(
        "rcs956 devices\nrcs956 probe [--path DEVICE_INTERFACE]\nrcs956 poll [--type felica|a|b] [--timeout-ms 500] [--path PATH]\nFeliCa poll options: [--rate 212|424] [--system FFFF] [--request 1] [--slots 0]\nrcs956 read --service HEX --blocks DECIMAL[,DECIMAL...] [FeliCa poll options]\nrcs956 write --service HEX --block-data DECIMAL:HEX [--block-data DECIMAL:HEX ...] [FeliCa poll options]\nrcs956 systems [FeliCa poll options]\nrcs956 service-at --index DECIMAL [FeliCa poll options]\nrcs956 raw-felica --data LENGTH_PREFIXED_HEX [--data LENGTH_PREFIXED_HEX ...] [FeliCa poll options]\nNFC-B options: [--b-profile standard|alternate] [--afi HEX] [--nad HEX]\nrcs956 exchange --type a|a-apdu|b|b-frame --data HEX [--timeout-ms 500] [--path PATH]\nrcs956 sequence --type a|a-apdu|b|b-frame --data HEX --data HEX [...] [--timeout-ms 500] [--path PATH]\nrcs956 ndef-read --type type1|a|felica|b [--rate 212|424] [--timeout-ms 500] [--path PATH]\nrcs956 ndef-write --type type1|a|felica|b --data NDEF_HEX [--rate 212|424] [--timeout-ms 500] [--path PATH]\nrcs956 ndef-decode NDEF_HEX\nrcs956 dep-echo --data SIX_BYTE_IDENTITY_SUFFIX_HEX [--timeout-ms 500] [--path PATH]\nrcs956 decode READER_FRAME_HEX\n\nHardware commands require an existing UMDF USB binding. exchange sends one caller-supplied card command (A) or ISO-DEP APDU (a-apdu or b) or a non-ISO-DEP card command (b-frame); sequence sends each supplied command in order within one card selection. Their effects belong to the caller. No automatic application-command replay."
    );
    println!(
        "rcs956 dep-send --data HEX [--type a|felica] [--rate 212|424] [--mode passive|active] [--timeout-ms 500] [--path PATH]\nrcs956 type2-emulate --uid THREE_BYTE_UID_SUFFIX_HEX --data NDEF_HEX [--timeout-ms 500] [--path PATH]"
    );
}
pub(super) fn run() -> Result<(), Box<dyn Error>> {
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
    if command == "ndef-decode" {
        let bytes = hex_bytes(&args.collect::<Vec<_>>().join(" "))?;
        return decode_ndef(&bytes);
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
            | "ndef-read"
            | "ndef-write"
            | "dep-echo"
            | "dep-send"
            | "type2-emulate"
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
    let mut dep_mode = DepMode::Passive;
    let mut type2_uid: Option<[u8; 3]> = None;
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
            "--type" if command != "type2-emulate" => technology = Technology::parse(&value)?,
            "--mode" if command == "dep-send" => {
                dep_mode = match value.as_str() {
                    "passive" => DepMode::Passive,
                    "active" => DepMode::Active,
                    _ => return Err("--mode must be passive or active".into()),
                }
            }
            "--uid" if command == "type2-emulate" => {
                type2_uid = Some(
                    hex_bytes(&value)?
                        .try_into()
                        .map_err(|_| "--uid requires three suffix bytes")?,
                );
            }
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
            "--nad" => {
                b_options_specified = true;
                b_options.node_address = Some(rcs956::isodep::NodeAddress::from_byte(
                    u8::try_from(hex_u16(&value)?)?,
                )?);
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
    if b_options_specified && !matches!(technology, Technology::TypeB | Technology::TypeBFrame) {
        return Err("NFC-B options require --type b or b-frame".into());
    }
    if b_options.node_address.is_some() && technology != Technology::TypeB {
        return Err("--nad requires --type b".into());
    }
    let is_ndef = matches!(command.as_str(), "ndef-read" | "ndef-write");
    if is_ndef
        && (!matches!(
            technology,
            Technology::Felica | Technology::Type1 | Technology::TypeA | Technology::TypeB
        ) || felica_options)
    {
        return Err(
            "NDEF requires --type type1, a, felica or b; the Type 3 system is fixed".into(),
        );
    }
    if technology == Technology::Type1 && !is_ndef {
        return Err("--type type1 requires an NDEF operation".into());
    }
    if command == "dep-echo"
        && (technology != Technology::Felica || felica_options || rate.is_some())
    {
        return Err("dep-echo uses its own passive NFC-DEP activation parameters".into());
    }
    if command == "dep-send"
        && (!matches!(technology, Technology::TypeA | Technology::Felica) || felica_options)
    {
        return Err("dep-send requires --type a or felica and uses NFC-DEP discovery".into());
    }
    if command == "type2-emulate" && (type2_uid.is_none() || felica_options || rate.is_some()) {
        return Err("type2-emulate requires --uid and uses a fixed NFC-A target profile".into());
    }
    validate_data_options(&command, technology, &data)?;
    let request = PollRequest::new(system, request, slots)?;
    let timeout = RfTimeout::new(Duration::from_millis(timeout))?;
    #[cfg(windows)]
    {
        let path = select_path(path)?;
        let usb = Usb::open(&path)?;
        println!("Interface: {path}");
        let mut reader = Reader::new(usb);
        if command == "dep-echo" {
            let [identity] = data.as_slice() else {
                return Err("dep-echo requires one identity suffix".into());
            };
            return dep_echo(&mut reader, identity.as_slice().try_into()?, timeout);
        }
        if command == "dep-send" {
            let [payload] = data.as_slice() else {
                return Err("dep-send requires one payload".into());
            };
            let rate = match (technology, rate) {
                (Technology::TypeA, _) => DepRate::Kbps106,
                (_, Some(BitRate::Kbps424)) => DepRate::Kbps424,
                _ => DepRate::Kbps212,
            };
            return dep_send(&mut reader, dep_mode, rate, payload, timeout);
        }
        if command == "type2-emulate" {
            let (Some(uid), [message]) = (type2_uid, data.as_slice()) else {
                return Err("type2-emulate requires a UID suffix and one NDEF message".into());
            };
            return type2_emulate(&mut reader, uid, message, timeout);
        }
        let info = reader.initialize()?;
        println!(
            "Firmware: {}\nModel: {:04X}\nReader flags: {:02X}\nConfiguration: 256 bytes; signature/checksums passed",
            hex(&info.firmware),
            info.configuration.model(),
            info.flags
        );
        let result = if command == "probe" {
            Ok(())
        } else if is_ndef {
            let operation = match data.as_slice() {
                [message] => NdefOperation::Write(message),
                _ => NdefOperation::Read,
            };
            ndef_operation(
                &mut reader,
                technology,
                rate.unwrap_or(BitRate::Kbps212),
                b_options,
                timeout,
                operation,
            )
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
                        ("raw-felica", _, _, _) => FelicaOperation::Raw(&data),
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
                Technology::TypeA | Technology::TypeAApdu => {
                    type_a_operation(&mut reader, timeout, &data, &command, technology)
                }
                Technology::TypeB | Technology::TypeBFrame => {
                    type_b_operation(&mut reader, b_options, timeout, &data, &command, technology)
                }
                Technology::Type1 => Err("Type 1 requires an NDEF operation".into()),
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
        let _ = (
            path, request, timeout, service, blocks, technology, data, dep_mode,
        );
        Err("hardware binding is currently Windows UMDF USB; portable library and codec are available".into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Technology {
    Felica,
    Type1,
    TypeA,
    TypeAApdu,
    TypeB,
    TypeBFrame,
}
impl Technology {
    fn parse(input: &str) -> Result<Self, Box<dyn Error>> {
        match input {
            "felica" => Ok(Self::Felica),
            "type1" => Ok(Self::Type1),
            "a" => Ok(Self::TypeA),
            "a-apdu" => Ok(Self::TypeAApdu),
            "b" => Ok(Self::TypeB),
            "b-frame" => Ok(Self::TypeBFrame),
            _ => Err("--type must be felica, type1, a, a-apdu, b or b-frame".into()),
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
        "ndef-write" | "type2-emulate" => {
            let [message] = data else {
                return Err(format!("{command} requires exactly one --data").into());
            };
            if command == "type2-emulate" && message.len() > MAX_TYPE2_EMULATED_NDEF_BYTES {
                return Err(format!(
                    "type2-emulate accepts up to {MAX_TYPE2_EMULATED_NDEF_BYTES} NDEF bytes"
                )
                .into());
            }
            if !message.is_empty() {
                Message::parse(message)?;
            }
        }
        "dep-echo" => {
            if !matches!(data, [identity] if identity.len() == 6) {
                return Err("dep-echo requires one six-byte identity suffix in --data".into());
            }
        }
        "dep-send" => {
            if !matches!(data, [payload] if payload.len() <= MAX_DEP_MESSAGE_BYTES) {
                return Err(format!(
                    "dep-send requires one --data of at most {MAX_DEP_MESSAGE_BYTES} bytes"
                )
                .into());
            }
        }
        "exchange" | "sequence" => {
            for apdu in data {
                validate_exchange(technology, apdu)?;
            }
        }
        _ if !data.is_empty() => return Err("unexpected --data for this command".into()),
        _ => {}
    }
    Ok(())
}

fn validate_exchange(technology: Technology, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let maximum = match technology {
        Technology::TypeA | Technology::TypeAApdu => MAX_TYPE_A_COMMAND_BYTES,
        Technology::TypeB => MAX_APDU_BYTES,
        Technology::TypeBFrame => 63,
        Technology::Felica | Technology::Type1 => {
            return Err("exchange and sequence require --type a, a-apdu, b or b-frame".into());
        }
    };
    if data.is_empty() || data.len() > maximum {
        return Err(format!("exchange requires 1..={maximum} bytes").into());
    }
    Ok(())
}

#[cfg(windows)]
fn type_a_operation(
    reader: &mut Reader<Usb>,
    timeout: RfTimeout,
    data: &[Vec<u8>],
    command: &str,
    technology: Technology,
) -> Result<(), Box<dyn Error>> {
    let Some(mut card) = reader.poll_type_a(timeout)? else {
        println!("No NFC-A card");
        return Ok(());
    };
    print_type_a(&card);
    if technology == Technology::TypeAApdu {
        for (index, apdu) in data.iter().enumerate() {
            if command == "sequence" {
                println!("APDU {}: {}", index + 1, hex(apdu));
            }
            println!("Response: {}", hex(&card.exchange_apdu(apdu)?));
        }
        return Ok(());
    }
    let mut card = card.into_raw();
    for (index, data) in data.iter().enumerate() {
        if command == "sequence" {
            println!("APDU {}: {}", index + 1, hex(data));
        }
        let mut reply = Some(card.exchange(data)?);
        while let Some(fragment) = reply {
            println!(
                "Reader status: {:02X}\nResponse: {}",
                fragment.status,
                hex(&fragment.data)
            );
            reply = card.receive_continuation()?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn type_b_operation(
    reader: &mut Reader<Usb>,
    options: TypeBPollOptions,
    timeout: RfTimeout,
    data: &[Vec<u8>],
    command: &str,
    technology: Technology,
) -> Result<(), Box<dyn Error>> {
    let Some(mut card) = reader.poll_type_b(options, timeout)? else {
        println!("No NFC-B card");
        return Ok(());
    };
    print_type_b(&card);
    for (index, apdu) in data.iter().enumerate() {
        if command == "sequence" {
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
fn print_type_a(card: &rcs956::reader::TypeACard<'_, Usb>) {
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
}

#[cfg(windows)]
fn print_type_b(card: &TypeBSelection<'_, Usb>) {
    let observation = card.observation();
    println!(
        "Target: {}\nPUPI: {}\nATQB: {}\nATTRIB: {}",
        card.target_number(),
        hex(&observation.pupi()),
        hex(observation.atqb()),
        hex(observation.attrib_response())
    );
}

#[cfg(windows)]
enum NdefOperation<'a> {
    Read,
    Write(&'a [u8]),
}

#[cfg(windows)]
impl NdefOperation<'_> {
    fn no_tag(&self, message: &'static str) -> Result<(), Box<dyn Error>> {
        match self {
            Self::Read => {
                println!("{message}");
                Ok(())
            }
            Self::Write(_) => Err(message.into()),
        }
    }
}

#[cfg(windows)]
fn ndef_operation(
    reader: &mut Reader<Usb>,
    technology: Technology,
    rate: BitRate,
    options: TypeBPollOptions,
    timeout: RfTimeout,
    operation: NdefOperation<'_>,
) -> Result<(), Box<dyn Error>> {
    match technology {
        Technology::Type1 => {
            let Some(mut tag) = reader.poll_type1(timeout)? else {
                return operation.no_tag("No Type 1 tag");
            };
            println!("UID: {}", hex(&tag.uid()));
            match operation {
                NdefOperation::Read => match tag.read_ndef()? {
                    Some(message) => println!("NDEF: {}", hex(&message)),
                    None => println!("No NDEF message"),
                },
                NdefOperation::Write(message) => tag.write_ndef(message)?,
            }
        }
        Technology::Felica => {
            let Some(mut tag) = reader.poll_type3(rate, timeout)? else {
                return operation.no_tag("No NFC Forum Type 3 tag");
            };
            match operation {
                NdefOperation::Read => println!("NDEF: {}", hex(&tag.read_ndef()?)),
                NdefOperation::Write(message) => tag.write_ndef(message)?,
            }
        }
        Technology::TypeA => {
            let Some(mut card) = reader.poll_type_a(timeout)? else {
                return operation.no_tag("No NFC-A card");
            };
            print_type_a(&card);
            match (&operation, card.observation().supports_iso_dep()) {
                (NdefOperation::Read, true) => println!("NDEF: {}", hex(&card.read_type4_ndef()?)),
                (NdefOperation::Read, false) => match card.read_type2_ndef()? {
                    Some(message) => println!("NDEF: {}", hex(&message)),
                    None => println!("No NDEF message"),
                },
                (NdefOperation::Write(message), true) => card.write_type4_ndef(message)?,
                (NdefOperation::Write(message), false) => card.write_type2_ndef(message)?,
            }
        }
        Technology::TypeB => {
            let Some(mut selection) = reader.poll_type_b(options, timeout)? else {
                return operation.no_tag("No NFC-B card");
            };
            print_type_b(&selection);
            let TypeBSelection::IsoDep(card) = &mut selection else {
                return Err("Type 4B NDEF requires ISO-DEP activation".into());
            };
            match operation {
                NdefOperation::Read => println!("NDEF: {}", hex(&card.read_type4_ndef()?)),
                NdefOperation::Write(message) => card.write_type4_ndef(message)?,
            }
        }
        _ => return Err("invalid NDEF technology".into()),
    }
    if let NdefOperation::Write(message) = operation {
        println!("NDEF written ({} bytes)", message.len());
    }
    Ok(())
}

fn decode_ndef(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let message = Message::parse(bytes)?;
    for (index, record) in message.records().iter().enumerate() {
        let (format, name) = match record.record_type {
            RecordType::Empty => ("Empty", &[][..]),
            RecordType::WellKnown(name) => ("Well-known", name),
            RecordType::Media(name) => ("Media", name),
            RecordType::AbsoluteUri(name) => ("Absolute URI", name),
            RecordType::External(name) => ("External", name),
            RecordType::Unknown => ("Unknown", &[][..]),
        };
        println!(
            "Record {}: {}\nType: {}\nID: {}\nPayload: {}",
            index + 1,
            format,
            hex(name),
            hex(record.id.unwrap_or_default()),
            hex(&record.payload),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn dep_echo(
    reader: &mut Reader<Usb>,
    identity: [u8; 6],
    timeout: RfTimeout,
) -> Result<(), Box<dyn Error>> {
    let mut target = match reader.listen_passive_dep(identity, &[], timeout) {
        Ok(target) => target,
        Err(error) => {
            if let Err(reset) = reader.initialize() {
                eprintln!("NFC-DEP cleanup: {reset}");
            }
            return Err(error.into());
        }
    };
    let initiator = target.initiator();
    println!(
        "Rate: {:?}\nNFCID3: {}\nGeneral bytes: {}",
        initiator.rate,
        hex(&initiator.nfcid3),
        hex(&initiator.general_bytes),
    );
    let exchange = (|| {
        let mut request = target.receive(timeout)?;
        let payload = request.payload().to_vec();
        println!("Request: {}", hex(&payload));
        request.respond(&payload)
    })();
    finish_target(exchange, target.finish())
}

#[cfg(windows)]
fn dep_send(
    reader: &mut Reader<Usb>,
    mode: DepMode,
    rate: DepRate,
    payload: &[u8],
    timeout: RfTimeout,
) -> Result<(), Box<dyn Error>> {
    let activation = DepActivation {
        mode,
        rate,
        nfcid3: None,
        general_bytes: &[],
        node_address: None,
    };
    let mut link = match reader.activate_dep(activation, timeout) {
        Ok(link) => link,
        Err(error) => return finish_target(Err(error), reader.initialize().map(|_| ())),
    };
    println!("NFCID3: {}", hex(&link.peer().nfcid3));
    let result = link
        .exchange(payload)
        .map(|reply| println!("Response: {}", hex(&reply.payload)));
    finish_target(result, link.finish())
}

#[cfg(windows)]
fn type2_emulate(
    reader: &mut Reader<Usb>,
    uid: [u8; 3],
    message: &[u8],
    timeout: RfTimeout,
) -> Result<(), Box<dyn Error>> {
    let mut target = match reader.listen_type2_ndef(uid, message, timeout) {
        Ok(target) => target,
        Err(error) => return finish_target(Err(error), reader.initialize().map(|_| ())),
    };
    let result = loop {
        match target.serve_next(timeout) {
            Ok(Type2Event::Read(page)) => println!("Read page {page}"),
            Ok(Type2Event::Ignored(command)) => println!("Ignored: {}", hex(&command)),
            Ok(Type2Event::Halted) => break Ok(()),
            Err(error) => break Err(error),
        }
    };
    finish_target(result, target.finish())
}

#[cfg(windows)]
fn finish_target(
    operation: Result<(), impl Error + 'static>,
    cleanup: Result<(), impl Error + 'static>,
) -> Result<(), Box<dyn Error>> {
    if let Err(error) = operation {
        if let Err(reset) = cleanup {
            eprintln!("Reader cleanup: {reset}");
        }
        return Err(error.into());
    }
    Ok(cleanup?)
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
    Raw(&'a [Vec<u8>]),
}

#[cfg(windows)]
fn card_operation(
    reader: &mut Reader<Usb>,
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
            Some(rcs956::felica::ServiceEntry::Service(code)) => {
                println!("Service: {code:04X}")
            }
            Some(rcs956::felica::ServiceEntry::Area { code, end }) => {
                println!("Area: {code:04X}..={end:04X}")
            }
            None => println!("End of service list"),
        },
        FelicaOperation::Raw(packets) => {
            let mut raw = card.into_raw();
            for packet in packets {
                println!("Response: {}", hex(&raw.exchange_packet(packet)?));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn list_devices() -> Result<(), Box<dyn Error>> {
    let devices = windows::devices()?;
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
        for path in device.usb_paths {
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
    let devices = windows::devices()?;
    match select_discovered_path(&devices) {
        Ok(path) => Ok(path.to_owned()),
        Err(SelectionError::NoDevice) => Err(
            "RC-S956 USB (054C:02E1) is not present; connect it to this PC, then run devices".into(),
        ),
        Err(SelectionError::NoUsbInterface) => Err(format!(
            "reader is present, but no RC-S956 USB driver interface is available (services: {}). OS driver rebinding is not performed by this tool",
            devices.iter().map(|d| d.service.as_deref().unwrap_or("not bound")).collect::<Vec<_>>().join(", ")
        ).into()),
        Err(SelectionError::MultipleReaders) => Err("multiple RC-S956 USB readers found; select one with --path".into()),
    }
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
enum SelectionError {
    NoDevice,
    NoUsbInterface,
    MultipleReaders,
}

#[cfg(windows)]
fn select_discovered_path(devices: &[Device]) -> Result<&str, SelectionError> {
    if devices.is_empty() {
        return Err(SelectionError::NoDevice);
    }
    // Each Device is one PnP function. Multiple registered aliases do not make
    // that function multiple readers; enumeration sorts aliases deterministically.
    let mut functions = devices.iter().filter_map(|device| device.usb_paths.first());
    let path = functions.next().ok_or(SelectionError::NoUsbInterface)?;
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
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

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
            usb_paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        }
    }

    #[test]
    fn aliases_belong_to_one_function_and_unbound_functions_are_not_candidates() {
        let devices = [
            device("reader-one", Some("WUDFRd"), &["alias-a", "alias-b"]),
            device("reader-two", Some("sonyrcs956c"), &[]),
        ];
        assert_eq!(select_discovered_path(&devices), Ok("alias-a"));
    }

    #[test]
    fn separate_usb_functions_require_selection() {
        let devices = [
            device("reader-one", Some("WUDFRd"), &["alias-a", "alias-b"]),
            device("reader-two", Some("WUDFRd"), &["alias-c"]),
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
            device("reader", Some("WUDFRd"), &[]),
            device("reader", Some("sonyrcs956c"), &[]),
        ] {
            assert_eq!(
                select_discovered_path(&[present]),
                Err(SelectionError::NoUsbInterface)
            );
        }
    }
}

#[cfg(test)]
mod sequence_tests {
    use super::*;

    #[test]
    fn ndef_write_validates_the_complete_message_before_device_access() {
        assert!(
            validate_data_options("ndef-write", Technology::Type1, &[vec![0xd0, 0, 0]]).is_ok()
        );
        assert!(validate_data_options("ndef-write", Technology::Felica, &[vec![]]).is_ok());
        assert!(validate_data_options("ndef-write", Technology::TypeB, &[]).is_err());
        assert!(validate_data_options("ndef-write", Technology::TypeA, &[vec![0xd1, 0]]).is_err());
        assert!(
            validate_data_options(
                "ndef-write",
                Technology::TypeA,
                &[vec![0xd0, 0, 0], vec![0xd0, 0, 0]]
            )
            .is_err()
        );
    }

    #[test]
    fn peer_commands_admit_only_one_bounded_payload() {
        assert!(validate_data_options("dep-send", Technology::TypeA, &[vec![1]]).is_ok());
        assert!(validate_data_options("dep-send", Technology::TypeA, &[]).is_err());
        assert!(
            validate_data_options(
                "dep-send",
                Technology::TypeA,
                &[vec![0; MAX_DEP_MESSAGE_BYTES + 1]],
            )
            .is_err()
        );
        assert!(
            validate_data_options("type2-emulate", Technology::Felica, &[vec![0xd0, 0, 0]]).is_ok()
        );
        assert!(
            validate_data_options("type2-emulate", Technology::Felica, &[vec![0xd0, 0]]).is_err()
        );
        assert!(
            validate_data_options(
                "type2-emulate",
                Technology::Felica,
                &[vec![0; MAX_TYPE2_EMULATED_NDEF_BYTES + 1]],
            )
            .is_err()
        );
    }

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
