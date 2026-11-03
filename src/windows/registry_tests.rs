//! Exercise registration lookup through the Windows registry API, without a device.

use super::*;
use std::{
    mem::size_of_val,
    sync::atomic::{AtomicU64, Ordering},
};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, ERROR_UNSUPPORTED_TYPE},
    System::Registry::{
        HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_CREATED_NEW_KEY, REG_DWORD,
        REG_MULTI_SZ, REG_OPTION_VOLATILE, REG_SZ, REG_VALUE_TYPE, RegCreateKeyExW, RegDeleteKeyW,
        RegOpenKeyExW, RegSetValueExW,
    },
};

const FIRST: &str = "{12345678-1234-5678-90AB-CDEF01234567}";
const SECOND: &str = "{87654321-4321-8765-BA09-76543210FEDC}";
const FIRST_FIELDS: (u32, u16, u16, [u8; 8]) = (
    0x12345678,
    0x1234,
    0x5678,
    [0x90, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67],
);
const SECOND_FIELDS: (u32, u16, u16, [u8; 8]) = (
    0x87654321,
    0x4321,
    0x8765,
    [0xba, 0x09, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc],
);

fn fields(value: &GUID) -> (u32, u16, u16, [u8; 8]) {
    (value.data1, value.data2, value.data3, value.data4)
}

struct Registration {
    key: RegistryKey,
    path: Vec<u16>,
}

impl Registration {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = wide(&format!(
            "Software\\rcs956-registry-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut key = null_mut();
        let mut disposition = 0;
        // SAFETY: the path is terminated and outputs are writable. This creates
        // only an isolated volatile HKCU key, with value read/write permissions.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                null(),
                REG_OPTION_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                null(),
                &mut key,
                &mut disposition,
            )
        };
        registry_ok(status)?;
        let key = RegistryKey(key);
        if disposition != REG_CREATED_NEW_KEY {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "registration fixture key already exists",
            ));
        }
        Ok(Self { key, path })
    }

    fn set(&self, name: &str, kind: REG_VALUE_TYPE, data: &[u16]) -> io::Result<()> {
        let name = wide(name);
        let bytes = u32::try_from(size_of_val(data)).map_err(io::Error::other)?;
        // SAFETY: this fixture owns a live writable key. The name is terminated;
        // data is initialized and readable for exactly the supplied byte count.
        registry_ok(unsafe {
            RegSetValueExW(
                self.key.0,
                name.as_ptr(),
                0,
                kind,
                data.as_ptr().cast(),
                bytes,
            )
        })
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // SAFETY: creation established exclusive ownership of this exact fixture
        // path. It has no subkeys. Deletion is deferred until key's owner closes
        // its handle after this Drop; cleanup has no device or durable effect.
        let status = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, self.path.as_ptr()) };
        if status != 0 {
            eprintln!(
                "registration fixture cleanup: {}",
                io::Error::from_raw_os_error(status as i32)
            );
        }
    }
}

fn registry_ok(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

#[test]
fn single_string_registration_is_read_from_the_open_key() -> io::Result<()> {
    let registration = Registration::new()?;
    registration.set("DeviceInterfaceGUID", REG_SZ, &wide(FIRST))?;
    let guids = registered_interface_guids(&registration.key)?;
    assert_eq!(guids.len(), 1);
    assert_eq!(fields(&guids[0]), FIRST_FIELDS);
    Ok(())
}

#[test]
fn multi_string_and_single_string_registrations_are_combined() -> io::Result<()> {
    let registration = Registration::new()?;
    registration.set("DeviceInterfaceGUID", REG_SZ, &wide(SECOND))?;
    registration.set(
        "DeviceInterfaceGUIDs",
        REG_MULTI_SZ,
        &wide(&format!("{FIRST}\0{SECOND}\0")),
    )?;
    let guids = registered_interface_guids(&registration.key)?;
    assert_eq!(guids.len(), 2);
    assert_eq!(fields(&guids[0]), FIRST_FIELDS);
    assert_eq!(fields(&guids[1]), SECOND_FIELDS);
    Ok(())
}

#[test]
fn registration_list_can_exceed_four_kibibytes() -> io::Result<()> {
    let registration = Registration::new()?;
    let entries = std::iter::repeat_n(FIRST, 80)
        .collect::<Vec<_>>()
        .join("\0");
    let data = wide(&format!("{entries}\0"));
    assert!(size_of_val(data.as_slice()) > 4096);
    registration.set("DeviceInterfaceGUIDs", REG_MULTI_SZ, &data)?;
    let guids = registered_interface_guids(&registration.key)?;
    assert_eq!(guids.len(), 1);
    assert_eq!(fields(&guids[0]), FIRST_FIELDS);
    Ok(())
}

#[test]
fn missing_values_and_wrong_registry_types_remain_distinct() -> io::Result<()> {
    let registration = Registration::new()?;
    assert!(registered_interface_guids(&registration.key)?.is_empty());
    registration.set("DeviceInterfaceGUID", REG_DWORD, &[1, 0])?;
    let error = registered_interface_guids(&registration.key)
        .err()
        .ok_or_else(|| io::Error::other("wrong registry type was accepted"))?;
    assert_eq!(error.raw_os_error(), Some(ERROR_UNSUPPORTED_TYPE as i32));
    Ok(())
}

#[test]
fn registry_access_failure_is_not_reported_as_missing_registration() -> io::Result<()> {
    let registration = Registration::new()?;
    let mut write_only = null_mut();
    // SAFETY: the parent key is live; an empty terminated path opens that same
    // key with only set-value access. The newly returned handle is owned below.
    registry_ok(unsafe {
        RegOpenKeyExW(
            registration.key.0,
            wide("").as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut write_only,
        )
    })?;
    let write_only = RegistryKey(write_only);
    let error = registered_interface_guids(&write_only)
        .err()
        .ok_or_else(|| io::Error::other("query without read access succeeded"))?;
    assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
    Ok(())
}
