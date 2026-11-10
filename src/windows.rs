//! Windows device discovery.

mod metadata;

use std::{
    io,
    mem::{offset_of, size_of},
    ptr::{null, null_mut},
};
use windows_sys::{
    Win32::{
        Devices::{
            DeviceAndDriverInstallation::*,
            Properties::{DEVPKEY_Device_DeviceDesc, DEVPKEY_Device_Service, DEVPROP_TYPE_STRING},
        },
        Foundation::{
            DEVPROPKEY, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND,
            GetLastError,
        },
    },
    core::GUID,
};

/// A currently enumerated RC-S956 USB device and its available interface paths.
#[derive(Debug, Clone)]
pub struct Device {
    /// PnP instance identity used only for selecting this attached device.
    pub instance: String,
    /// Device description, absent only if the property is not registered.
    pub description: Option<String>,
    /// Active OS function service, absent if no service property is registered.
    pub service: Option<String>,
    /// Registered raw USB application interface aliases of this exact function.
    /// USB hub presence interfaces are not candidates for application I/O.
    pub usb_paths: Vec<String>,
}

struct DeviceSet(HDEVINFO);
impl Drop for DeviceSet {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns a valid SetupAPI device information set.
        // Destruction has no device command effect; Drop is best-effort OS cleanup.
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn win_ok(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn native_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::from_ne_bytes(code.to_ne_bytes()))
}

fn property(set: HDEVINFO, dev: &SP_DEVINFO_DATA, key: &DEVPROPKEY) -> io::Result<Option<String>> {
    let value = metadata::read_utf16(|buffer| {
        let capacity = metadata::capacity_bytes(buffer)?;
        let mut required = 0;
        let mut kind = 0;
        let output = if buffer.is_empty() {
            null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        // SAFETY: set/dev are live; key and both scalar outputs are valid. The
        // initialized aligned output buffer has exactly capacity writable bytes.
        let ok = unsafe {
            SetupDiGetDevicePropertyW(set, dev, key, &mut kind, output, capacity, &mut required, 0)
        };
        if ok == 0 {
            // SAFETY: called immediately after the failed SetupAPI operation.
            return match unsafe { GetLastError() } {
                ERROR_NOT_FOUND => Ok(metadata::Query::Missing),
                ERROR_INSUFFICIENT_BUFFER => Ok(metadata::Query::NeededBytes(required)),
                code => Err(native_error(code)),
            };
        }
        if kind != DEVPROP_TYPE_STRING {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "device property is not a string",
            ));
        }
        Ok(metadata::Query::ValueBytes(required))
    })?;
    value.as_deref().map(metadata::string).transpose()
}

fn interface_paths(guid: &GUID, instance: &str) -> io::Result<Vec<String>> {
    // SAFETY: guid lives through the call; no HWND or enumerator filter is required.
    let raw = unsafe {
        SetupDiGetClassDevsW(
            guid,
            null(),
            null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    let set = DeviceSet(raw);
    let mut paths = Vec::new();
    for index in 0..4096u32 {
        let mut item = SP_DEVICE_INTERFACE_DATA {
            cbSize: u32::try_from(size_of::<SP_DEVICE_INTERFACE_DATA>())
                .map_err(io::Error::other)?,
            ..Default::default()
        };
        // SAFETY: the device set is live, item has the required size and is writable.
        let ok = unsafe { SetupDiEnumDeviceInterfaces(set.0, null(), guid, index, &mut item) };
        if ok == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                return Ok(paths);
            }
            return Err(e);
        }
        let mut needed = 0;
        // SAFETY: this is the documented size query with a null output buffer.
        let ok = unsafe {
            SetupDiGetDeviceInterfaceDetailW(set.0, &item, null_mut(), 0, &mut needed, null_mut());
            // GetLastError is captured before any other operation can change it.
            GetLastError()
        };
        if ok != ERROR_INSUFFICIENT_BUFFER {
            return Err(native_error(ok));
        }
        if !(8..=65536).contains(&needed) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "interface path size",
            ));
        }
        // u64 provides the alignment of the Windows detail structure. All bytes
        // are initialized before passing them to the OS, including spare storage.
        let mut storage = vec![
            0u64;
            usize::try_from(needed)
                .map_err(io::Error::other)?
                .div_ceil(8)
        ];
        let detail = storage
            .as_mut_ptr()
            .cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
        // SAFETY: storage is aligned and large enough for the detail header.
        unsafe {
            (*detail).cbSize = u32::try_from(size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>())
                .map_err(io::Error::other)?;
        }
        let mut dev = SP_DEVINFO_DATA {
            cbSize: u32::try_from(size_of::<SP_DEVINFO_DATA>()).map_err(io::Error::other)?,
            ..Default::default()
        };
        // SAFETY: item/set are live; detail has the exact required byte capacity,
        // and dev is an initialized correctly sized output element.
        win_ok(unsafe {
            SetupDiGetDeviceInterfaceDetailW(set.0, &item, detail, needed, null_mut(), &mut dev)
        })?;
        if device_instance(set.0, &mut dev)? != instance {
            continue;
        }
        let offset = offset_of!(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath);
        let count = (usize::try_from(needed).map_err(io::Error::other)? - offset) / 2;
        // SAFETY: the complete allocation was initialized; DevicePath occupies
        // the in-bounds UTF-16 tail just written by SetupAPI. No mutation follows.
        let chars = unsafe {
            std::slice::from_raw_parts(
                storage.as_ptr().cast::<u8>().add(offset).cast::<u16>(),
                count,
            )
        };
        let end = chars.iter().position(|c| *c == 0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unterminated interface path")
        })?;
        paths.push(String::from_utf16(&chars[..end]).map_err(io::Error::other)?);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "interface enumeration exceeds limit",
    ))
}

fn device_instance(set: HDEVINFO, dev: &mut SP_DEVINFO_DATA) -> io::Result<String> {
    let mut buf = [0u16; 512];
    let mut needed = 0;
    // SAFETY: dev belongs to set; the buffer holds 512 initialized UTF-16 units.
    win_ok(unsafe { SetupDiGetDeviceInstanceIdW(set, dev, buf.as_mut_ptr(), 512, &mut needed) })?;
    let end = buf.iter().position(|c| *c == 0).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "unterminated device instance")
    })?;
    String::from_utf16(&buf[..end]).map_err(io::Error::other)
}

/// Enumerate present RC-S956 devices without sending commands or changing drivers.
pub fn devices() -> io::Result<Vec<Device>> {
    let usb = wide("USB");
    // SAFETY: the enumerator is terminated, flags request only present devices.
    let raw = unsafe {
        SetupDiGetClassDevsW(
            null(),
            usb.as_ptr(),
            null_mut(),
            DIGCF_ALLCLASSES | DIGCF_PRESENT,
        )
    };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    let set = DeviceSet(raw);
    let mut out = Vec::new();
    for index in 0..4096u32 {
        let mut dev = SP_DEVINFO_DATA {
            cbSize: u32::try_from(size_of::<SP_DEVINFO_DATA>()).map_err(io::Error::other)?,
            ..Default::default()
        };
        // SAFETY: this live set owns the returned element; cbSize is initialized.
        if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut dev) } == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                return Ok(out);
            }
            return Err(e);
        }
        let instance = device_instance(set.0, &mut dev)?;
        if !instance
            .to_ascii_uppercase()
            .starts_with("USB\\VID_054C&PID_02E1\\")
        {
            continue;
        }
        let description = property(set.0, &dev, &DEVPKEY_Device_DeviceDesc)?;
        let service = property(set.0, &dev, &DEVPKEY_Device_Service)?;
        let paths = Vec::new();
        out.push(Device {
            instance,
            description,
            service,
            usb_paths: paths,
        });
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "device enumeration exceeds limit",
    ))
}
