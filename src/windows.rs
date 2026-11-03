//! Windows WinUSB binding. Does not install, remove, or replace an OS driver.
//!
//! WinUSB must already own the selected function. Synchronous pipe operations
//! retain all buffers until completion and use a finite pipe timeout.

mod metadata;
#[cfg(test)]
mod registry_tests;

use crate::transport::Transport;
use std::{
    fmt, io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    time::Duration,
};
use windows_sys::{
    Win32::{
        Devices::{
            DeviceAndDriverInstallation::*,
            Properties::{DEVPKEY_Device_DeviceDesc, DEVPKEY_Device_Service, DEVPROP_TYPE_STRING},
            Usb::*,
        },
        Foundation::{
            DEVPROPKEY, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_KEY_DOES_NOT_EXIST,
            ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND, ERROR_PATH_NOT_FOUND,
            GetLastError, INVALID_HANDLE_VALUE,
        },
        Storage::FileSystem::{CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING},
        System::Registry::{
            HKEY, KEY_QUERY_VALUE, REG_ROUTINE_FLAGS, RRF_RT_REG_MULTI_SZ, RRF_RT_REG_SZ,
            RegCloseKey, RegGetValueW,
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
    /// Registered WinUSB application interface aliases of this exact function.
    /// USB hub presence interfaces are not candidates for application I/O.
    pub winusb_paths: Vec<String>,
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

struct RegistryKey(HKEY);
impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the open registry key.
        // Closing releases local resources and has no device or registry write effect.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn registry_value(
    key: &RegistryKey,
    name: &str,
    flags: REG_ROUTINE_FLAGS,
) -> io::Result<Option<Vec<u16>>> {
    let name = wide(name);
    metadata::read_utf16(|buffer| {
        let mut size = metadata::capacity_bytes(buffer)?;
        let output = if buffer.is_empty() {
            null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        // SAFETY: key is live, the value name is terminated, and
        // output is null for sizing or points to size initialized writable bytes.
        // DIREG_DEV already opens Device Parameters, so the value is on key itself.
        let status = unsafe {
            RegGetValueW(
                key.0,
                null(),
                name.as_ptr(),
                flags,
                null_mut(),
                output,
                &mut size,
            )
        };
        match status {
            0 if buffer.is_empty() && size > 0 => Ok(metadata::Query::NeededBytes(size)),
            0 => Ok(metadata::Query::ValueBytes(size)),
            ERROR_MORE_DATA => Ok(metadata::Query::NeededBytes(size)),
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(metadata::Query::Missing),
            code => Err(native_error(code)),
        }
    })
}

/// Interpret both Windows registration forms on an already opened hardware key.
/// Missing values are absence; access, type, and malformed-data failures propagate.
fn registered_interface_guids(key: &RegistryKey) -> io::Result<Vec<GUID>> {
    let multi = registry_value(key, "DeviceInterfaceGUIDs", RRF_RT_REG_MULTI_SZ)?;
    let single = registry_value(key, "DeviceInterfaceGUID", RRF_RT_REG_SZ)?;
    metadata::interface_guids(multi.as_deref(), single.as_deref())
}

fn interface_guids(set: HDEVINFO, dev: &SP_DEVINFO_DATA) -> io::Result<Vec<GUID>> {
    // SAFETY: the device set and element are live; only value-read access is requested.
    let raw =
        unsafe { SetupDiOpenDevRegKey(set, dev, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_QUERY_VALUE) };
    if raw == INVALID_HANDLE_VALUE {
        // SAFETY: called immediately after the failed key-open operation.
        return match unsafe { GetLastError() } {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_KEY_DOES_NOT_EXIST => {
                Ok(Vec::new())
            }
            code => Err(native_error(code)),
        };
    }
    let key = RegistryKey(raw);
    registered_interface_guids(&key)
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
        let mut paths = Vec::new();
        if service
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("winusb"))
        {
            for guid in interface_guids(set.0, &dev)? {
                paths.extend(interface_paths(&guid, &instance)?);
            }
        }
        paths.sort();
        paths.dedup();
        out.push(Device {
            instance,
            description,
            service,
            winusb_paths: paths,
        });
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "device enumeration exceeds limit",
    ))
}

/// An exclusively opened WinUSB function with one 64-byte bulk pair.
pub struct WinUsb {
    usb: WINUSB_INTERFACE_HANDLE,
    file: OwnedHandle,
    input: u8,
    output: u8,
}
impl fmt::Debug for WinUsb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WinUsb")
            .field("input", &self.input)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
impl WinUsb {
    /// Open an existing WinUSB interface. Verifies VID/PID and descriptors before
    /// exposing the transport. Never rebinds an installed driver.
    pub fn open(path: &str) -> io::Result<Self> {
        if path.contains('\0') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
        }
        let path = wide(path);
        // SAFETY: path is terminated; access is exclusive and the returned handle
        // is either INVALID_HANDLE_VALUE or newly owned by this scope.
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                0xc0000000,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly created valid kernel handle, transferred once.
        let file = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut usb = null_mut();
        // SAFETY: file stays alive until after WinUsb_Free; usb is writable output.
        win_ok(unsafe { WinUsb_Initialize(file.as_raw_handle(), &mut usb) })?;
        let mut owner = Self {
            usb,
            file,
            input: 0,
            output: 0,
        };
        owner.configure()?;
        Ok(owner)
    }
    fn configure(&mut self) -> io::Result<()> {
        let mut descriptor = [0u8; 18];
        let mut n = 0;
        // SAFETY: the interface is live; descriptor and n are exclusively writable.
        win_ok(unsafe {
            WinUsb_GetDescriptor(self.usb, 1, 0, 0, descriptor.as_mut_ptr(), 18, &mut n)
        })?;
        if n != 18 || descriptor[8..12] != [0x4c, 0x05, 0xe1, 0x02] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not an RC-S956 054C:02E1 device",
            ));
        }
        let mut interface = USB_INTERFACE_DESCRIPTOR::default();
        // SAFETY: the initialized output structure is writable and interface is live.
        win_ok(unsafe { WinUsb_QueryInterfaceSettings(self.usb, 0, &mut interface) })?;
        for i in 0..interface.bNumEndpoints {
            let mut pipe = WINUSB_PIPE_INFORMATION::default();
            // SAFETY: queried index is within the endpoint count; pipe is writable.
            win_ok(unsafe { WinUsb_QueryPipe(self.usb, 0, i, &mut pipe) })?;
            if pipe.PipeType != UsbdPipeTypeBulk {
                continue;
            }
            if pipe.MaximumPacketSize != 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "RC-S956 bulk MPS must be 64",
                ));
            }
            let slot = if pipe.PipeId & 0x80 != 0 {
                &mut self.input
            } else {
                &mut self.output
            };
            if *slot != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ambiguous bulk endpoints",
                ));
            }
            *slot = pipe.PipeId;
        }
        if self.input == 0 || self.output == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing bulk pair",
            ));
        }
        // WinUSB emits the terminating ZLP on nonzero 64-byte multiples.
        let enabled = 1u8;
        // SAFETY: policy uses a one-byte BOOL value; interface and OUT pipe are live.
        win_ok(unsafe {
            WinUsb_SetPipePolicy(
                self.usb,
                self.output,
                SHORT_PACKET_TERMINATE,
                1,
                (&enabled as *const u8).cast(),
            )
        })?;
        let disabled = 0u8;
        // SAFETY: policy uses a one-byte BOOL, and input pipe belongs to this owner.
        win_ok(unsafe {
            WinUsb_SetPipePolicy(
                self.usb,
                self.input,
                IGNORE_SHORT_PACKETS,
                1,
                (&disabled as *const u8).cast(),
            )
        })?;
        Ok(())
    }
    fn timeout(&self, pipe: u8, duration: Duration) -> io::Result<()> {
        let ms = u32::try_from(duration.as_millis().max(1)).map_err(io::Error::other)?;
        // SAFETY: PIPE_TRANSFER_TIMEOUT consumes one u32 synchronously; its
        // borrowed pointer remains valid throughout the call.
        win_ok(unsafe {
            WinUsb_SetPipePolicy(
                self.usb,
                pipe,
                PIPE_TRANSFER_TIMEOUT,
                4,
                (&ms as *const u32).cast(),
            )
        })
    }
}
impl Transport for WinUsb {
    fn write(&mut self, frame: &[u8], timeout: Duration) -> io::Result<usize> {
        self.timeout(self.output, timeout)?;
        let mut n = 0;
        let length = u32::try_from(frame.len()).map_err(io::Error::other)?;
        // SAFETY: the input is borrowed until the synchronous call completes;
        // WinUSB documents this buffer as input despite its ABI's mutable pointer.
        // Null OVERLAPPED requests synchronous completion, with n always provided.
        win_ok(unsafe {
            WinUsb_WritePipe(
                self.usb,
                self.output,
                frame.as_ptr().cast_mut(),
                length,
                &mut n,
                null(),
            )
        })?;
        usize::try_from(n).map_err(io::Error::other)
    }
    fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> io::Result<usize> {
        self.timeout(self.input, timeout)?;
        let mut n = 0;
        let length = u32::try_from(buffer.len()).map_err(io::Error::other)?;
        // SAFETY: buffer has length writable initialized bytes; synchronous
        // completion keeps it alive and exclusively borrowed until return.
        win_ok(unsafe {
            WinUsb_ReadPipe(
                self.usb,
                self.input,
                buffer.as_mut_ptr(),
                length,
                &mut n,
                null(),
            )
        })?;
        let n = usize::try_from(n).map_err(io::Error::other)?;
        if n > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WinUSB receive length",
            ));
        }
        Ok(n)
    }
    fn recover(&mut self) -> io::Result<()> {
        for pipe in [self.input, self.output] {
            // SAFETY: operations are synchronous and no transfer remains in flight.
            win_ok(unsafe { WinUsb_ResetPipe(self.usb, pipe) })?;
        }
        // SAFETY: the exclusively owned input pipe has no operation in flight.
        win_ok(unsafe { WinUsb_FlushPipe(self.usb, self.input) })
    }
}
impl Drop for WinUsb {
    fn drop(&mut self) {
        // SAFETY: all operations completed synchronously. usb is uniquely owned;
        // file is still live and is dropped after the WinUSB interface is freed.
        // Free is local resource cleanup, not a fallible RF-off completion.
        unsafe {
            WinUsb_Free(self.usb);
        }
        let _file_lifetime = &self.file;
    }
}
