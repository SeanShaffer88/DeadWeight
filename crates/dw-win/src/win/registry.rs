//! Registry-backed sources: the Uninstall keys (app inventory) and
//! the evidence keys (UserAssist, BAM).
//!
//! Collection is read-only. The write operations at the bottom of
//! the `RegKey` impl exist for exactly one purpose: the disable
//! tier's StartupApproved values, written through the `action_win`
//! platform implementation. Nothing else in the crate writes to
//! the registry, and no Run/RunOnce value is ever written or
//! deleted — disabling a startup item changes only its
//! StartupApproved state, the same mechanism Task Manager uses.

use dw_core::model::{AuditItem, Kind};
use dw_core::time::install_date_from_yyyymmdd;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
    KEY_SET_VALUE, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, REG_SZ,
    REG_VALUE_TYPE,
};

use super::wide;

const ERROR_SUCCESS_CODE: u32 = 0;

/// RAII wrapper for a registry key handle.
pub(crate) struct RegKey(pub(crate) HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a key opened by this wrapper and owned
        // solely by it, so closing it once here is the only close.
        // Predefined root keys are never wrapped (open() is only ever
        // called for subkeys), so no predefined key is closed.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

impl RegKey {
    pub(crate) fn open(root: HKEY, subkey: &str) -> Option<RegKey> {
        let wide_subkey = wide(subkey);
        let mut handle = HKEY::default();
        // SAFETY: `wide_subkey` is NUL-terminated and lives for the
        // call; `handle` is a valid out-pointer; access requested is
        // read-only.
        let error = unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(wide_subkey.as_ptr()),
                None,
                KEY_READ,
                &mut handle,
            )
        };
        if error == WIN32_ERROR(ERROR_SUCCESS_CODE) {
            Some(RegKey(handle))
        } else {
            None
        }
    }

    /// Read a string (`REG_SZ` / `REG_EXPAND_SZ`) value, if present.
    pub(crate) fn get_string(&self, name: &str) -> Option<String> {
        let wide_name = wide(name);
        let mut value_type = REG_VALUE_TYPE::default();
        let mut byte_count = 0u32;
        // SAFETY: sizing call — null data pointer with a size
        // out-pointer; `wide_name` lives for the call.
        let error = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut value_type),
                None,
                Some(&mut byte_count),
            )
        };
        if error != WIN32_ERROR(ERROR_SUCCESS_CODE)
            || (value_type != REG_SZ && value_type != REG_EXPAND_SZ)
            || byte_count == 0
        {
            return None;
        }
        let mut data = vec![0u8; byte_count as usize];
        // SAFETY: `data` is `byte_count` writable bytes, as the API
        // requires; the arguments are unchanged from the sizing call,
        // so the value cannot have grown past the buffer without the
        // call failing instead of overflowing.
        let error = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut value_type),
                Some(data.as_mut_ptr()),
                Some(&mut byte_count),
            )
        };
        if error != WIN32_ERROR(ERROR_SUCCESS_CODE) {
            return None;
        }
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Some(
            String::from_utf16_lossy(&units)
                .trim_end_matches('\0')
                .to_owned(),
        )
    }

    /// Read a `REG_DWORD` value, if present.
    pub(crate) fn get_dword(&self, name: &str) -> Option<u32> {
        let wide_name = wide(name);
        let mut value_type = REG_VALUE_TYPE::default();
        let mut data = [0u8; 4];
        let mut byte_count = 4u32;
        // SAFETY: `data` is a 4-byte buffer matching REG_DWORD's fixed
        // size; `wide_name` lives for the call.
        let error = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut value_type),
                Some(data.as_mut_ptr()),
                Some(&mut byte_count),
            )
        };
        if error != WIN32_ERROR(ERROR_SUCCESS_CODE) || value_type != REG_DWORD {
            return None;
        }
        Some(u32::from_le_bytes(data))
    }

    /// Open a subkey with write access (`KEY_READ | KEY_SET_VALUE`),
    /// for the StartupApproved platform operations.
    pub(crate) fn open_with_write(root: HKEY, subkey: &str) -> Option<RegKey> {
        let wide_subkey = wide(subkey);
        let mut handle = HKEY::default();
        // SAFETY: `wide_subkey` is NUL-terminated and lives for the
        // call; `handle` is a valid out-pointer.
        let error = unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(wide_subkey.as_ptr()),
                None,
                KEY_READ | KEY_SET_VALUE,
                &mut handle,
            )
        };
        if error == WIN32_ERROR(ERROR_SUCCESS_CODE) {
            Some(RegKey(handle))
        } else {
            None
        }
    }

    /// Create (or open) a subkey with write access. Used for the
    /// StartupApproved keys, which may not exist yet on a machine
    /// where nothing has ever been disabled through Windows.
    pub(crate) fn create_with_write(root: HKEY, subkey: &str) -> Option<RegKey> {
        let wide_subkey = wide(subkey);
        let mut handle = HKEY::default();
        // SAFETY: `wide_subkey` is NUL-terminated and lives for the
        // call; `handle` is a valid out-pointer; no class, no
        // security attributes, non-volatile — the documented
        // defaults for application keys.
        let error = unsafe {
            RegCreateKeyExW(
                root,
                PCWSTR(wide_subkey.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_SET_VALUE,
                None,
                &mut handle,
                None,
            )
        };
        if error == WIN32_ERROR(ERROR_SUCCESS_CODE) {
            Some(RegKey(handle))
        } else {
            None
        }
    }

    /// Whether a value with this name exists under the key.
    pub(crate) fn has_value(&self, name: &str) -> bool {
        self.values().iter().any(|(n, _, _)| n == name)
    }

    /// A value's raw bytes, whatever its type (used for
    /// StartupApproved blobs, which are `REG_BINARY`).
    pub(crate) fn get_binary(&self, name: &str) -> Option<Vec<u8>> {
        self.values()
            .into_iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, _, data)| data)
    }

    /// Write a `REG_BINARY` value.
    pub(crate) fn set_binary(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let wide_name = wide(name);
        // SAFETY: `wide_name` is NUL-terminated and lives for the
        // call; the slice carries its own length, as the binding
        // requires.
        let error = unsafe {
            RegSetValueExW(
                self.0,
                PCWSTR(wide_name.as_ptr()),
                None,
                REG_BINARY,
                Some(bytes),
            )
        };
        if error == WIN32_ERROR(ERROR_SUCCESS_CODE) {
            Ok(())
        } else {
            Err(format!(
                "writing registry value {name:?} failed (error {})",
                error.0
            ))
        }
    }

    /// Delete a value. Deleting an absent value is an error at the
    /// API level; callers check `has_value` first when absence is a
    /// valid end state.
    pub(crate) fn delete_value(&self, name: &str) -> Result<(), String> {
        let wide_name = wide(name);
        // SAFETY: `wide_name` is NUL-terminated and lives for the call.
        let error = unsafe { RegDeleteValueW(self.0, PCWSTR(wide_name.as_ptr())) };
        if error == WIN32_ERROR(ERROR_SUCCESS_CODE) {
            Ok(())
        } else {
            Err(format!(
                "deleting registry value {name:?} failed (error {})",
                error.0
            ))
        }
    }

    /// Names of all subkeys, in enumeration order.
    pub(crate) fn subkey_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        // Key names are limited to 255 characters by Windows.
        let mut buffer = vec![0u16; 256];
        for index in 0..u32::MAX {
            let mut length = buffer.len() as u32;
            // SAFETY: `buffer` is 256 writable UTF-16 units and
            // `length` is its capacity on entry, exactly as the API
            // requires; on success `length` becomes the name length.
            let error = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    Some(PWSTR(buffer.as_mut_ptr())),
                    &mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if error != WIN32_ERROR(ERROR_SUCCESS_CODE) {
                break;
            }
            names.push(String::from_utf16_lossy(&buffer[..length as usize]));
        }
        names
    }

    /// All values of this key as `(name, type, data)` triples. Values
    /// larger than the 64 KB data buffer (none of the evidence
    /// formats come close) are skipped rather than truncated.
    pub(crate) fn values(&self) -> Vec<(String, u32, Vec<u8>)> {
        let mut values = Vec::new();
        // Value names are limited to 16,383 characters by Windows.
        let mut name_buffer = vec![0u16; 16_384];
        let mut data_buffer = vec![0u8; 65_536];
        for index in 0..u32::MAX {
            let mut name_length = name_buffer.len() as u32;
            let mut value_type = 0u32;
            let mut data_length = data_buffer.len() as u32;
            // SAFETY: both buffers are capacity-sized and their
            // lengths are passed as in/out capacity parameters,
            // exactly as the API requires; on success the lengths
            // become the actual name/data sizes, which bound the
            // slices read below.
            let error = unsafe {
                RegEnumValueW(
                    self.0,
                    index,
                    Some(PWSTR(name_buffer.as_mut_ptr())),
                    &mut name_length,
                    None,
                    Some(&mut value_type),
                    Some(data_buffer.as_mut_ptr()),
                    Some(&mut data_length),
                )
            };
            if error != WIN32_ERROR(ERROR_SUCCESS_CODE) {
                break;
            }
            let name = String::from_utf16_lossy(&name_buffer[..name_length as usize]);
            let data = data_buffer[..data_length as usize].to_vec();
            values.push((name, value_type, data));
        }
        values
    }
}

const UNINSTALL_SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
const UNINSTALL_WOW_SUBKEY: &str =
    "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

/// Whether an Uninstall entry is a real, user-visible app, following
/// the same documented heuristic Settings uses: it needs a display
/// name, and entries flagged `SystemComponent` (sub-components of
/// other installs) are skipped.
fn should_include_app(display_name: Option<&str>, system_component: Option<u32>) -> bool {
    match display_name {
        Some(name) => !name.trim().is_empty() && system_component != Some(1),
        None => false,
    }
}

/// App inventory from the three Uninstall roots (machine 64-bit,
/// machine 32-bit/WOW6432Node, per-user). Sizes come from the
/// `EstimatedSize` DWORD (kilobytes) — reported by the installer, and
/// kept `None` when absent rather than estimated.
pub(crate) fn collect_apps() -> Result<Vec<AuditItem>, String> {
    let roots = [
        (HKEY_LOCAL_MACHINE, UNINSTALL_SUBKEY),
        (HKEY_LOCAL_MACHINE, UNINSTALL_WOW_SUBKEY),
        (HKEY_CURRENT_USER, UNINSTALL_SUBKEY),
    ];
    let mut items = Vec::new();
    let mut roots_opened = 0usize;
    for (root, subkey) in roots {
        let Some(key) = RegKey::open(root, subkey) else {
            continue;
        };
        roots_opened += 1;
        for subkey_name in key.subkey_names() {
            let Some(entry) = RegKey::open(key.0, &subkey_name) else {
                continue;
            };
            let display_name = entry.get_string("DisplayName");
            let system_component = entry.get_dword("SystemComponent");
            if !should_include_app(display_name.as_deref(), system_component) {
                continue;
            }
            let mut item = AuditItem::new(
                display_name.as_deref().unwrap_or_default(),
                Kind::App,
                "installed",
            );
            item.publisher = entry
                .get_string("Publisher")
                .filter(|p| !p.trim().is_empty());
            item.size_bytes = entry
                .get_dword("EstimatedSize")
                .map(|kb| u64::from(kb) * 1_024);
            item.install_date = entry
                .get_string("InstallDate")
                .and_then(|raw| install_date_from_yyyymmdd(&raw));
            item.install_location = entry
                .get_string("InstallLocation")
                .filter(|p| !p.trim().is_empty());
            items.push(item);
        }
    }
    if roots_opened == 0 {
        return Err("could not open any Uninstall registry key".to_owned());
    }
    Ok(items)
}
