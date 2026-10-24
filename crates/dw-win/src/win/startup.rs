//! Startup items inventory: the Run/RunOnce registry keys (current
//! user, machine-wide, and the 32-bit WOW6432Node view) and both
//! Startup folders.
//!
//! The inventory is deliberately read-only and deliberately shallow:
//! it records each item's name, target, and source. It does **not**
//! read the `StartupApproved` state — whether an item is currently
//! disabled that way is the disable tier's business, read at action
//! time — so audit items carry state `unknown` rather than a guess.

use dw_core::model::{AuditItem, Kind, StartupSource};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_EXPAND_SZ, REG_SZ,
};

use super::registry::RegKey;

pub(crate) const RUN_SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
pub(crate) const RUN_ONCE_SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
pub(crate) const RUN_WOW_SUBKEY: &str =
    "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
pub(crate) const RUN_ONCE_WOW_SUBKEY: &str =
    "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce";

/// The registry startup sources: root key, subkey, and the model
/// source each pair represents.
pub(crate) const REGISTRY_SOURCES: [(HKEY, &str, StartupSource); 6] = [
    (HKEY_CURRENT_USER, RUN_SUBKEY, StartupSource::RunHkcu),
    (HKEY_LOCAL_MACHINE, RUN_SUBKEY, StartupSource::RunHklm),
    (
        HKEY_LOCAL_MACHINE,
        RUN_WOW_SUBKEY,
        StartupSource::RunHklmWow64,
    ),
    (
        HKEY_CURRENT_USER,
        RUN_ONCE_SUBKEY,
        StartupSource::RunOnceHkcu,
    ),
    (
        HKEY_LOCAL_MACHINE,
        RUN_ONCE_SUBKEY,
        StartupSource::RunOnceHklm,
    ),
    (
        HKEY_LOCAL_MACHINE,
        RUN_ONCE_WOW_SUBKEY,
        StartupSource::RunOnceHklmWow64,
    ),
];

/// Decode a registry value's bytes as a UTF-16 string, for the
/// string-valued sources. Returns `None` for non-string types.
fn decode_string_value(value_type: u32, data: &[u8]) -> Option<String> {
    if value_type != REG_SZ.0 && value_type != REG_EXPAND_SZ.0 {
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

fn startup_items_from_key(root: HKEY, subkey: &str, source: StartupSource) -> Vec<AuditItem> {
    let mut items = Vec::new();
    let Some(key) = RegKey::open(root, subkey) else {
        return items;
    };
    for (name, value_type, data) in key.values() {
        // The (empty-named) default value is not a startup program.
        if name.is_empty() {
            continue;
        }
        let Some(command) = decode_string_value(value_type, &data) else {
            continue;
        };
        if command.trim().is_empty() {
            continue;
        }
        let mut item = AuditItem::new(&name, Kind::StartupItem, "unknown");
        item.target = Some(command);
        item.startup_source = Some(source);
        items.push(item);
    }
    items
}

/// The Startup folder for an environment base (`APPDATA` per-user,
/// `ProgramData` common), when the base is set.
pub(crate) fn startup_folder(env_var: &str) -> Option<std::path::PathBuf> {
    let base = std::env::var_os(env_var)?;
    Some(
        std::path::PathBuf::from(base)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup"),
    )
}

fn startup_items_from_folder(env_var: &str, source: StartupSource) -> Vec<AuditItem> {
    let mut items = Vec::new();
    let Some(folder) = startup_folder(env_var) else {
        return items;
    };
    let Ok(entries) = std::fs::read_dir(&folder) else {
        return items;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // desktop.ini is a shell folder artifact, not a startup program.
        if name.eq_ignore_ascii_case("desktop.ini") {
            continue;
        }
        let mut item = AuditItem::new(&name, Kind::StartupItem, "unknown");
        item.target = Some(path.to_string_lossy().into_owned());
        item.startup_source = Some(source);
        items.push(item);
    }
    items
}

/// Inventory every startup item from every source. No source can
/// fail this collection: a missing key or folder is a normal state
/// on a real machine, not an error.
pub(crate) fn collect_startup() -> Result<Vec<AuditItem>, String> {
    let mut items = Vec::new();
    for (root, subkey, source) in REGISTRY_SOURCES {
        items.append(&mut startup_items_from_key(root, subkey, source));
    }
    items.append(&mut startup_items_from_folder(
        "APPDATA",
        StartupSource::StartupFolderUser,
    ));
    items.append(&mut startup_items_from_folder(
        "ProgramData",
        StartupSource::StartupFolderCommon,
    ));
    Ok(items)
}
