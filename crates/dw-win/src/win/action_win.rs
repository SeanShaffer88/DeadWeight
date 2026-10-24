//! The real [`PlatformOps`]: SCM start types and StartupApproved
//! values on a live Windows system.
//!
//! Two invariants hold for everything here:
//!
//! - Services: only the start type is ever read or written
//!   (`ChangeServiceConfigW` with `SERVICE_NO_CHANGE` for every
//!   other field). DeadWeight never starts or stops a service.
//! - Startup items: only the item's value under the documented
//!   `Explorer\StartupApproved` keys is read, written, or deleted.
//!   The Run value or shortcut that makes the item start is never
//!   touched, so disabling here means exactly what disabling in
//!   Task Manager means, and undo restores the recorded bytes.

use dw_core::model::StartupSource;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

use super::registry::RegKey;
use super::scm;
use super::startup;
use crate::action::PlatformOps;

/// The StartupApproved key for registry-backed startup items,
/// under `Software\Microsoft\Windows\CurrentVersion\Explorer`.
const STARTUP_APPROVED_BASE: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved";

/// The (root key, StartupApproved subkey) an item's state lives
/// under, by source. The mapping is Microsoft's documented layout:
/// both Run keys report into `...\StartupApproved\Run` (the WOW64
/// Run key into `\Run32`), and both Startup folders into
/// `\StartupFolder`; the hive follows the source (per-user sources
/// are HKCU, machine sources HKLM). RunOnce sources have no
/// StartupApproved state at all — the plan layer refuses them
/// before the platform is ever asked.
fn approved_location(source: StartupSource) -> Option<(HKEY, String)> {
    let (root, leaf) = match source {
        StartupSource::RunHkcu => (HKEY_CURRENT_USER, "Run"),
        StartupSource::RunHklm => (HKEY_LOCAL_MACHINE, "Run"),
        StartupSource::RunHklmWow64 => (HKEY_LOCAL_MACHINE, "Run32"),
        StartupSource::StartupFolderUser => (HKEY_CURRENT_USER, "StartupFolder"),
        StartupSource::StartupFolderCommon => (HKEY_LOCAL_MACHINE, "StartupFolder"),
        StartupSource::RunOnceHkcu
        | StartupSource::RunOnceHklm
        | StartupSource::RunOnceHklmWow64 => return None,
    };
    Some((root, format!("{STARTUP_APPROVED_BASE}\\{leaf}")))
}

/// The real Windows platform for the disable engine.
pub struct WindowsPlatform;

impl PlatformOps for WindowsPlatform {
    fn service_start_type(&self, name: &str) -> Result<u32, String> {
        scm::query_start_type(name)
    }

    fn set_service_start_type(&self, name: &str, start_type: u32) -> Result<(), String> {
        scm::set_start_type(name, start_type)
    }

    fn startup_approved(
        &self,
        name: &str,
        source: StartupSource,
    ) -> Result<Option<Vec<u8>>, String> {
        let Some((root, subkey)) = approved_location(source) else {
            return Err(format!(
                "{source:?} items have no StartupApproved state (RunOnce items \
                 cannot be disabled — they run once and remove themselves)"
            ));
        };
        let Some(key) = RegKey::open(root, &subkey) else {
            // No StartupApproved key yet: nothing has ever been
            // disabled through Windows on this machine, so the item
            // has no recorded state — which means it runs.
            return Ok(None);
        };
        Ok(key.get_binary(name))
    }

    fn set_startup_approved(
        &self,
        name: &str,
        source: StartupSource,
        blob: Option<&[u8]>,
    ) -> Result<(), String> {
        let Some((root, subkey)) = approved_location(source) else {
            return Err(format!(
                "{source:?} items have no StartupApproved state (RunOnce items \
                 cannot be disabled — they run once and remove themselves)"
            ));
        };
        match blob {
            Some(bytes) => {
                let key = RegKey::create_with_write(root, &subkey).ok_or_else(|| {
                    format!(
                        "could not open {} for writing (an elevated terminal \
                         may be needed for machine-wide items)",
                        source.describe()
                    )
                })?;
                key.set_binary(name, bytes)
            }
            None => {
                let Some(key) = RegKey::open_with_write(root, &subkey) else {
                    // No key: the value cannot exist either, so the
                    // desired end state (no value) already holds.
                    return Ok(());
                };
                if key.has_value(name) {
                    key.delete_value(name)
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Find every source a startup item name appears in: the registry
/// Run/RunOnce keys (a value with that name) and both Startup
/// folders (a file with that stem). The CLI uses this to resolve a
/// bare name — and to refuse, listing the candidates, when a name
/// is ambiguous. The audit collector reads the same sources.
pub fn find_startup_sources(name: &str) -> Vec<StartupSource> {
    let mut found = Vec::new();
    for (root, subkey, source) in startup::REGISTRY_SOURCES {
        if let Some(key) = RegKey::open(root, subkey) {
            if key.has_value(name) {
                found.push(source);
            }
        }
    }
    for (env_var, source) in [
        ("APPDATA", StartupSource::StartupFolderUser),
        ("ProgramData", StartupSource::StartupFolderCommon),
    ] {
        // `startup_folder` returns the Startup folder itself (the
        // same path the collector reads).
        if let Some(folder) = startup::startup_folder(env_var) {
            if let Ok(entries) = std::fs::read_dir(&folder) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    let file_name = entry.file_name().to_string_lossy().into_owned();
                    if file_name.eq_ignore_ascii_case("desktop.ini") {
                        continue;
                    }
                    let stem = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default();
                    // Folder items are named by file name ("Tool.lnk"
                    // in the audit); accept the stem too, so both
                    // `Tool` and `Tool.lnk` resolve.
                    if stem.eq_ignore_ascii_case(name) || file_name.eq_ignore_ascii_case(name) {
                        found.push(source);
                        break;
                    }
                }
            }
        }
    }
    found
}
