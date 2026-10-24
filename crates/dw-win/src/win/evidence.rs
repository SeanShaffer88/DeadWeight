//! The three usage-evidence collectors: Prefetch, UserAssist, BAM.
//!
//! Each returns per-executable observations (grouped by normalized
//! base key, keeping the newest last-use and the highest run count —
//! Prefetch can hold several files for one executable, UserAssist
//! several GUID buckets). Each fails independently: the caller turns
//! a failure into a warning and the audit simply has less evidence.

use std::collections::BTreeMap;

use dw_core::evidence_parse::{
    exe_base_key, exe_name_from_prefetch, file_name_of, filetime_to_unix, parse_userassist_value,
    rot13,
};
use dw_core::model::EvidenceSource;
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

use super::registry::RegKey;
use crate::match_evidence::ExeEvidence;

/// Merge one observation into the per-executable map.
fn record(
    map: &mut BTreeMap<String, ExeEvidence>,
    exe_name: &str,
    source: EvidenceSource,
    last_used_unix: Option<i64>,
    run_count: Option<u32>,
) {
    let base_key = exe_base_key(exe_name);
    if base_key.is_empty() {
        return;
    }
    let entry = map.entry(base_key.clone()).or_insert_with(|| ExeEvidence {
        exe_name: exe_name.to_owned(),
        base_key,
        source,
        last_used_unix: None,
        run_count: None,
    });
    entry.last_used_unix = match (entry.last_used_unix, last_used_unix) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    entry.run_count = match (entry.run_count, run_count) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
}

fn into_vec(map: BTreeMap<String, ExeEvidence>) -> Vec<ExeEvidence> {
    map.into_values().collect()
}

/// Prefetch: file names give the executable, file modification times
/// the last run Prefetch recorded. Reading the folder can require
/// elevation on some builds; a failure is a warning upstream.
pub(crate) fn collect_prefetch() -> Result<Vec<ExeEvidence>, String> {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let dir = std::path::Path::new(&system_root).join("Prefetch");
    let entries = std::fs::read_dir(&dir)
        .map_err(|err| format!("could not read {}: {err}", dir.display()))?;
    let mut map = BTreeMap::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let Some(exe_name) = exe_name_from_prefetch(&file_name) else {
            continue;
        };
        let last_used = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);
        record(
            &mut map,
            &exe_name,
            EvidenceSource::Prefetch,
            last_used,
            None,
        );
    }
    Ok(into_vec(map))
}

const USERASSIST_SUBKEY: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";

/// UserAssist: each GUID subkey's `Count` key holds ROT13-encoded
/// value names (paths to what Explorer launched) with binary values
/// in the layout `dw_core` parses. Aggregate counters (names starting
/// `UEME_` once decoded) are not programs and are skipped, as are
/// entries that do not name an `.exe` (folders, shortcuts to
/// documents). Values in the older 16-byte layout still prove the
/// executable was seen — they are recorded with no count or date
/// rather than dropped.
pub(crate) fn collect_userassist() -> Result<Vec<ExeEvidence>, String> {
    let Some(root) = RegKey::open(HKEY_CURRENT_USER, USERASSIST_SUBKEY) else {
        return Err("UserAssist key could not be opened".to_owned());
    };
    let mut map = BTreeMap::new();
    for guid in root.subkey_names() {
        let Some(count_key) = RegKey::open(root.0, &format!("{guid}\\Count")) else {
            continue;
        };
        for (encoded_name, _value_type, data) in count_key.values() {
            let decoded = rot13(&encoded_name);
            if decoded.starts_with("UEME_") {
                continue;
            }
            let file_name = file_name_of(&decoded);
            if !file_name.to_lowercase().ends_with(".exe") {
                continue;
            }
            let parsed = parse_userassist_value(&data);
            record(
                &mut map,
                file_name,
                EvidenceSource::UserAssist,
                parsed.and_then(|p| p.last_run_unix),
                parsed.map(|p| p.run_count),
            );
        }
    }
    Ok(into_vec(map))
}

const BAM_SUBKEY: &str = "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";

/// BAM (Background Activity Moderator): under each user SID, value
/// names are executable paths (device paths) and the first 8 bytes of
/// each binary value are the FILETIME of the last execution. Reading
/// BAM generally needs an elevated process; a key that will not open
/// is a warning upstream, not a failed audit.
pub(crate) fn collect_bam() -> Result<Vec<ExeEvidence>, String> {
    let Some(root) = RegKey::open(HKEY_LOCAL_MACHINE, BAM_SUBKEY) else {
        return Err(
            "BAM key could not be opened (reading BAM usually needs an elevated run)".to_owned(),
        );
    };
    let mut map = BTreeMap::new();
    for sid in root.subkey_names() {
        let Some(sid_key) = RegKey::open(root.0, &sid) else {
            continue;
        };
        for (path, _value_type, data) in sid_key.values() {
            if !path.contains('\\') {
                continue; // Version / SequenceNumber bookkeeping values.
            }
            let file_name = file_name_of(&path);
            if !file_name.to_lowercase().ends_with(".exe") {
                continue;
            }
            let last_used = data
                .get(0..8)
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map(u64::from_le_bytes)
                .and_then(filetime_to_unix);
            record(&mut map, file_name, EvidenceSource::Bam, last_used, None);
        }
    }
    Ok(into_vec(map))
}
