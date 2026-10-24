//! Live Windows collection and the disable tier's platform
//! operations. All `unsafe` code in this crate lives in this module
//! tree; every block is commented with its invariants.
//!
//! Each collection source is independent and fault-tolerant: a
//! source that fails contributes a warning and no items. The audit
//! as a whole only fails when the entire substantive inventory
//! (apps, features, capabilities, and services) failed — evidence
//! sources can never fail an audit, they can only leave it with
//! less evidence, and the startup inventory has no failure mode (a
//! missing key or folder is a normal state).

pub mod action_win;
mod dism;
mod evidence;
mod registry;
pub mod restore;
mod scm;
mod startup;

use dw_core::model::{AuditItem, AuditSnapshot, SCHEMA_VERSION};
use dw_core::service_parse::{exe_path_from_binary_path, path_is_under_windows_dir};
use dw_core::time::now_utc;

use crate::match_evidence::{
    evidence_for_exe, evidence_window_days, find_evidence, parent_app_for, ExeEvidence,
};
use crate::{CollectError, CollectOutcome};

/// Encode a string as a NUL-terminated UTF-16 buffer for Win32 APIs.
pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a NUL-terminated UTF-16 string from a raw pointer.
///
/// # Safety
/// `ptr` must be null or point to a NUL-terminated UTF-16 string that
/// stays alive and unmodified for the duration of the call. All call
/// sites pass pointers into API-owned buffers (enumeration results,
/// service configuration) that outlive the read.
pub(crate) unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: per this function's contract, `ptr` references a
    // NUL-terminated UTF-16 string; we scan for the terminator
    // without writing, then decode exactly the scanned range.
    let len = unsafe {
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        len
    };
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

/// Run all sources and assemble the audit. See the module docs for
/// the fault-tolerance contract.
pub(crate) fn collect() -> Result<CollectOutcome, CollectError> {
    let mut warnings: Vec<String> = Vec::new();
    let mut inventory_failures = 0usize;

    // --- Inventory ---------------------------------------------------
    let mut apps = match registry::collect_apps() {
        Ok(apps) => apps,
        Err(warning) => {
            inventory_failures += 1;
            warnings.push(format!("installed apps: {warning}"));
            Vec::new()
        }
    };
    let mut features = match dism::collect_features() {
        Ok(items) => items,
        Err(warning) => {
            inventory_failures += 1;
            warnings.push(format!("optional features: {warning}"));
            Vec::new()
        }
    };
    let mut capabilities = match dism::collect_capabilities() {
        Ok(items) => items,
        Err(warning) => {
            inventory_failures += 1;
            warnings.push(format!("capabilities: {warning}"));
            Vec::new()
        }
    };
    let mut services = match scm::collect_services() {
        Ok(items) => items,
        Err(warning) => {
            inventory_failures += 1;
            warnings.push(format!("services: {warning}"));
            Vec::new()
        }
    };
    // The startup inventory cannot fail (missing keys/folders are
    // normal), so it is not part of the total-failure count: an audit
    // fails only when apps, features, capabilities, AND services all
    // failed — nothing substantive could be inventoried at all.
    let mut startup_items = match startup::collect_startup() {
        Ok(items) => items,
        Err(warning) => {
            warnings.push(format!("startup items: {warning}"));
            Vec::new()
        }
    };
    if inventory_failures == 4 {
        return Err(CollectError::TotalFailure { warnings });
    }

    // --- Usage evidence ------------------------------------------------
    let mut observations: Vec<ExeEvidence> = Vec::new();
    for (name, source) in [
        (
            "Prefetch",
            evidence::collect_prefetch as fn() -> Result<Vec<ExeEvidence>, String>,
        ),
        ("UserAssist", evidence::collect_userassist),
        ("BAM", evidence::collect_bam),
    ] {
        match source() {
            Ok(mut found) => observations.append(&mut found),
            Err(warning) => warnings.push(format!("{name} evidence: {warning}")),
        }
    }

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let window_days = evidence_window_days(&observations, now_unix);

    // Apps get evidence matched onto them; features and capabilities
    // carry no usage evidence (nothing records "running" a feature),
    // which the tiering rules account for.
    for app in &mut apps {
        if let Some(evidence) = find_evidence(&app.name, &observations) {
            app.evidence = evidence;
        }
    }

    let windows_dir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());

    // Services and startup items are matched by their exact
    // executable (binary path / target command), not by name
    // heuristics, and each learns which inventoried app it belongs
    // to (if any) and whether its program lives in the Windows
    // directory — the facts their tiering rules cite.
    for service in &mut services {
        attach_exe_context(
            service,
            service.binary_path.clone(),
            &apps,
            &windows_dir,
            &observations,
        );
    }
    for item in &mut startup_items {
        let exe = item
            .target
            .as_deref()
            .map(exe_path_from_binary_path)
            .filter(|path| !path.is_empty());
        attach_exe_context(item, exe, &apps, &windows_dir, &observations);
    }

    let mut items = apps;
    items.append(&mut features);
    items.append(&mut capabilities);
    items.append(&mut services);
    items.append(&mut startup_items);
    items.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    Ok(CollectOutcome {
        snapshot: AuditSnapshot {
            schema_version: SCHEMA_VERSION,
            captured_at: now_utc(),
            evidence_window_days: window_days,
            windows_dir: Some(windows_dir),
            items,
        },
        warnings,
    })
}

/// Attach exact-executable evidence, parent app, and the
/// Windows-directory fact to one service or startup item.
fn attach_exe_context(
    item: &mut AuditItem,
    exe_path: Option<String>,
    apps: &[AuditItem],
    windows_dir: &str,
    observations: &[ExeEvidence],
) {
    let Some(exe_path) = exe_path else {
        return;
    };
    if let Some(evidence) = evidence_for_exe(&exe_path, observations) {
        item.evidence = evidence;
    }
    item.parent_app = parent_app_for(&exe_path, apps);
    item.binary_in_windows_dir = path_is_under_windows_dir(&exe_path, windows_dir);
}
