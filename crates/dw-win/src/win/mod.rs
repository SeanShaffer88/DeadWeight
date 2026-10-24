//! Live Windows collection. All `unsafe` code in this crate lives in
//! this module tree (the registry wrapper); every block is commented
//! with its invariants.
//!
//! Each source is independent and fault-tolerant: a source that
//! fails contributes a warning and no items. The audit as a whole
//! only fails when the entire inventory (apps, features, and
//! capabilities) failed — evidence sources can never fail an audit,
//! they can only leave it with less evidence.

mod dism;
mod evidence;
mod registry;

use dw_core::model::{AuditSnapshot, SCHEMA_VERSION};
use dw_core::time::now_utc;

use crate::match_evidence::{evidence_window_days, find_evidence, ExeEvidence};
use crate::{CollectError, CollectOutcome};

/// Encode a string as a NUL-terminated UTF-16 buffer for Win32 APIs.
pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
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
    if inventory_failures == 3 {
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

    let mut items = apps;
    items.append(&mut features);
    items.append(&mut capabilities);
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
            items,
        },
        warnings,
    })
}
