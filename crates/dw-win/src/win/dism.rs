//! Optional-feature and capability inventory via DISM.
//!
//! DISM is driven as a child process (its output parsed by the pure
//! parsers in `dw_core::dism_parse`). `/Online` queries against the
//! running OS need elevation on most builds: when DISM refuses, this
//! source fails with a warning that says so, and the audit continues
//! without features rather than failing outright.

use dw_core::dism_parse::{parse_dism_capabilities, parse_dism_features, DismEntry};
use dw_core::model::{AuditItem, Kind};

fn run_dism(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("dism.exe")
        .args(args)
        .output()
        .map_err(|err| format!("could not run dism.exe: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "dism.exe {} failed (exit code {}) — this inventory needs an \
             elevated run",
            args.join(" "),
            output
                .status
                .code()
                .map_or_else(|| "unknown".to_owned(), |c| c.to_string())
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn to_items(entries: Vec<DismEntry>, kind: Kind) -> Vec<AuditItem> {
    entries
        .into_iter()
        .map(|entry| AuditItem::new(&entry.name, kind, &entry.state))
        .collect()
}

/// Optional features from `dism /Online /Get-Features /Format:List`.
pub(crate) fn collect_features() -> Result<Vec<AuditItem>, String> {
    let text = run_dism(&["/Online", "/Get-Features", "/Format:List"])?;
    let entries = parse_dism_features(&text);
    if entries.is_empty() {
        return Err(
            "DISM reported no optional features (on a non-English Windows, \
             DISM's field labels differ and this parser finds nothing)"
                .to_owned(),
        );
    }
    Ok(to_items(entries, Kind::OptionalFeature))
}

/// Capabilities from `dism /Online /Get-Capabilities`.
pub(crate) fn collect_capabilities() -> Result<Vec<AuditItem>, String> {
    let text = run_dism(&["/Online", "/Get-Capabilities"])?;
    let entries = parse_dism_capabilities(&text);
    if entries.is_empty() {
        return Err("DISM reported no capabilities (on a non-English Windows, \
             DISM's field labels differ and this parser finds nothing)"
            .to_owned());
    }
    Ok(to_items(entries, Kind::Capability))
}
