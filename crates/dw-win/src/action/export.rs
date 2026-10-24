//! Export: copy the journal and the latest audit into a folder
//! the user chooses, with a manifest.
//!
//! This is the one way DeadWeight data leaves its own store, and
//! it happens only when the user runs `deadweight export <dir>`.
//! The export is a plain folder of JSON files — readable forever,
//! no DeadWeight required — so a user can hand it to a helper, keep
//! an off-PC copy of what was disabled, or delete it.

use std::fs;
use std::path::{Path, PathBuf};

use dw_core::time::format_unix_utc;

use crate::store;

/// What an export wrote.
#[derive(Debug)]
pub struct ExportSummary {
    /// The destination directory.
    pub dir: PathBuf,
    /// How many journal entries were copied.
    pub journal_entries: usize,
    /// Whether the latest audit was included.
    pub audit_included: bool,
}

/// Copy every journal entry from `journal_dir` and the latest audit
/// from `audits_dir` into `dir`, plus a `manifest.json` describing
/// the bundle.
pub fn export_to(
    dir: &Path,
    journal_dir: &Path,
    audits_dir: &Path,
    now_unix: i64,
) -> Result<ExportSummary, String> {
    fs::create_dir_all(dir).map_err(|e| format!("cannot create the export folder: {e}"))?;

    let journal_out = dir.join("journal");
    fs::create_dir_all(&journal_out)
        .map_err(|e| format!("cannot create the export journal folder: {e}"))?;
    let mut copied = 0usize;
    if journal_dir.exists() {
        let read = fs::read_dir(journal_dir)
            .map_err(|e| format!("cannot read the journal folder: {e}"))?;
        for item in read {
            let item = item.map_err(|e| format!("cannot read the journal folder: {e}"))?;
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let name = path
                .file_name()
                .ok_or_else(|| "journal entry without a file name".to_owned())?;
            fs::copy(&path, journal_out.join(name))
                .map_err(|e| format!("cannot copy journal entry {path:?}: {e}"))?;
            copied += 1;
        }
    }

    let mut audit_included = false;
    if let Some(latest) = store::latest_audit_in(audits_dir) {
        fs::copy(&latest, dir.join("audit.json"))
            .map_err(|e| format!("cannot copy the latest audit: {e}"))?;
        audit_included = true;
    }

    let manifest = serde_json::json!({
        "tool": "DeadWeight",
        "format": 1,
        "exported_at": format_unix_utc(now_unix.max(0) as u64),
        "journal_entries": copied,
        "audit_included": audit_included,
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("cannot serialise the export manifest: {e}"))?,
    )
    .map_err(|e| format!("cannot write the export manifest: {e}"))?;

    Ok(ExportSummary {
        dir: dir.to_path_buf(),
        journal_entries: copied,
        audit_included,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::journal::tests_support::TempJournal;
    use crate::action::journal::{EntryKind, JournalEntry, PriorState};

    #[test]
    fn export_copies_journal_audit_and_manifest() {
        let store = TempJournal::new();
        let journal = store.journal().clone();
        let mut entry = JournalEntry::new(
            1_792_569_600,
            EntryKind::Startup,
            "Tool",
            Some(dw_core::model::StartupSource::RunHkcu),
            PriorState::StartupAbsent,
        );
        journal.append(&mut entry).unwrap();

        let root = store.journal().dir().parent().unwrap().to_path_buf();
        let audits = root.join("audits");
        fs::create_dir_all(&audits).unwrap();
        fs::write(
            audits.join("2026-10-24T00-00-00Z.audit.json"),
            "{\"old\":true}",
        )
        .unwrap();
        fs::write(
            audits.join("2026-10-25T00-00-00Z.audit.json"),
            "{\"new\":true}",
        )
        .unwrap();

        let out = root.join("exported");
        let summary = export_to(&out, journal.dir(), &audits, 1_792_569_600).unwrap();
        assert_eq!(summary.journal_entries, 1);
        assert!(summary.audit_included);
        assert!(out
            .join("journal")
            .join(format!("{}.json", entry.id))
            .exists());
        let audit_text = fs::read_to_string(out.join("audit.json")).unwrap();
        assert_eq!(audit_text, "{\"new\":true}");
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["journal_entries"], 1);
        assert_eq!(manifest["audit_included"], true);
        assert_eq!(manifest["exported_at"], "2026-10-21T08:00:00Z");
    }

    #[test]
    fn export_with_nothing_to_copy_still_writes_a_manifest() {
        let store = TempJournal::new();
        let root = store.journal().dir().parent().unwrap().to_path_buf();
        let out = root.join("exported-empty");
        let summary = export_to(
            &out,
            &root.join("no-journal"),
            &root.join("no-audits"),
            1_792_569_600,
        )
        .unwrap();
        assert_eq!(summary.journal_entries, 0);
        assert!(!summary.audit_included);
        assert!(out.join("manifest.json").exists());
    }
}
