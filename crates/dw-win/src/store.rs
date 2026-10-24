//! Local audit storage.
//!
//! Audits are written atomically: the JSON goes to a temporary file
//! in the same directory, is flushed to disk, and is then renamed
//! over the final path (the pattern used by SEAN's SettingsKit), so a
//! crash mid-write can never leave a half-written audit behind.
//!
//! Audits are sensitive: they record what is installed on a PC and
//! how it has been used. They live only under
//! `%LOCALAPPDATA%\DeadWeight` and [`purge_audits`] deletes the whole
//! store in one action.

use std::io::Write;
use std::path::{Path, PathBuf};

use dw_core::model::AuditSnapshot;

/// The application data directory: `%LOCALAPPDATA%\DeadWeight` on
/// Windows. The non-Windows fallback (`$XDG_DATA_HOME` or
/// `~/.local/share`) exists only so the storage layer can be
/// developed and tested off Windows; the collector is Windows-only.
#[must_use]
pub fn default_app_dir() -> PathBuf {
    base_data_dir().join("DeadWeight")
}

/// Directory audits are stored in by default:
/// `%LOCALAPPDATA%\DeadWeight\audits` on Windows.
#[must_use]
pub fn default_audits_dir() -> PathBuf {
    default_app_dir().join("audits")
}

/// Directory journal entries are stored in by default:
/// `%LOCALAPPDATA%\DeadWeight\journal` on Windows.
#[must_use]
pub fn default_journal_dir() -> PathBuf {
    default_app_dir().join("journal")
}

/// The newest audit file in `dir`, if any. Audit file names are
/// derived from their capture timestamps, so the greatest file name
/// is the latest audit.
#[must_use]
pub fn latest_audit_in(dir: &Path) -> Option<PathBuf> {
    let read = std::fs::read_dir(dir).ok()?;
    read.filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".audit.json"))
        })
        .max()
}

#[cfg(target_os = "windows")]
fn base_data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA").map_or_else(|| PathBuf::from("."), PathBuf::from)
}

#[cfg(not(target_os = "windows"))]
fn base_data_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg);
    }
    std::env::var_os("HOME").map_or_else(
        || PathBuf::from("."),
        |home| PathBuf::from(home).join(".local").join("share"),
    )
}

/// Make a timestamp safe to use as a file name: characters that are
/// not alphanumeric, `-`, or `.` become `-`. (ISO-8601 timestamps
/// contain `:`, which Windows file names forbid.)
#[must_use]
pub fn sanitize_timestamp_for_filename(captured_at: &str) -> String {
    captured_at
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// File name an audit is stored under, derived from its capture time.
#[must_use]
pub fn audit_filename(captured_at: &str) -> String {
    format!(
        "{}.audit.json",
        sanitize_timestamp_for_filename(captured_at)
    )
}

/// Write text to `path` atomically (temp file + flush + rename in the
/// same directory), creating parent directories as needed.
///
/// # Errors
/// Returns any I/O error from creating directories or writing the file.
pub fn write_text_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "data.json".to_owned());
    let temp_path = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    let write_result = (|| {
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp_path, path)
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

/// Write an audit to `path` atomically.
///
/// # Errors
/// Returns any I/O error from creating directories or writing the
/// file, and a serialization error wrapped as `InvalidData`.
pub fn write_audit_atomic(path: &Path, audit: &AuditSnapshot) -> std::io::Result<()> {
    let json = audit
        .to_json()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    write_text_atomic(path, &json)
}

/// What a purge removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeOutcome {
    /// The directory that was purged.
    pub dir: PathBuf,
    /// Number of files deleted.
    pub files_removed: usize,
    /// Total size of the deleted files, in bytes.
    pub bytes_removed: u64,
}

/// Delete every file in the default audits directory, then the
/// directory itself. This is the product's one-action privacy exit:
/// no audit data survives it.
///
/// # Errors
/// Returns the first I/O error encountered while deleting.
pub fn purge_audits() -> std::io::Result<PurgeOutcome> {
    purge_dir(&default_audits_dir())
}

/// [`purge_audits`] against an explicit directory (the testable core).
///
/// # Errors
/// Returns the first I/O error encountered while deleting.
pub fn purge_dir(dir: &Path) -> std::io::Result<PurgeOutcome> {
    let mut outcome = PurgeOutcome {
        dir: dir.to_path_buf(),
        files_removed: 0,
        bytes_removed: 0,
    };
    if !dir.exists() {
        return Ok(outcome);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            outcome.bytes_removed += entry.metadata().map(|m| m.len()).unwrap_or(0);
            std::fs::remove_file(&path)?;
            outcome.files_removed += 1;
        }
    }
    // Best effort: the directory itself goes too, but a locked or
    // recreated directory must not fail the purge — the data is gone.
    let _ = std::fs::remove_dir(dir);
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "deadweight-store-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn purge_removes_files_and_counts_bytes() {
        let dir = temp_dir("purge");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("a.audit.json"), b"12345").expect("write");
        std::fs::write(dir.join("b.audit.json"), b"123").expect("write");
        let outcome = purge_dir(&dir).expect("purge");
        assert_eq!(outcome.files_removed, 2);
        assert_eq!(outcome.bytes_removed, 8);
        assert!(!dir.exists());
    }

    #[test]
    fn purge_of_missing_dir_is_a_no_op() {
        let dir = temp_dir("missing");
        let outcome = purge_dir(&dir).expect("purge");
        assert_eq!(outcome.files_removed, 0);
        assert_eq!(outcome.bytes_removed, 0);
    }

    #[test]
    fn audit_write_round_trip() {
        let dir = temp_dir("write");
        let audit = AuditSnapshot {
            schema_version: dw_core::model::SCHEMA_VERSION,
            captured_at: "2026-10-24T20:56:00Z".to_owned(),
            evidence_window_days: 42,
            windows_dir: None,
            items: Vec::new(),
        };
        let path = dir.join(audit_filename(&audit.captured_at));
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".audit.json"));
        write_audit_atomic(&path, &audit).expect("write");
        let text = std::fs::read_to_string(&path).expect("read");
        let back = AuditSnapshot::from_json(&text).expect("parse");
        assert_eq!(back, audit);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
