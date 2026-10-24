//! The action journal: one JSON file per disable action, written
//! *before* the action is applied.
//!
//! The journal is the product's memory and its conscience. An entry
//! records exactly what was about to change and what the state was
//! before, so undo can restore it byte-for-byte even after a crash,
//! and so the "watch list" can tell the user what has been disabled,
//! when, and when its 30-day watch period ends. The journal lives
//! under `%LOCALAPPDATA%\DeadWeight\journal` and never leaves the
//! machine except through the user's own `export`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use dw_core::model::StartupSource;
use dw_core::time::format_unix_utc;

/// How many days a disabled item stays on the watch list before the
/// report calls it due for review. Disabling is never permanent by
/// default — the watch period is when the user finds out whether
/// anything they use actually needed the thing.
pub const WATCH_DAYS: i64 = 30;

const SECONDS_PER_DAY: i64 = 86_400;

/// What kind of item an entry disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Service,
    Startup,
}

impl EntryKind {
    /// Human label for CLI output.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            EntryKind::Service => "service",
            EntryKind::Startup => "startup item",
        }
    }
}

/// Where an entry is in its lifecycle.
///
/// Written `Planned` before the mutation is attempted, so a crash
/// mid-action leaves a truthful record; undo treats `Planned` as
/// possibly-applied and restores the prior state idempotently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    Planned,
    Applied,
    Failed,
    Undone,
}

/// The state an item was in before it was disabled — everything
/// undo needs, captured before the change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PriorState {
    /// A service's start type before it was set to Disabled.
    ServiceStartType {
        /// The raw `dwStartType` value (2 = Automatic, 3 = Manual…).
        start_type: u32,
    },
    /// A startup item's StartupApproved bytes, verbatim.
    StartupBlob {
        /// The exact bytes that were present.
        bytes: Vec<u8>,
    },
    /// The startup item had no StartupApproved value (it ran).
    StartupAbsent,
}

/// One journaled disable action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// File-safe unique id (also the file's stem).
    pub id: String,
    /// When the action was planned, ISO-8601 UTC.
    pub created_at: String,
    /// The same moment as a Unix timestamp, for arithmetic.
    pub created_unix: i64,
    /// Service or startup item.
    pub kind: EntryKind,
    /// The service name or startup item name.
    pub name: String,
    /// Startup items only: which source the entry came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<StartupSource>,
    /// The state before the change.
    pub prior_state: PriorState,
    /// Lifecycle status.
    pub status: EntryStatus,
    /// Unix time the 30-day watch period ends.
    pub watch_due_unix: i64,
}

impl JournalEntry {
    /// Create a `Planned` entry for an action about to happen.
    #[must_use]
    pub fn new(
        now_unix: i64,
        kind: EntryKind,
        name: &str,
        source: Option<StartupSource>,
        prior_state: PriorState,
    ) -> JournalEntry {
        let kind_slug = match kind {
            EntryKind::Service => "service",
            EntryKind::Startup => "startup",
        };
        JournalEntry {
            id: format!("{now_unix}-{kind_slug}-{}", slug(name)),
            created_at: format_unix_utc(now_unix.max(0) as u64),
            created_unix: now_unix,
            kind,
            name: name.to_owned(),
            source,
            prior_state,
            status: EntryStatus::Planned,
            watch_due_unix: now_unix + WATCH_DAYS * SECONDS_PER_DAY,
        }
    }

    /// The watch-due moment as an ISO-8601 UTC date.
    #[must_use]
    pub fn watch_due_date(&self) -> String {
        format_unix_utc(self.watch_due_unix.max(0) as u64)
    }

    /// Whole days between `now_unix` and the watch deadline
    /// (negative once the watch is overdue).
    #[must_use]
    pub fn watch_days_remaining(&self, now_unix: i64) -> i64 {
        (self.watch_due_unix - now_unix).div_euclid(SECONDS_PER_DAY)
    }
}

/// File-safe slug for ids: ASCII alphanumerics and `-`, everything
/// else folded to `-`, capped so file names stay reasonable.
fn slug(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= 48 {
            break;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "item".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Reads and writes journal entries in one directory.
#[derive(Debug, Clone)]
pub struct Journal {
    dir: PathBuf,
}

impl Journal {
    /// A journal rooted at `dir` (created on first write).
    #[must_use]
    pub fn new(dir: PathBuf) -> Journal {
        Journal { dir }
    }

    /// The journal directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn entry_path(&self, id: &str) -> Result<PathBuf, String> {
        if id.is_empty()
            || id.contains('/')
            || id.contains('\\')
            || id.contains("..")
            || id.contains('\0')
        {
            return Err(format!("invalid journal entry id {id:?}"));
        }
        Ok(self.dir.join(format!("{id}.json")))
    }

    /// Write a new entry. If an entry with the same id already
    /// exists (two actions on the same item within one second), the
    /// entry's id gains a `-2`, `-3`, … suffix until it is unique —
    /// a journal entry is never silently overwritten at creation.
    pub fn append(&self, entry: &mut JournalEntry) -> Result<(), String> {
        fs::create_dir_all(&self.dir)
            .map_err(|e| format!("cannot create the journal folder: {e}"))?;
        let base = entry.id.clone();
        let mut n = 1;
        loop {
            let path = self.entry_path(&entry.id)?;
            if !path.exists() {
                break;
            }
            n += 1;
            entry.id = format!("{base}-{n}");
        }
        self.write(entry)
    }

    /// Overwrite an existing entry (status transitions).
    pub fn update(&self, entry: &JournalEntry) -> Result<(), String> {
        self.write(entry)
    }

    fn write(&self, entry: &JournalEntry) -> Result<(), String> {
        let path = self.entry_path(&entry.id)?;
        let json = serde_json::to_string_pretty(entry)
            .map_err(|e| format!("cannot serialise journal entry: {e}"))?;
        // Write-then-rename so a crash never leaves a torn entry.
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json)
            .map_err(|e| format!("cannot write journal entry {}: {e}", entry.id))?;
        fs::rename(&tmp, &path)
            .map_err(|e| format!("cannot store journal entry {}: {e}", entry.id))?;
        Ok(())
    }

    /// Load one entry by id.
    pub fn load(&self, id: &str) -> Result<JournalEntry, String> {
        let path = self.entry_path(id)?;
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("no journal entry {id:?} can be read: {e}"))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("journal entry {id:?} is not valid JSON: {e}"))
    }

    /// All entries, newest first. A missing directory is an empty
    /// journal, not an error; an unreadable entry file is skipped
    /// only if it is not JSON at all (foreign files), while a
    /// corrupt DeadWeight entry is an error worth surfacing.
    pub fn entries(&self) -> Result<Vec<JournalEntry>, String> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let read =
            fs::read_dir(&self.dir).map_err(|e| format!("cannot read the journal folder: {e}"))?;
        for item in read {
            let item = item.map_err(|e| format!("cannot read the journal folder: {e}"))?;
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path)
                .map_err(|e| format!("cannot read journal entry {path:?}: {e}"))?;
            let entry: JournalEntry = serde_json::from_str(&text)
                .map_err(|e| format!("journal entry {path:?} is not valid DeadWeight JSON: {e}"))?;
            out.push(entry);
        }
        out.sort_by(|a, b| {
            b.created_unix
                .cmp(&a.created_unix)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(out)
    }

    /// The newest entry that can still be undone (`Applied`, or
    /// `Planned` — a crash may have applied it), if any.
    pub fn latest_undoable(&self) -> Result<Option<JournalEntry>, String> {
        Ok(self
            .entries()?
            .into_iter()
            .find(|e| matches!(e.status, EntryStatus::Applied | EntryStatus::Planned)))
    }
}

/// Test support: a journal rooted in a unique temp directory,
/// removed on drop. Shared by the journal and engine tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::Journal;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// Owns the temp directory; the journal handle is cloned out.
    pub struct TempJournal {
        root: PathBuf,
        journal: Journal,
    }

    impl TempJournal {
        pub fn new() -> TempJournal {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("dw-journal-test-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let journal = Journal::new(root.join("journal"));
            TempJournal { root, journal }
        }

        /// The journal rooted inside the temp directory.
        pub fn journal(&self) -> &Journal {
            &self.journal
        }
    }

    impl Drop for TempJournal {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::TempJournal;
    use super::*;

    fn temp_journal() -> (TempJournal, Journal) {
        let store = TempJournal::new();
        let journal = store.journal().clone();
        (store, journal)
    }

    const NOW: i64 = 1_792_569_600;

    fn service_entry(name: &str, now: i64) -> JournalEntry {
        JournalEntry::new(
            now,
            EntryKind::Service,
            name,
            None,
            PriorState::ServiceStartType { start_type: 2 },
        )
    }

    #[test]
    fn new_entry_is_planned_with_a_30_day_watch() {
        let entry = service_entry("ExampleSvc", NOW);
        assert_eq!(entry.status, EntryStatus::Planned);
        assert_eq!(entry.watch_due_unix, NOW + 30 * 86_400);
        assert_eq!(entry.watch_days_remaining(NOW), 30);
        assert_eq!(entry.watch_days_remaining(NOW + 31 * 86_400), -1);
        assert!(entry.id.contains("examplesvc"), "{}", entry.id);
        assert_eq!(entry.created_at, "2026-10-21T08:00:00Z");
    }

    #[test]
    fn append_load_update_round_trip() {
        let (_dir, journal) = temp_journal();
        let mut entry = service_entry("ExampleSvc", NOW);
        journal.append(&mut entry).unwrap();
        let loaded = journal.load(&entry.id).unwrap();
        assert_eq!(loaded, entry);

        let mut updated = entry.clone();
        updated.status = EntryStatus::Applied;
        journal.update(&updated).unwrap();
        assert_eq!(
            journal.load(&entry.id).unwrap().status,
            EntryStatus::Applied
        );
    }

    #[test]
    fn append_never_overwrites_a_same_second_entry() {
        let (_dir, journal) = temp_journal();
        let mut first = service_entry("ExampleSvc", NOW);
        let mut second = service_entry("ExampleSvc", NOW);
        journal.append(&mut first).unwrap();
        journal.append(&mut second).unwrap();
        assert_ne!(first.id, second.id);
        assert!(second.id.ends_with("-2"), "{}", second.id);
        assert_eq!(journal.entries().unwrap().len(), 2);
    }

    #[test]
    fn entries_newest_first_and_latest_undoable_skips_undone() {
        let (_dir, journal) = temp_journal();
        let mut older = service_entry("Older", NOW);
        older.status = EntryStatus::Undone;
        journal.append(&mut older).unwrap();
        let mut newer = service_entry("Newer", NOW + 10);
        newer.status = EntryStatus::Applied;
        journal.append(&mut newer).unwrap();

        let entries = journal.entries().unwrap();
        assert_eq!(entries[0].name, "Newer");
        let undoable = journal.latest_undoable().unwrap().unwrap();
        assert_eq!(undoable.name, "Newer");
    }

    #[test]
    fn missing_directory_is_an_empty_journal() {
        let journal = Journal::new(PathBuf::from("/definitely/not/a/real/dw/dir"));
        assert!(journal.entries().unwrap().is_empty());
        assert!(journal.latest_undoable().unwrap().is_none());
    }

    #[test]
    fn load_rejects_path_traversal_ids() {
        let (_dir, journal) = temp_journal();
        assert!(journal.load("../secret").is_err());
        assert!(journal.load("a/b").is_err());
    }
}
