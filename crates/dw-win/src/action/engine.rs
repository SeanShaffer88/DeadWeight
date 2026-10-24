//! The disable / re-enable engine.
//!
//! The order of operations is the safety contract, and it is the
//! same on every path:
//!
//! 1. **Validate** the plan (denylist and RunOnce refusals happen
//!    here, before anything is read or written).
//! 2. **Capture** the item's prior state.
//! 3. **Attempt a system restore point.** If it cannot be created,
//!    abort — unless the caller explicitly chose to proceed without
//!    one, in which case the journal still records the action.
//! 4. **Journal `Planned`** — the record exists before the change.
//! 5. **Mutate**, then **verify by re-reading** the state.
//! 6. Mark the entry `Applied`, or `Failed` with the record kept.
//!
//! Undo (`enable`) runs the inverse: load the entry, restore the
//! recorded prior state (idempotently — an entry left `Planned` by a
//! crash is treated as possibly-applied), verify, mark `Undone`.
//! Undo never consults the denylist: putting something back is
//! always allowed.
//!
//! The engine is generic over [`PlatformOps`] and [`RestorePointOps`]
//! so the whole state machine is unit-tested on any platform with
//! recording fakes; the real Windows implementations live in the
//! `win` module.

use dw_core::model::StartupSource;
use dw_core::service_parse::SERVICE_DISABLED;

use super::journal::{EntryKind, EntryStatus, Journal, JournalEntry, PriorState};
use super::plan::{
    decode_startup_state, plan_disable_service, plan_disable_startup, startup_blob, Refusal,
    StartupState,
};

/// The live-system operations the engine needs. Implementations
/// must obey two rules: service operations change the start type
/// only (never start or stop a service), and startup operations
/// touch only the item's StartupApproved value.
pub trait PlatformOps {
    /// A service's current start type (the raw `dwStartType`).
    fn service_start_type(&self, name: &str) -> Result<u32, String>;
    /// Set a service's start type, changing nothing else about it.
    fn set_service_start_type(&self, name: &str, start_type: u32) -> Result<(), String>;
    /// A startup item's current StartupApproved bytes, if any.
    fn startup_approved(
        &self,
        name: &str,
        source: StartupSource,
    ) -> Result<Option<Vec<u8>>, String>;
    /// Write (`Some`) or remove (`None`) a startup item's
    /// StartupApproved value.
    fn set_startup_approved(
        &self,
        name: &str,
        source: StartupSource,
        blob: Option<&[u8]>,
    ) -> Result<(), String>;
}

/// Creating system restore points, abstracted for testing.
pub trait RestorePointOps {
    /// Create a restore point; on success returns a short
    /// human-readable note (sequence number when known).
    fn create(&self, description: &str) -> Result<String, String>;
}

/// Why an engine operation did not complete.
#[derive(Debug)]
pub enum EngineError {
    /// The plan layer refused the action (denylist / RunOnce).
    Refused(Refusal),
    /// No restore point could be created and the caller did not
    /// agree to proceed without one. Nothing was changed.
    RestorePointUnavailable(String),
    /// A live-system operation failed.
    Platform(String),
    /// The journal could not be read or written. When this happens
    /// before a mutation, nothing was changed; the entry may exist
    /// as `Planned` if the failure came after it was written.
    Journal(String),
    /// There is no entry to undo (none exists, or it is undone).
    NothingToUndo(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Refused(r) => write!(f, "{r}"),
            EngineError::RestorePointUnavailable(why) => write!(
                f,
                "no system restore point could be created ({why}); nothing was \
                 changed. Re-run with --no-restore-point to proceed without one \
                 — the action is still journaled and undoable"
            ),
            EngineError::Platform(why) => write!(f, "{why}"),
            EngineError::Journal(why) => write!(f, "journal: {why}"),
            EngineError::NothingToUndo(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// The result of a successful disable or enable call.
#[derive(Debug)]
pub enum ActionOutcome {
    /// The change was applied and verified.
    Applied {
        /// The journal entry (status `Applied` after a disable,
        /// `Undone` after an enable).
        entry: JournalEntry,
        /// What the restore-point step did (disable only; empty
        /// for enable, which takes no restore point).
        restore_note: String,
    },
    /// The item was already in the desired state; nothing was
    /// changed and nothing was journaled (there is nothing new to
    /// undo — an earlier disable, if any, has its own entry).
    AlreadyInDesiredState {
        /// Plain-language description of the existing state.
        description: String,
    },
}

/// The disable/re-enable engine over a journal and two providers.
pub struct Engine<'a, P: PlatformOps, R: RestorePointOps> {
    journal: &'a Journal,
    platform: &'a P,
    restore: &'a R,
}

impl<'a, P: PlatformOps, R: RestorePointOps> Engine<'a, P, R> {
    /// An engine over the given journal, platform, and restore
    /// provider.
    pub fn new(journal: &'a Journal, platform: &'a P, restore: &'a R) -> Engine<'a, P, R> {
        Engine {
            journal,
            platform,
            restore,
        }
    }

    /// Attempt the restore point, honouring the caller's choice.
    /// Returns the note to record, or aborts the action.
    fn restore_step(
        &self,
        description: &str,
        proceed_without: bool,
    ) -> Result<String, EngineError> {
        match self.restore.create(description) {
            Ok(note) => Ok(note),
            Err(why) if proceed_without => Ok(format!(
                "no restore point was created ({why}) — proceeded anyway at \
                 your request; the action is journaled and undoable"
            )),
            Err(why) => Err(EngineError::RestorePointUnavailable(why)),
        }
    }

    /// Mark an entry `Failed` (best effort — the original error is
    /// the one reported) and return the error.
    fn fail(&self, entry: &mut JournalEntry, err: EngineError) -> EngineError {
        entry.status = EntryStatus::Failed;
        let _ = self.journal.update(entry);
        err
    }

    /// Disable a service: set its start type to Disabled. A running
    /// service is never stopped — the change takes effect at the
    /// next start, which the CLI output says plainly.
    pub fn disable_service(
        &self,
        name: &str,
        proceed_without_restore_point: bool,
        now_unix: i64,
    ) -> Result<ActionOutcome, EngineError> {
        plan_disable_service(name).map_err(EngineError::Refused)?;
        let prior = self
            .platform
            .service_start_type(name)
            .map_err(EngineError::Platform)?;
        if prior == SERVICE_DISABLED {
            return Ok(ActionOutcome::AlreadyInDesiredState {
                description: format!(
                    "service \"{name}\" is already disabled (its start type is \
                     Disabled) — nothing to do"
                ),
            });
        }
        let restore_note = self.restore_step(
            &format!("Before DeadWeight disabled the service {name}"),
            proceed_without_restore_point,
        )?;
        let mut entry = JournalEntry::new(
            now_unix,
            EntryKind::Service,
            name,
            None,
            PriorState::ServiceStartType { start_type: prior },
        );
        self.journal
            .append(&mut entry)
            .map_err(EngineError::Journal)?;
        if let Err(why) = self.platform.set_service_start_type(name, SERVICE_DISABLED) {
            return Err(self.fail(&mut entry, EngineError::Platform(why)));
        }
        match self.platform.service_start_type(name) {
            Ok(now) if now == SERVICE_DISABLED => {}
            Ok(now) => {
                return Err(self.fail(
                    &mut entry,
                    EngineError::Platform(format!(
                        "verification failed: the service's start type reads {now} \
                         after the change, not Disabled (4) — the entry is marked \
                         Failed; check the service's state before retrying"
                    )),
                ));
            }
            Err(why) => return Err(self.fail(&mut entry, EngineError::Platform(why))),
        }
        entry.status = EntryStatus::Applied;
        self.journal.update(&entry).map_err(EngineError::Journal)?;
        Ok(ActionOutcome::Applied {
            entry,
            restore_note,
        })
    }

    /// Disable a startup item: write its StartupApproved value as
    /// disabled. The item's Run entry or shortcut is never touched.
    pub fn disable_startup(
        &self,
        name: &str,
        source: StartupSource,
        proceed_without_restore_point: bool,
        now_unix: i64,
    ) -> Result<ActionOutcome, EngineError> {
        plan_disable_startup(name, source).map_err(EngineError::Refused)?;
        let prior_blob = self
            .platform
            .startup_approved(name, source)
            .map_err(EngineError::Platform)?;
        if decode_startup_state(prior_blob.as_deref()) == StartupState::Disabled {
            return Ok(ActionOutcome::AlreadyInDesiredState {
                description: format!("startup item \"{name}\" is already disabled — nothing to do"),
            });
        }
        let restore_note = self.restore_step(
            &format!("Before DeadWeight disabled the startup item {name}"),
            proceed_without_restore_point,
        )?;
        let prior_state = match &prior_blob {
            Some(bytes) => PriorState::StartupBlob {
                bytes: bytes.clone(),
            },
            None => PriorState::StartupAbsent,
        };
        let mut entry = JournalEntry::new(
            now_unix,
            EntryKind::Startup,
            name,
            Some(source),
            prior_state,
        );
        self.journal
            .append(&mut entry)
            .map_err(EngineError::Journal)?;
        let blob = startup_blob(true, now_unix);
        if let Err(why) = self
            .platform
            .set_startup_approved(name, source, Some(&blob))
        {
            return Err(self.fail(&mut entry, EngineError::Platform(why)));
        }
        match self.platform.startup_approved(name, source) {
            Ok(now) if decode_startup_state(now.as_deref()) == StartupState::Disabled => {}
            Ok(_) => {
                return Err(self.fail(
                    &mut entry,
                    EngineError::Platform(
                        "verification failed: the startup item does not read as \
                         disabled after the change — the entry is marked Failed; \
                         check its state in Task Manager before retrying"
                            .to_owned(),
                    ),
                ));
            }
            Err(why) => return Err(self.fail(&mut entry, EngineError::Platform(why))),
        }
        entry.status = EntryStatus::Applied;
        self.journal.update(&entry).map_err(EngineError::Journal)?;
        Ok(ActionOutcome::Applied {
            entry,
            restore_note,
        })
    }

    /// Undo a disable: restore the entry's recorded prior state.
    /// `entry_id` selects an entry; `None` undoes the newest
    /// undoable one. Idempotent: an item already back in its prior
    /// state verifies clean and the entry is marked `Undone`.
    pub fn enable(&self, entry_id: Option<&str>) -> Result<ActionOutcome, EngineError> {
        let mut entry = match entry_id {
            Some(id) => self.journal.load(id).map_err(EngineError::Journal)?,
            None => self
                .journal
                .latest_undoable()
                .map_err(EngineError::Journal)?
                .ok_or_else(|| {
                    EngineError::NothingToUndo(
                        "there is no disable action waiting to be undone".to_owned(),
                    )
                })?,
        };
        if entry.status == EntryStatus::Undone {
            return Err(EngineError::NothingToUndo(format!(
                "journal entry {} (\"{}\") was already undone",
                entry.id, entry.name
            )));
        }
        match entry.kind {
            EntryKind::Service => {
                let PriorState::ServiceStartType { start_type: prior } = entry.prior_state else {
                    return Err(EngineError::Journal(format!(
                        "entry {} is a service entry without a service prior state",
                        entry.id
                    )));
                };
                let current = self
                    .platform
                    .service_start_type(&entry.name)
                    .map_err(EngineError::Platform)?;
                if current != prior {
                    self.platform
                        .set_service_start_type(&entry.name, prior)
                        .map_err(EngineError::Platform)?;
                }
                let after = self
                    .platform
                    .service_start_type(&entry.name)
                    .map_err(EngineError::Platform)?;
                if after != prior {
                    return Err(EngineError::Platform(format!(
                        "verification failed: the service's start type reads {after} \
                         after undo, not the recorded {prior} — the entry is left \
                         un-undone so you can retry"
                    )));
                }
            }
            EntryKind::Startup => {
                let Some(source) = entry.source else {
                    return Err(EngineError::Journal(format!(
                        "entry {} is a startup entry without a source",
                        entry.id
                    )));
                };
                let target: Option<Vec<u8>> = match &entry.prior_state {
                    PriorState::StartupBlob { bytes } => Some(bytes.clone()),
                    PriorState::StartupAbsent => None,
                    PriorState::ServiceStartType { .. } => {
                        return Err(EngineError::Journal(format!(
                            "entry {} is a startup entry with a service prior state",
                            entry.id
                        )));
                    }
                };
                let current = self
                    .platform
                    .startup_approved(&entry.name, source)
                    .map_err(EngineError::Platform)?;
                if current != target {
                    self.platform
                        .set_startup_approved(&entry.name, source, target.as_deref())
                        .map_err(EngineError::Platform)?;
                }
                let after = self
                    .platform
                    .startup_approved(&entry.name, source)
                    .map_err(EngineError::Platform)?;
                if after != target {
                    return Err(EngineError::Platform(
                        "verification failed: the startup item's recorded state was \
                         not restored — the entry is left un-undone so you can retry"
                            .to_owned(),
                    ));
                }
            }
        }
        entry.status = EntryStatus::Undone;
        self.journal.update(&entry).map_err(EngineError::Journal)?;
        Ok(ActionOutcome::Applied {
            entry,
            restore_note: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::journal::EntryStatus;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakePlatform {
        services: RefCell<HashMap<String, u32>>,
        blobs: RefCell<HashMap<(String, StartupSource), Vec<u8>>>,
        fail_set_service: RefCell<bool>,
    }

    impl PlatformOps for FakePlatform {
        fn service_start_type(&self, name: &str) -> Result<u32, String> {
            self.services
                .borrow()
                .get(name)
                .copied()
                .ok_or_else(|| format!("no such service {name}"))
        }

        fn set_service_start_type(&self, name: &str, start_type: u32) -> Result<(), String> {
            if *self.fail_set_service.borrow() {
                return Err("simulated SCM failure".to_owned());
            }
            self.services
                .borrow_mut()
                .insert(name.to_owned(), start_type);
            Ok(())
        }

        fn startup_approved(
            &self,
            name: &str,
            source: StartupSource,
        ) -> Result<Option<Vec<u8>>, String> {
            Ok(self.blobs.borrow().get(&(name.to_owned(), source)).cloned())
        }

        fn set_startup_approved(
            &self,
            name: &str,
            source: StartupSource,
            blob: Option<&[u8]>,
        ) -> Result<(), String> {
            let mut blobs = self.blobs.borrow_mut();
            match blob {
                Some(bytes) => {
                    blobs.insert((name.to_owned(), source), bytes.to_vec());
                }
                None => {
                    blobs.remove(&(name.to_owned(), source));
                }
            }
            Ok(())
        }
    }

    struct FakeRestore {
        fail: bool,
        calls: RefCell<Vec<String>>,
    }

    impl RestorePointOps for FakeRestore {
        fn create(&self, description: &str) -> Result<String, String> {
            self.calls.borrow_mut().push(description.to_owned());
            if self.fail {
                Err("System Restore is turned off".to_owned())
            } else {
                Ok("created restore point (sequence 42)".to_owned())
            }
        }
    }

    const NOW: i64 = 1_792_569_600;

    fn setup() -> (
        crate::action::journal::tests_support::TempJournal,
        FakePlatform,
        FakeRestore,
    ) {
        (
            crate::action::journal::tests_support::TempJournal::new(),
            FakePlatform::default(),
            FakeRestore {
                fail: false,
                calls: RefCell::new(Vec::new()),
            },
        )
    }

    #[test]
    fn disable_service_happy_path_journals_then_applies() {
        let (store, platform, restore) = setup();
        platform
            .services
            .borrow_mut()
            .insert("ExampleSvc".to_owned(), 2);
        let engine = Engine::new(store.journal(), &platform, &restore);
        let outcome = engine.disable_service("ExampleSvc", false, NOW).unwrap();
        let ActionOutcome::Applied {
            entry,
            restore_note,
        } = outcome
        else {
            panic!("expected Applied, got {outcome:?}");
        };
        assert_eq!(entry.status, EntryStatus::Applied);
        assert_eq!(entry.watch_due_unix, NOW + 30 * 86_400);
        assert!(restore_note.contains("sequence 42"));
        assert_eq!(platform.service_start_type("ExampleSvc").unwrap(), 4);
        assert_eq!(store.journal().entries().unwrap().len(), 1);
        assert_eq!(restore.calls.borrow().len(), 1);
    }

    #[test]
    fn protected_service_is_refused_before_anything_happens() {
        let (store, platform, restore) = setup();
        platform
            .services
            .borrow_mut()
            .insert("WinDefend".to_owned(), 2);
        let engine = Engine::new(store.journal(), &platform, &restore);
        let err = engine.disable_service("WinDefend", false, NOW).unwrap_err();
        assert!(matches!(err, EngineError::Refused(_)), "{err}");
        assert!(store.journal().entries().unwrap().is_empty());
        assert_eq!(platform.service_start_type("WinDefend").unwrap(), 2);
        assert!(restore.calls.borrow().is_empty());
    }

    #[test]
    fn restore_failure_aborts_unless_proceeding_was_chosen() {
        let (store, platform, _) = setup();
        platform
            .services
            .borrow_mut()
            .insert("ExampleSvc".to_owned(), 2);
        let failing = FakeRestore {
            fail: true,
            calls: RefCell::new(Vec::new()),
        };
        let engine = Engine::new(store.journal(), &platform, &failing);
        let err = engine
            .disable_service("ExampleSvc", false, NOW)
            .unwrap_err();
        assert!(
            matches!(err, EngineError::RestorePointUnavailable(_)),
            "{err}"
        );
        assert_eq!(platform.service_start_type("ExampleSvc").unwrap(), 2);
        assert!(store.journal().entries().unwrap().is_empty());

        let outcome = engine.disable_service("ExampleSvc", true, NOW).unwrap();
        let ActionOutcome::Applied { restore_note, .. } = outcome else {
            panic!("expected Applied");
        };
        assert!(restore_note.contains("proceeded anyway"), "{restore_note}");
        assert_eq!(platform.service_start_type("ExampleSvc").unwrap(), 4);
    }

    #[test]
    fn platform_failure_marks_the_entry_failed() {
        let (store, platform, restore) = setup();
        platform
            .services
            .borrow_mut()
            .insert("ExampleSvc".to_owned(), 2);
        *platform.fail_set_service.borrow_mut() = true;
        let engine = Engine::new(store.journal(), &platform, &restore);
        let err = engine
            .disable_service("ExampleSvc", false, NOW)
            .unwrap_err();
        assert!(matches!(err, EngineError::Platform(_)), "{err}");
        let entries = store.journal().entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, EntryStatus::Failed);
    }

    #[test]
    fn already_disabled_service_is_a_no_op_without_a_journal_entry() {
        let (store, platform, restore) = setup();
        platform
            .services
            .borrow_mut()
            .insert("ExampleSvc".to_owned(), 4);
        let engine = Engine::new(store.journal(), &platform, &restore);
        let outcome = engine.disable_service("ExampleSvc", false, NOW).unwrap();
        assert!(matches!(
            outcome,
            ActionOutcome::AlreadyInDesiredState { .. }
        ));
        assert!(store.journal().entries().unwrap().is_empty());
        assert!(restore.calls.borrow().is_empty());
    }

    #[test]
    fn startup_disable_then_enable_restores_absence() {
        let (store, platform, restore) = setup();
        let engine = Engine::new(store.journal(), &platform, &restore);
        let outcome = engine
            .disable_startup("Tool", StartupSource::RunHkcu, false, NOW)
            .unwrap();
        assert!(matches!(outcome, ActionOutcome::Applied { .. }));
        let blob = platform
            .startup_approved("Tool", StartupSource::RunHkcu)
            .unwrap();
        assert_eq!(
            decode_startup_state(blob.as_deref()),
            StartupState::Disabled
        );

        let outcome = engine.enable(None).unwrap();
        let ActionOutcome::Applied { entry, .. } = outcome else {
            panic!("expected Applied");
        };
        assert_eq!(entry.status, EntryStatus::Undone);
        assert_eq!(
            platform
                .startup_approved("Tool", StartupSource::RunHkcu)
                .unwrap(),
            None
        );
    }

    #[test]
    fn startup_enable_restores_prior_bytes_verbatim() {
        let (store, platform, restore) = setup();
        platform.blobs.borrow_mut().insert(
            ("Tool".to_owned(), StartupSource::RunHkcu),
            vec![7, 7, 7], // unrecognized shape — must survive the round trip
        );
        let engine = Engine::new(store.journal(), &platform, &restore);
        engine
            .disable_startup("Tool", StartupSource::RunHkcu, false, NOW)
            .unwrap();
        engine.enable(None).unwrap();
        assert_eq!(
            platform
                .startup_approved("Tool", StartupSource::RunHkcu)
                .unwrap(),
            Some(vec![7, 7, 7])
        );
    }

    #[test]
    fn run_once_disable_is_refused_at_the_engine() {
        let (store, platform, restore) = setup();
        let engine = Engine::new(store.journal(), &platform, &restore);
        let err = engine
            .disable_startup("Setup", StartupSource::RunOnceHklm, false, NOW)
            .unwrap_err();
        assert!(matches!(err, EngineError::Refused(_)), "{err}");
        assert!(store.journal().entries().unwrap().is_empty());
    }

    #[test]
    fn enable_is_idempotent_and_second_undo_reports_nothing_to_do() {
        let (store, platform, restore) = setup();
        platform
            .services
            .borrow_mut()
            .insert("ExampleSvc".to_owned(), 2);
        let engine = Engine::new(store.journal(), &platform, &restore);
        engine.disable_service("ExampleSvc", false, NOW).unwrap();
        // Simulate the state having been restored by hand already.
        platform
            .services
            .borrow_mut()
            .insert("ExampleSvc".to_owned(), 2);
        let outcome = engine.enable(None).unwrap();
        assert!(matches!(outcome, ActionOutcome::Applied { .. }));
        let err = engine.enable(None).unwrap_err();
        assert!(matches!(err, EngineError::NothingToUndo(_)), "{err}");
    }

    #[test]
    fn enable_by_id_of_an_undone_entry_reports_nothing_to_do() {
        let (store, platform, restore) = setup();
        platform
            .services
            .borrow_mut()
            .insert("ExampleSvc".to_owned(), 2);
        let engine = Engine::new(store.journal(), &platform, &restore);
        let outcome = engine.disable_service("ExampleSvc", false, NOW).unwrap();
        let ActionOutcome::Applied { entry, .. } = outcome else {
            panic!("expected Applied");
        };
        engine.enable(Some(&entry.id)).unwrap();
        let err = engine.enable(Some(&entry.id)).unwrap_err();
        assert!(matches!(err, EngineError::NothingToUndo(_)), "{err}");
    }

    #[test]
    fn service_enable_restores_the_prior_start_type() {
        let (store, platform, restore) = setup();
        platform
            .services
            .borrow_mut()
            .insert("ExampleSvc".to_owned(), 3);
        // Manual services are not disable candidates in the rules,
        // but the engine's contract is generic; disable via a direct
        // call to prove undo restores 3, not a hardcoded 2.
        let engine = Engine::new(store.journal(), &platform, &restore);
        engine.disable_service("ExampleSvc", false, NOW).unwrap();
        assert_eq!(platform.service_start_type("ExampleSvc").unwrap(), 4);
        engine.enable(None).unwrap();
        assert_eq!(platform.service_start_type("ExampleSvc").unwrap(), 3);
    }
}
