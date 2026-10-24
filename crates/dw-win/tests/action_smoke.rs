//! Windows-only smoke test for the disable tier: a throwaway HKCU
//! Run entry is disabled and re-enabled through the real platform
//! and the real engine, and the StartupApproved bytes are checked
//! at each step.
//!
//! What this proves (on a CI runner): the StartupApproved registry
//! layout this build writes is the one it reads back, the engine's
//! ordering works against the live registry, and undo restores the
//! exact prior state (here: no value at all).
//!
//! What it deliberately does NOT do:
//! - Mutate any service. CI runners are shared, short-lived
//!   machines where flipping a real service's start type proves
//!   little beyond the SCM call shape (which type-checks at compile
//!   time) and could race other jobs; service mutation is verified
//!   by the field test on a real PC instead.
//! - Create a real restore point (runners commonly have System
//!   Restore off). The engine runs here with a recording no-op
//!   restore provider, which still proves the step is attempted,
//!   in order, before any mutation.
//!
//! The fixture Run value is created with `reg.exe` (part of
//! Windows) rather than through dw-win: the product deliberately
//! has no Run-key write API — it never writes Run values — and the
//! test keeps that invariant intact.
#![cfg(target_os = "windows")]

use std::path::PathBuf;

use dw_core::model::StartupSource;
use dw_win::action::journal::{EntryStatus, Journal};
use dw_win::action::plan::{decode_startup_state, StartupState};
use dw_win::action::{ActionOutcome, Engine, PlatformOps, RestorePointOps};

const FIXTURE_NAME: &str = "DeadWeightActionTest";
const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

/// A restore provider that never touches System Restore but proves
/// the engine attempted the step, in order, before mutating.
#[derive(Default)]
struct RecordingRestore {
    calls: std::cell::RefCell<Vec<String>>,
}

impl RestorePointOps for RecordingRestore {
    fn create(&self, description: &str) -> Result<String, String> {
        self.calls.borrow_mut().push(description.to_owned());
        Ok("no-op restore provider (CI smoke)".to_owned())
    }
}

/// Removes the fixture's Run value and any StartupApproved value on
/// drop — even when an assertion panics — so a failed run never
/// leaves test state behind on the machine.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new("reg")
            .args([
                "delete",
                &format!("HKCU\\{RUN_KEY}"),
                "/v",
                FIXTURE_NAME,
                "/f",
            ])
            .output();
        let platform = dw_win::WindowsPlatform;
        let _ = platform.set_startup_approved(FIXTURE_NAME, StartupSource::RunHkcu, None);
    }
}

fn unique_journal_dir() -> PathBuf {
    std::env::temp_dir().join(format!("deadweight-action-smoke-{}", std::process::id()))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[test]
fn startup_disable_enable_round_trip() {
    // Install the fixture Run value the way an installer would —
    // with reg.exe, since dw-win has no Run-write API by design.
    let add = std::process::Command::new("reg")
        .args([
            "add",
            &format!("HKCU\\{RUN_KEY}"),
            "/v",
            FIXTURE_NAME,
            "/t",
            "REG_SZ",
            "/d",
            "C:\\Windows\\System32\\cmd.exe /c rem deadweight-smoke",
            "/f",
        ])
        .output()
        .expect("run reg add");
    assert!(add.status.success(), "reg add failed: {add:?}");
    let _cleanup = Cleanup;

    // The fixture resolves through the same lookup the CLI uses.
    let sources = dw_win::find_startup_sources(FIXTURE_NAME);
    assert_eq!(sources, vec![StartupSource::RunHkcu]);

    let journal_dir = unique_journal_dir();
    let _ = std::fs::remove_dir_all(&journal_dir);
    let journal = Journal::new(journal_dir.clone());
    let platform = dw_win::WindowsPlatform;
    let restore = RecordingRestore::default();
    let engine = Engine::new(&journal, &platform, &restore);

    // Disable: the restore step ran first, the blob now decodes as
    // disabled, and the journal recorded the action as Applied.
    let outcome = engine
        .disable_startup(FIXTURE_NAME, StartupSource::RunHkcu, false, now_unix())
        .expect("disable should succeed");
    let ActionOutcome::Applied { entry, .. } = outcome else {
        panic!("expected Applied, got {outcome:?}");
    };
    assert_eq!(entry.status, EntryStatus::Applied);
    assert_eq!(restore.calls.borrow().len(), 1);
    let blob = platform
        .startup_approved(FIXTURE_NAME, StartupSource::RunHkcu)
        .expect("read StartupApproved")
        .expect("a StartupApproved value should exist after disable");
    assert_eq!(decode_startup_state(Some(&blob)), StartupState::Disabled);

    // Enable: the value is removed entirely, restoring the exact
    // prior state (no value), and the entry is marked Undone.
    let outcome = engine
        .enable(Some(&entry.id))
        .expect("enable should succeed");
    let ActionOutcome::Applied { entry, .. } = outcome else {
        panic!("expected Applied, got {outcome:?}");
    };
    assert_eq!(entry.status, EntryStatus::Undone);
    let after = platform
        .startup_approved(FIXTURE_NAME, StartupSource::RunHkcu)
        .expect("read StartupApproved");
    assert_eq!(after, None, "undo must restore the value's absence");

    let _ = std::fs::remove_dir_all(&journal_dir);
}
