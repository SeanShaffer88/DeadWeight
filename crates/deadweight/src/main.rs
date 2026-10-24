#![forbid(unsafe_code)]

//! DeadWeight CLI.
//!
//! - `deadweight audit [--out <path>]` — collect an audit of this PC
//!   (Windows only), save it under `%LOCALAPPDATA%\DeadWeight\audits`,
//!   and print the report.
//! - `deadweight report <audit.json>` — print the report for a saved
//!   audit (any platform).
//! - `deadweight disable service <name> [--no-restore-point] [--yes]`
//!   and `deadweight disable startup <name> [--source <token>]
//!   [--no-restore-point] [--yes]` — disable a service (start type
//!   only) or a startup item (StartupApproved only), Windows only.
//!   Dry-run by default: without `--yes` the plan and current state
//!   are printed and nothing is changed or written.
//! - `deadweight enable [--id <journal-id>]` — undo a disable
//!   (Windows only; default: the newest undoable journal entry).
//! - `deadweight journal` — list journal entries (any platform).
//! - `deadweight disabled` — the watch list: what is still disabled,
//!   since when, and whether its 30-day watch is due (any platform).
//! - `deadweight export <dir>` — copy the journal and latest audit
//!   into a folder with a manifest (any platform).
//! - `deadweight purge` — delete the local audit store in one action
//!   and say what was removed (any platform).
//!
//! Apps, optional features, and capabilities are never changed by
//! any command. There is no uninstall, no deletion of system items,
//! and no automatic action anywhere.

use std::process::ExitCode;

use dw_core::model::AuditSnapshot;
use dw_core::report::render_report;

const USAGE: &str = "usage:\n  deadweight audit [--out <path>]\n  deadweight report <audit.json>\n  deadweight disable service <name> [--no-restore-point] [--yes]\n  deadweight disable startup <name> [--source <token>] [--no-restore-point] [--yes]\n  deadweight enable [--id <journal-id>]\n  deadweight journal\n  deadweight disabled\n  deadweight export <dir>\n  deadweight purge";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match command.as_str() {
        "audit" => run_audit(rest),
        "report" => run_report(rest),
        "disable" => run_disable(rest),
        "enable" => run_enable(rest),
        "journal" => run_journal(rest),
        "disabled" => run_disabled(rest),
        "export" => run_export(rest),
        "purge" => run_purge(rest),
        other => Err(format!("unknown command: {other}\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

/// Current Unix time in seconds (0 if the clock is before 1970,
/// which would be the least of that machine's problems).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn run_audit(args: &[String]) -> Result<(), String> {
    let mut out: Option<std::path::PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--out" => {
                let path = args
                    .get(index + 1)
                    .ok_or_else(|| "--out needs a path argument".to_owned())?;
                out = Some(std::path::PathBuf::from(path));
                index += 2;
            }
            other => return Err(format!("unknown audit argument: {other}\n{USAGE}")),
        }
    }

    let outcome = dw_win::collect().map_err(|err| err.to_string())?;
    for warning in &outcome.warnings {
        eprintln!("warning: {warning}");
    }
    let path = out.unwrap_or_else(|| {
        dw_win::store::default_audits_dir()
            .join(dw_win::store::audit_filename(&outcome.snapshot.captured_at))
    });
    dw_win::store::write_audit_atomic(&path, &outcome.snapshot)
        .map_err(|err| format!("could not save audit to {}: {err}", path.display()))?;
    println!("Audit saved to {}\n", path.display());
    println!("{}", render_report(&outcome.snapshot));
    Ok(())
}

fn run_report(args: &[String]) -> Result<(), String> {
    let Some(path) = args.first() else {
        return Err(format!("report needs the path of a saved audit\n{USAGE}"));
    };
    let text =
        std::fs::read_to_string(path).map_err(|err| format!("could not read {path}: {err}"))?;
    let snapshot = AuditSnapshot::from_json(&text)
        .map_err(|err| format!("{path} is not a valid audit: {err}"))?;
    println!("{}", render_report(&snapshot));
    Ok(())
}

fn run_purge(args: &[String]) -> Result<(), String> {
    if let Some(other) = args.first() {
        return Err(format!("unknown purge argument: {other}\n{USAGE}"));
    }
    let outcome = dw_win::store::purge_audits()
        .map_err(|err| format!("could not purge the audit store: {err}"))?;
    if outcome.files_removed == 0 {
        println!(
            "Nothing to purge: no audits stored at {}.",
            outcome.dir.display()
        );
    } else {
        println!(
            "Purged {} audit file(s), {} bytes, from {}. No audit data remains.",
            outcome.files_removed,
            outcome.bytes_removed,
            outcome.dir.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Disable / enable (Windows only)
// ---------------------------------------------------------------------

/// Parsed `disable` arguments, shared by the dry run and the real
/// run (and validated identically on every platform).
struct DisableArgs {
    kind: DisableKind,
    name: String,
    source_token: Option<String>,
    no_restore_point: bool,
    yes: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DisableKind {
    Service,
    Startup,
}

fn parse_disable(args: &[String]) -> Result<DisableArgs, String> {
    let (kind_word, rest) = args
        .split_first()
        .ok_or_else(|| format!("disable needs `service` or `startup`\n{USAGE}"))?;
    let kind = match kind_word.as_str() {
        "service" => DisableKind::Service,
        "startup" => DisableKind::Startup,
        other => {
            return Err(format!(
                "disable works on `service` or `startup`, not {other:?}\n{USAGE}"
            ))
        }
    };
    let (name, rest) = rest
        .split_first()
        .ok_or_else(|| "disable needs the name of the item to disable".to_owned())?;
    let mut parsed = DisableArgs {
        kind,
        name: name.clone(),
        source_token: None,
        no_restore_point: false,
        yes: false,
    };
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--yes" => {
                parsed.yes = true;
                index += 1;
            }
            "--no-restore-point" => {
                parsed.no_restore_point = true;
                index += 1;
            }
            "--source" => {
                if kind != DisableKind::Startup {
                    return Err("--source only applies to startup items".to_owned());
                }
                let token = rest
                    .get(index + 1)
                    .ok_or_else(|| "--source needs a token argument".to_owned())?;
                parsed.source_token = Some(token.clone());
                index += 2;
            }
            other => return Err(format!("unknown disable argument: {other}\n{USAGE}")),
        }
    }
    Ok(parsed)
}

fn run_disable(args: &[String]) -> Result<(), String> {
    let parsed = parse_disable(args)?;
    #[cfg(target_os = "windows")]
    {
        win::disable(&parsed)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // The arguments were fully parsed and validated above; on
        // this platform there is nothing further to do with them.
        let _ = (
            &parsed.kind,
            &parsed.name,
            &parsed.source_token,
            parsed.no_restore_point,
            parsed.yes,
        );
        Err(
            "the disable commands only run on Windows (they change service and \
             startup configuration); this platform can read audits and journals only"
                .to_owned(),
        )
    }
}

fn run_enable(args: &[String]) -> Result<(), String> {
    let mut id: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--id" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--id needs a journal entry id".to_owned())?;
                id = Some(value.clone());
                index += 2;
            }
            other => return Err(format!("unknown enable argument: {other}\n{USAGE}")),
        }
    }
    #[cfg(target_os = "windows")]
    {
        win::enable(id.as_deref())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = &id;
        Err(
            "the enable command only runs on Windows (it restores service and \
             startup configuration); this platform can read audits and journals only"
                .to_owned(),
        )
    }
}

/// The Windows implementations of disable/enable. The engine does
/// the safety-critical ordering; this module resolves names, prints
/// plans, and reports outcomes.
#[cfg(target_os = "windows")]
mod win {
    use dw_core::model::StartupSource;
    use dw_core::service_parse::start_type_label;
    use dw_win::action::journal::PriorState;
    use dw_win::action::plan::{decode_startup_state, plan_disable_service, plan_disable_startup};
    use dw_win::action::{ActionOutcome, Engine, Journal, PlatformOps};

    use super::{now_unix, DisableArgs, DisableKind};

    fn engine_parts() -> (
        Journal,
        dw_win::WindowsPlatform,
        dw_win::SystemRestorePoints,
    ) {
        (
            Journal::new(dw_win::store::default_journal_dir()),
            dw_win::WindowsPlatform,
            dw_win::SystemRestorePoints,
        )
    }

    /// Resolve a startup item's source: the explicit `--source`
    /// token when given, otherwise the single source the name is
    /// found in. Ambiguity is an error that lists the candidates
    /// and their tokens.
    fn resolve_source(name: &str, token: Option<&str>) -> Result<StartupSource, String> {
        if let Some(token) = token {
            return StartupSource::from_token(token).ok_or_else(|| {
                let known = StartupSource::ALL
                    .iter()
                    .map(|s| s.token())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("unknown --source token {token:?} (known tokens: {known})")
            });
        }
        let found = dw_win::find_startup_sources(name);
        match found.len() {
            0 => Err(format!(
                "no startup item named \"{name}\" was found in any Run key, \
                 RunOnce key, or Startup folder — check the name (the audit \
                 report lists startup items exactly as Windows names them)"
            )),
            1 => Ok(found[0]),
            _ => {
                let list = found
                    .iter()
                    .map(|s| format!("{} (--source {})", s.describe(), s.token()))
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(format!(
                    "\"{name}\" appears in more than one place: {list}. \
                     Re-run with --source to say which one you mean"
                ))
            }
        }
    }

    pub(super) fn disable(parsed: &DisableArgs) -> Result<(), String> {
        let (journal, platform, restore) = engine_parts();
        let engine = Engine::new(&journal, &platform, &restore);
        match parsed.kind {
            DisableKind::Service => disable_service(parsed, &engine, &platform),
            DisableKind::Startup => disable_startup(parsed, &engine, &platform),
        }
    }

    fn disable_service(
        parsed: &DisableArgs,
        engine: &Engine<'_, dw_win::WindowsPlatform, dw_win::SystemRestorePoints>,
        platform: &dw_win::WindowsPlatform,
    ) -> Result<(), String> {
        // The plan check runs in the dry run too: a refusal is the
        // most useful thing a dry run can report.
        plan_disable_service(&parsed.name).map_err(|r| r.to_string())?;
        let current = platform
            .service_start_type(&parsed.name)
            .map_err(|e| e.to_string())?;
        if !parsed.yes {
            println!("Plan (dry run — nothing will be changed or written):");
            println!("  Service: {}", parsed.name);
            println!("  Current start type: {}", start_type_label(current, false));
            println!(
                "  Change: start type -> Disabled. A running service keeps \
                 running; it simply will not start next time."
            );
            if parsed.no_restore_point {
                println!(
                    "  No restore point will be created (--no-restore-point); \
                     the action is still journaled and undoable."
                );
            } else {
                println!("  First, a system restore point will be attempted.");
            }
            println!(
                "  The action is journaled before it happens; undo with: \
                 deadweight enable"
            );
            println!("\nRe-run with --yes to apply this plan.");
            return Ok(());
        }
        match engine.disable_service(&parsed.name, parsed.no_restore_point, now_unix()) {
            Ok(ActionOutcome::Applied {
                entry,
                restore_note,
            }) => {
                println!("Disabled service \"{}\".", parsed.name);
                println!("Restore point: {restore_note}");
                println!(
                    "Journal entry: {} (undo with: deadweight enable --id {})",
                    entry.id, entry.id
                );
                println!(
                    "Watch: if nothing you use misbehaves by {}, the disable \
                     has proved itself; deadweight disabled will remind you.",
                    entry.watch_due_date()
                );
            }
            Ok(ActionOutcome::AlreadyInDesiredState { description }) => {
                println!("{description}");
            }
            Err(err) => return Err(err.to_string()),
        }
        Ok(())
    }

    fn disable_startup(
        parsed: &DisableArgs,
        engine: &Engine<'_, dw_win::WindowsPlatform, dw_win::SystemRestorePoints>,
        platform: &dw_win::WindowsPlatform,
    ) -> Result<(), String> {
        let source = resolve_source(&parsed.name, parsed.source_token.as_deref())?;
        plan_disable_startup(&parsed.name, source).map_err(|r| r.to_string())?;
        let current_blob = platform
            .startup_approved(&parsed.name, source)
            .map_err(|e| e.to_string())?;
        if !parsed.yes {
            println!("Plan (dry run — nothing will be changed or written):");
            println!("  Startup item: {}", parsed.name);
            println!("  Source: {}", source.describe());
            println!(
                "  Current state: {}",
                decode_startup_state(current_blob.as_deref())
            );
            println!(
                "  Change: mark the item disabled (its StartupApproved state, \
                 the same mechanism Task Manager uses). The Run entry or \
                 shortcut itself is not touched."
            );
            if parsed.no_restore_point {
                println!(
                    "  No restore point will be created (--no-restore-point); \
                     the action is still journaled and undoable."
                );
            } else {
                println!("  First, a system restore point will be attempted.");
            }
            println!(
                "  The action is journaled before it happens; undo with: \
                 deadweight enable"
            );
            println!("\nRe-run with --yes to apply this plan.");
            return Ok(());
        }
        match engine.disable_startup(&parsed.name, source, parsed.no_restore_point, now_unix()) {
            Ok(ActionOutcome::Applied {
                entry,
                restore_note,
            }) => {
                println!("Disabled startup item \"{}\".", parsed.name);
                println!("Restore point: {restore_note}");
                println!(
                    "Journal entry: {} (undo with: deadweight enable --id {})",
                    entry.id, entry.id
                );
                println!(
                    "Watch: if nothing you use is missing by {}, the disable \
                     has proved itself; deadweight disabled will remind you.",
                    entry.watch_due_date()
                );
            }
            Ok(ActionOutcome::AlreadyInDesiredState { description }) => {
                println!("{description}");
            }
            Err(err) => return Err(err.to_string()),
        }
        Ok(())
    }

    pub(super) fn enable(id: Option<&str>) -> Result<(), String> {
        let (journal, platform, restore) = engine_parts();
        let engine = Engine::new(&journal, &platform, &restore);
        match engine.enable(id) {
            Ok(ActionOutcome::Applied { entry, .. }) => {
                match (&entry.prior_state, entry.source) {
                    (PriorState::ServiceStartType { start_type }, _) => {
                        println!(
                            "Re-enabled service \"{}\": start type restored to {}.",
                            entry.name,
                            start_type_label(*start_type, false)
                        );
                    }
                    (_, Some(source)) => {
                        println!(
                            "Re-enabled startup item \"{}\" ({}): its recorded \
                             state was restored.",
                            entry.name,
                            source.describe()
                        );
                    }
                    _ => {
                        println!("Re-enabled \"{}\".", entry.name);
                    }
                }
                println!("Journal entry {} marked undone.", entry.id);
                Ok(())
            }
            Ok(ActionOutcome::AlreadyInDesiredState { description }) => {
                println!("{description}");
                Ok(())
            }
            Err(err) => Err(err.to_string()),
        }
    }
}

// ---------------------------------------------------------------------
// Journal / watch list / export (any platform: they read local data)
// ---------------------------------------------------------------------

/// Plain-language journal status for CLI output.
fn status_label(status: dw_win::action::EntryStatus) -> &'static str {
    use dw_win::action::EntryStatus;
    match status {
        EntryStatus::Planned => "planned",
        EntryStatus::Applied => "applied (still disabled)",
        EntryStatus::Failed => "failed",
        EntryStatus::Undone => "undone",
    }
}

fn run_journal(args: &[String]) -> Result<(), String> {
    if let Some(other) = args.first() {
        return Err(format!("unknown journal argument: {other}\n{USAGE}"));
    }
    let journal = dw_win::action::Journal::new(dw_win::store::default_journal_dir());
    let entries = journal.entries().map_err(|e| e.to_string())?;
    if entries.is_empty() {
        println!(
            "The journal is empty: no disable actions have been recorded.\n\
             Journal folder: {}",
            journal.dir().display()
        );
        return Ok(());
    }
    println!(
        "DeadWeight journal — {} entr{} (newest first):",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );
    for entry in &entries {
        let source = entry
            .source
            .map(|s| format!(", {}", s.describe()))
            .unwrap_or_default();
        let watch = match entry.status {
            dw_win::action::EntryStatus::Applied => {
                format!(", watch until {}", entry.watch_due_date())
            }
            _ => String::new(),
        };
        println!(
            "  {}  {}  {} \"{}\"{} — {}{}",
            entry.id,
            entry.created_at,
            entry.kind.label(),
            entry.name,
            source,
            status_label(entry.status),
            watch
        );
    }
    Ok(())
}

fn run_disabled(args: &[String]) -> Result<(), String> {
    if let Some(other) = args.first() {
        return Err(format!("unknown disabled argument: {other}\n{USAGE}"));
    }
    let journal = dw_win::action::Journal::new(dw_win::store::default_journal_dir());
    let entries = journal.entries().map_err(|e| e.to_string())?;
    let active: Vec<_> = entries
        .iter()
        .filter(|e| e.status == dw_win::action::EntryStatus::Applied)
        .collect();
    if active.is_empty() {
        println!("Nothing is currently disabled by DeadWeight.");
        return Ok(());
    }
    let now = now_unix();
    println!(
        "Currently disabled by DeadWeight ({} item{}). DeadWeight never \
         re-enables anything on its own — the watch is a reminder, not a timer:",
        active.len(),
        if active.len() == 1 { "" } else { "s" }
    );
    for entry in active {
        let days = (now - entry.created_unix).div_euclid(86_400);
        let due = if now >= entry.watch_due_unix {
            format!(
                "WATCH DUE ({} day(s) past the 30-day watch) — if everything \
                 you use still works, this disable has proved itself; leave it \
                 disabled, or undo with: deadweight enable --id {}",
                (now - entry.watch_due_unix).div_euclid(86_400),
                entry.id
            )
        } else {
            format!(
                "watch due {} ({} day(s) left)",
                entry.watch_due_date(),
                entry.watch_days_remaining(now)
            )
        };
        println!(
            "  {} \"{}\" — disabled {} ({} day(s) ago); {}",
            entry.kind.label(),
            entry.name,
            entry.created_at,
            days,
            due
        );
    }
    Ok(())
}

fn run_export(args: &[String]) -> Result<(), String> {
    let Some(dir) = args.first() else {
        return Err(format!("export needs a destination folder\n{USAGE}"));
    };
    if let Some(other) = args.get(1) {
        return Err(format!("unknown export argument: {other}\n{USAGE}"));
    }
    let summary = dw_win::action::export::export_to(
        std::path::Path::new(dir),
        &dw_win::store::default_journal_dir(),
        &dw_win::store::default_audits_dir(),
        now_unix(),
    )
    .map_err(|e| e.to_string())?;
    println!(
        "Exported {} journal entr{} and {} to {}",
        summary.journal_entries,
        if summary.journal_entries == 1 {
            "y"
        } else {
            "ies"
        },
        if summary.audit_included {
            "the latest audit"
        } else {
            "no audit (none stored)"
        },
        summary.dir.display()
    );
    Ok(())
}
