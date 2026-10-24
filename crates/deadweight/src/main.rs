#![forbid(unsafe_code)]

//! DeadWeight CLI (slice 1 — read-only).
//!
//! - `deadweight audit [--out <path>]` — collect an audit of this PC
//!   (Windows only), save it under `%LOCALAPPDATA%\DeadWeight\audits`,
//!   and print the report.
//! - `deadweight report <audit.json>` — print the report for a saved
//!   audit (any platform).
//! - `deadweight purge` — delete the local audit store in one action
//!   and say what was removed (any platform).
//!
//! There is deliberately no command here that changes anything on
//! the PC. v1 only looks.

use std::process::ExitCode;

use dw_core::model::AuditSnapshot;
use dw_core::report::render_report;

const USAGE: &str = "usage:\n  deadweight audit [--out <path>]\n  deadweight report <audit.json>\n  deadweight purge";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match command.as_str() {
        "audit" => run_audit(rest),
        "report" => run_report(rest),
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
