//! The audit report: plain-language, tiered, and evidence-first.
//!
//! Every item line carries its evidence (size as reported, last use,
//! which sources saw it, what executable matched) and the tier's
//! reason. The report is conservative by design: it warns prominently
//! when the evidence window is shorter than a year, because seasonal
//! software is the known false positive, and it repeats in the footer
//! that absence of evidence is not proof of non-use.

use crate::model::{AuditItem, AuditSnapshot, EvidenceStrength, Kind};
use crate::rules::{tier, Tier, RULES_VERSION};
use crate::service_parse::start_type_label;
use crate::time::{format_unix_date, parse_iso_utc};

/// Windows at or above this many days of evidence no longer trigger
/// the seasonal warning: a full year covers annual software.
pub const SEASONAL_WINDOW_DAYS: u32 = 365;

/// Format a byte count for humans (`512 B`, `1.5 KB`, `230 MB`,
/// `2.3 GB`), decimal units, one decimal place at most.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1_000.0;
    let value = bytes as f64;
    if bytes < 1_000 {
        format!("{bytes} B")
    } else if value < KB * 1_000.0 {
        format!("{:.1} KB", value / KB)
    } else if value < KB * 1_000_000.0 {
        format!("{:.1} MB", value / (KB * 1_000.0))
    } else {
        format!("{:.1} GB", value / (KB * 1_000_000.0))
    }
}

/// Render the full report for an audit snapshot as plain text with
/// light Markdown headings (readable in a terminal and in a rendered
/// preview alike).
#[must_use]
pub fn render_report(snapshot: &AuditSnapshot) -> String {
    let now_unix = parse_iso_utc(&snapshot.captured_at).unwrap_or(0);
    let window = snapshot.evidence_window_days;

    let mut decided: Vec<(&AuditItem, Tier, String)> = snapshot
        .items
        .iter()
        .map(|item| {
            let (tier, reason) = tier(item, &snapshot.items, window, now_unix);
            (item, tier, reason)
        })
        .collect();
    // Deterministic output: tier sections in tier order, items by
    // name (case-insensitive) inside each section.
    decided.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then_with(|| a.0.name.to_lowercase().cmp(&b.0.name.to_lowercase()))
    });

    let count = |t: Tier| decided.iter().filter(|d| d.1 == t).count();
    let kind_count = |k: Kind| snapshot.items.iter().filter(|i| i.kind == k).count();
    let apps = kind_count(Kind::App);
    let services = kind_count(Kind::Service);
    let startup_items = kind_count(Kind::StartupItem);
    let features = kind_count(Kind::OptionalFeature) + kind_count(Kind::Capability);

    let mut out = String::new();
    out.push_str(&format!(
        "# DeadWeight audit — {}\n\n",
        snapshot.captured_at
    ));
    out.push_str(&format!(
        "Rules version: {RULES_VERSION}. Items audited: {} ({apps} apps, {services} services, \
         {startup_items} startup items, {features} optional features and capabilities).\n\n",
        snapshot.items.len()
    ));

    // --- Evidence window + seasonal warning -------------------------
    if window == 0 {
        out.push_str(
            "Evidence window: no dated usage evidence could be read on this PC. \
             Every \"no usage evidence\" line below means only that — nothing was \
             *recorded* — and the tiering rules have held back every app \
             recommendation because of it.\n\n",
        );
    } else {
        out.push_str(&format!(
            "Evidence window: {window} days (the furthest back any usage evidence \
             on this PC reaches).\n\n"
        ));
    }
    if window < SEASONAL_WINDOW_DAYS {
        out.push_str(&format!(
            "**Warning — short evidence window.** The usage evidence on this PC \
             spans {window} days, less than a full year. Software that is only \
             used seasonally — tax, holiday, annual tools — can look completely \
             unused in a window this short. Treat every recommendation below \
             as a prompt to think, not a verdict.\n\n"
        ));
    }
    out.push_str(
        "Absence of evidence is not proof an item is never used. Windows \
         records usage in Prefetch, UserAssist, and BAM, and all three can \
         be cleared, capped, or never recorded in the first place. \
         DeadWeight shows what the evidence says and where it came from; \
         it does not know what it cannot see.\n\n",
    );

    // --- Summary ------------------------------------------------------
    let safe_items: Vec<&(&AuditItem, Tier, String)> = decided
        .iter()
        .filter(|d| d.1 == Tier::SafeToRemove)
        .collect();
    let known_size_total: u64 = safe_items.iter().filter_map(|d| d.0.size_bytes).sum();
    let unknown_size_count = safe_items
        .iter()
        .filter(|d| d.0.size_bytes.is_none())
        .count();
    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- Safe to remove (recommendations): {} items, estimated reclaimable \
         ~{}",
        safe_items.len(),
        format_bytes(known_size_total)
    ));
    out.push_str(" (from sizes Windows reports — an estimate, not a measurement");
    if unknown_size_count > 0 {
        out.push_str(&format!(
            "; plus {unknown_size_count} item(s) whose size Windows does not report"
        ));
    }
    out.push_str(")\n");
    out.push_str(&format!(
        "- Disable and watch: {} items\n",
        count(Tier::DisableAndWatch)
    ));
    out.push_str(&format!(
        "- Never touch (considered and excluded): {} items\n",
        count(Tier::NeverTouch)
    ));
    out.push_str(&format!(
        "- No recommendation: {} items\n\n",
        count(Tier::NoRecommendation)
    ));
    out.push_str(
        "This audit inventoried apps, optional features and capabilities, \
         services, and startup items. The \"disable and watch\" section lists \
         services and startup items the rules consider disable candidates. \
         This report itself changes nothing: disabling happens only through \
         the separate `deadweight disable` command, which attempts a system \
         restore point first, records the action in a journal before it \
         happens, and can be undone with `deadweight enable`. Optional \
         features, capabilities, and apps are never changed by DeadWeight — \
         for them the report is the whole product.\n\n",
    );

    // --- Per-tier sections ---------------------------------------------
    for tier_value in [
        Tier::SafeToRemove,
        Tier::DisableAndWatch,
        Tier::NeverTouch,
        Tier::NoRecommendation,
    ] {
        out.push_str(&format!("## {}\n\n", tier_value.label()));
        let rows: Vec<&(&AuditItem, Tier, String)> =
            decided.iter().filter(|d| d.1 == tier_value).collect();
        if rows.is_empty() {
            out.push_str("None.\n\n");
            continue;
        }
        for (item, _, reason) in rows {
            out.push_str(&format!("- {}", item_line(item)));
            out.push_str(&format!(". Reason: {reason}\n"));
        }
        out.push('\n');
    }

    // --- Footer ---------------------------------------------------------
    out.push_str("---\n\n");
    out.push_str(
        "Privacy: usage evidence (Prefetch, UserAssist, BAM) is forensic \
         data about how this PC is used. DeadWeight read it on this \
         machine only; it never leaves the machine, and no part of this \
         report is sent anywhere. Stored audits live under \
         %LOCALAPPDATA%\\DeadWeight and can be deleted at any time with \
         `deadweight purge`.\n\n",
    );
    out.push_str(
        "This report is information only: reading it changes nothing on \
         your PC.\n",
    );
    out
}

/// One item's evidence-carrying report line (without the reason,
/// which the caller appends).
fn item_line(item: &AuditItem) -> String {
    let mut parts = vec![format!("**{}** ({})", item.name, item.kind.label())];
    match item.kind {
        Kind::Service => {
            match item.start_type {
                Some(start_type) => parts.push(format!(
                    "start type {}",
                    start_type_label(start_type, item.delayed_start)
                )),
                None => parts.push("start type not reported".to_owned()),
            }
            parts.push(format!("state {}", item.state));
            match &item.binary_path {
                Some(path) => parts.push(format!("program {path}")),
                None => parts.push("program path not reported".to_owned()),
            }
            if let Some(parent) = &item.parent_app {
                parts.push(format!("belongs to \"{parent}\""));
            }
        }
        Kind::StartupItem => {
            match &item.target {
                Some(target) => parts.push(format!("runs {target}")),
                None => parts.push("target not reported".to_owned()),
            }
            if let Some(source) = &item.startup_source {
                parts.push(format!("from {}", source.describe()));
            }
            if let Some(parent) = &item.parent_app {
                parts.push(format!("belongs to \"{parent}\""));
            }
        }
        _ => {
            match item.size_bytes {
                Some(size) => parts.push(format!("size {}", format_bytes(size))),
                None => parts.push("size not reported".to_owned()),
            }
            if let Some(date) = &item.install_date {
                parts.push(format!("installed {date}"));
            }
        }
    }
    let evidence = &item.evidence;
    match evidence.strength() {
        EvidenceStrength::None => parts.push("no usage evidence found".to_owned()),
        _ => {
            let mut text = match evidence.last_used_unix {
                Some(last) => format!("last used {}", format_unix_date(last)),
                None => "usage recorded (no date)".to_owned(),
            };
            if let Some(count) = evidence.run_count {
                text.push_str(&format!(", {count} run(s) recorded"));
            }
            let sources: Vec<&str> = evidence.sources.iter().map(|s| s.label()).collect();
            text.push_str(&format!("; seen by {}", sources.join(", ")));
            if let Some(exe) = &evidence.matched_exe {
                text.push_str(&format!(" (matched executable: {exe})"));
            }
            parts.push(text);
        }
    }
    parts.join(" — ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuditItem, Evidence, EvidenceSource, Kind};

    fn snapshot(window: u32, items: Vec<AuditItem>) -> AuditSnapshot {
        AuditSnapshot {
            schema_version: crate::model::SCHEMA_VERSION,
            captured_at: "2026-10-24T20:56:00Z".to_owned(),
            evidence_window_days: window,
            windows_dir: Some("C:\\Windows".to_owned()),
            items,
        }
    }

    fn old_unused_app() -> AuditItem {
        let mut item = AuditItem::new("Old Utility", Kind::App, "installed");
        item.install_date = Some("2023-01-01".to_owned());
        item.size_bytes = Some(250_000_000);
        item
    }

    #[test]
    fn seasonal_warning_present_under_a_year() {
        let report = render_report(&snapshot(200, vec![old_unused_app()]));
        assert!(report.contains("short evidence window"), "{report}");
        assert!(report.contains("200 days"), "{report}");
    }

    #[test]
    fn seasonal_warning_absent_at_a_full_year() {
        let report = render_report(&snapshot(400, vec![old_unused_app()]));
        assert!(!report.contains("short evidence window"), "{report}");
    }

    #[test]
    fn reclaimable_counts_only_safe_known_sizes() {
        let mut used_app = AuditItem::new("Used App", Kind::App, "installed");
        used_app.install_date = Some("2023-01-01".to_owned());
        used_app.size_bytes = Some(900_000_000);
        used_app.evidence = Evidence {
            last_used_unix: Some(1_792_000_000),
            run_count: Some(5),
            sources: vec![EvidenceSource::UserAssist],
            matched_exe: Some("usedapp.exe".to_owned()),
        };
        let mut defender = AuditItem::new("Windows Defender", Kind::App, "installed");
        defender.size_bytes = Some(500_000_000);
        let report = render_report(&snapshot(400, vec![old_unused_app(), used_app, defender]));
        // Only Old Utility (250 MB, Safe tier) counts toward reclaimable.
        assert!(report.contains("~250.0 MB"), "{report}");
        assert!(!report.contains("~1.7 GB"), "{report}");
    }

    #[test]
    fn footer_carries_privacy_and_information_only_lines() {
        let report = render_report(&snapshot(400, vec![old_unused_app()]));
        assert!(report.contains("never leaves the machine"), "{report}");
        assert!(
            report.contains("This report is information only"),
            "{report}"
        );
        assert!(report.contains("deadweight purge"), "{report}");
        // The summary explains the disable path honestly.
        assert!(report.contains("deadweight disable"), "{report}");
        assert!(report.contains("deadweight enable"), "{report}");
    }

    #[test]
    fn never_touch_items_are_listed_not_hidden() {
        let defender = AuditItem::new("Microsoft Defender Antivirus", Kind::App, "installed");
        let report = render_report(&snapshot(400, vec![defender]));
        let never_section = report
            .split("## Never touch")
            .nth(1)
            .expect("never-touch section");
        assert!(
            never_section.contains("Microsoft Defender Antivirus"),
            "{report}"
        );
    }

    #[test]
    fn rules_version_is_printed() {
        let report = render_report(&snapshot(400, vec![]));
        assert!(
            report.contains(&format!("Rules version: {RULES_VERSION}")),
            "{report}"
        );
    }

    #[test]
    fn disable_and_watch_section_lists_service_with_its_facts() {
        let mut service = AuditItem::new("Example Backup Service", Kind::Service, "Stopped");
        service.start_type = Some(2);
        service.binary_path = Some("C:\\Program Files\\Example\\backup.exe".to_owned());
        let mut startup = AuditItem::new("Example Reminder", Kind::StartupItem, "unknown");
        startup.target = Some("C:\\Program Files\\Example\\reminder.exe".to_owned());
        startup.startup_source = Some(crate::model::StartupSource::RunHkcu);
        let report = render_report(&snapshot(400, vec![service, startup]));
        let watch = report
            .split("## Disable and watch")
            .nth(1)
            .expect("watch section");
        assert!(watch.contains("Example Backup Service"), "{report}");
        assert!(watch.contains("start type Automatic"), "{report}");
        assert!(watch.contains("Example Reminder"), "{report}");
        assert!(watch.contains("Run registry key"), "{report}");
        assert!(report.contains("- Disable and watch: 2 items"), "{report}");
    }

    #[test]
    fn evidence_line_shows_matched_exe_and_sources() {
        let mut item = AuditItem::new("Some App", Kind::App, "installed");
        item.install_date = Some("2023-01-01".to_owned());
        item.evidence = Evidence {
            last_used_unix: Some(1_792_000_000),
            run_count: Some(2),
            sources: vec![EvidenceSource::Prefetch, EvidenceSource::Bam],
            matched_exe: Some("someapp.exe".to_owned()),
        };
        let report = render_report(&snapshot(400, vec![item]));
        assert!(
            report.contains("matched executable: someapp.exe"),
            "{report}"
        );
        assert!(report.contains("seen by Prefetch, BAM"), "{report}");
    }
}
