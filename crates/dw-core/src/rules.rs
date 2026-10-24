//! Tiering rules: which tier each audited item lands in, and why.
//!
//! This module is the product's safety core, and it is deliberately
//! conservative:
//!
//! - An item is only ever a **Safe to remove** candidate when the
//!   rules can point at concrete evidence (or a curated review-list
//!   entry) — never on suspicion.
//! - For apps, "safe" additionally requires *no* usage evidence in an
//!   evidence window of at least 90 days, and an install date older
//!   than the whole window. Seasonal software (tax, holiday, annual
//!   tools) is the defining false positive, so a short window blocks
//!   every app recommendation.
//! - The never-touch rules are checked first and always win.
//!
//! The allow/deny lists below are source data: changing them changes
//! what DeadWeight recommends, so they are versioned with
//! [`RULES_VERSION`], which is printed in every report. A list change
//! is a reviewable diff and must bump the version.

use crate::evidence_parse::normalize_for_match;
use crate::model::{AuditItem, EvidenceStrength, Kind};
use crate::time::iso_date_days;

/// Version of the tiering rules in this file. Printed in every
/// report so a reader can tell which rules produced it.
pub const RULES_VERSION: u32 = 1;

/// Minimum evidence window, in days, before any *app* may be tiered
/// Safe to remove. Below this, every app drops to No recommendation:
/// 90 days is already short next to seasonal software, and it is a
/// floor, not a target.
pub const MIN_WINDOW_DAYS_FOR_APP_SAFE: u32 = 90;

/// The tier an item is assigned by the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Recommendation: this looks safe to remove (in v1, a
    /// recommendation only — DeadWeight changes nothing).
    SafeToRemove,
    /// Candidate for the later slice's disable tier: services and
    /// helper programs that can be disabled and watched before any
    /// removal decision. Slice 1 does not inventory services, so no
    /// item lands here yet.
    DisableAndWatch,
    /// Considered and explicitly excluded: security components and
    /// other items the rules refuse to recommend against.
    NeverTouch,
    /// The honest middle: not enough evidence, not covered by the
    /// rules, or already in its minimal state.
    NoRecommendation,
}

impl Tier {
    /// Section heading used in reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Tier::SafeToRemove => "Safe to remove",
            Tier::DisableAndWatch => "Disable and watch",
            Tier::NeverTouch => "Never touch",
            Tier::NoRecommendation => "No recommendation",
        }
    }
}

/// Name patterns (matched case-insensitively on the normalized name,
/// substring) that mark an item as never-touch. These are security
/// components: DeadWeight lists them so the user can see they were
/// considered and excluded, and never recommends against them.
pub const NEVER_TOUCH_NAME_PATTERNS: &[&str] = &[
    // Microsoft's built-in antimalware, under either brand name.
    "Windows Defender",
    "Microsoft Defender",
    // The Security Health service/tray.
    "Security Health",
    // Capability identities for the Windows security stack begin with
    // this prefix (e.g. Microsoft-Windows-Security-IdentityListener).
    // Listed before the shorter "Windows Security" pattern so
    // capability matches name this rule.
    "Microsoft-Windows-Security",
    // The Windows Security UI app.
    "Windows Security",
    // The Microsoft antimalware service executable (MsMpEng) and the
    // service display name built from this word.
    "antimalware",
];

/// Publisher patterns with the same never-touch effect, for items
/// whose publisher field identifies the security stack even when the
/// product name does not match a name pattern.
pub const NEVER_TOUCH_PUBLISHER_PATTERNS: &[&str] = &["defender", "antimalware"];

/// One curated optional-feature/capability review entry: a name
/// pattern and the plain-language rationale for reviewing it. This
/// list is intentionally SMALL. A feature not on this list gets no
/// recommendation, however unused it looks — features carry no usage
/// evidence, so the list *is* the evidence.
pub struct FeatureReview {
    /// Name pattern, matched like the never-touch patterns.
    pub pattern: &'static str,
    /// Why this feature is a removal candidate, in plain language.
    pub rationale: &'static str,
}

/// The curated feature review list for rules version 1.
pub const FEATURE_REVIEW: &[FeatureReview] = &[
    FeatureReview {
        pattern: "SMB1Protocol",
        rationale: "SMB 1.0/CIFS file sharing is a legacy protocol with known \
                    security vulnerabilities; only very old network hardware still needs it.",
    },
    FeatureReview {
        pattern: "TelnetClient",
        rationale: "The Telnet client is a legacy remote-login tool that sends \
                    sign-ins in plain text; it is rarely used on modern networks.",
    },
    FeatureReview {
        pattern: "TFTP",
        rationale: "The TFTP client is a niche file-transfer tool used mainly \
                    for network-device maintenance.",
    },
    FeatureReview {
        pattern: "WorkFolders",
        rationale: "Work Folders is a workplace file-sync feature; it does \
                    nothing outside a managed work network.",
    },
    FeatureReview {
        pattern: "Printing-XPSServices",
        rationale: "XPS document services are rarely used now that PDF is the \
                    standard document format.",
    },
    FeatureReview {
        pattern: "XpsDocumentWriter",
        rationale: "The XPS document writer is rarely used now that PDF is \
                    the standard document format.",
    },
    FeatureReview {
        pattern: "XpsViewer",
        rationale: "The XPS Viewer is rarely used now that PDF is the \
                    standard document format.",
    },
    FeatureReview {
        pattern: "Internet-Explorer-Optional",
        rationale: "Internet Explorer 11 is retired; this optional component \
                    remains only for legacy compatibility.",
    },
    FeatureReview {
        pattern: "MicrosoftWindowsPowerShellV2",
        rationale: "Windows PowerShell 2.0 is deprecated and lacks modern \
                    security logging; the current PowerShell in Windows is \
                    separate and unaffected.",
    },
];

/// Whether `text` contains `pattern`, comparing both normalized
/// (lowercase, alphanumerics only) so spacing and punctuation in DISM
/// names (`TelnetClient` vs "Telnet Client") do not matter.
fn matches_pattern(text: &str, pattern: &str) -> bool {
    let text = normalize_for_match(text);
    let pattern = normalize_for_match(pattern);
    !pattern.is_empty() && text.contains(&pattern)
}

/// The never-touch pattern an item matches, if any (returned so the
/// report can name the rule that excluded it).
fn never_touch_match(item: &AuditItem) -> Option<&'static str> {
    for pattern in NEVER_TOUCH_NAME_PATTERNS {
        if matches_pattern(&item.name, pattern) {
            return Some(pattern);
        }
    }
    if let Some(publisher) = &item.publisher {
        for pattern in NEVER_TOUCH_PUBLISHER_PATTERNS {
            if matches_pattern(publisher, pattern) {
                return Some(pattern);
            }
        }
    }
    None
}

/// The feature review entry covering an item, if any.
fn feature_review_match(item: &AuditItem) -> Option<&'static FeatureReview> {
    FEATURE_REVIEW
        .iter()
        .find(|entry| matches_pattern(&item.name, entry.pattern))
}

/// Assign a tier to one item, with the plain-language reason.
///
/// `window_days` is the audit's evidence window and `now_unix` the
/// capture time; app tiering compares the install date against both.
#[must_use]
pub fn tier(item: &AuditItem, window_days: u32, now_unix: i64) -> (Tier, String) {
    // Never-touch is checked first and always wins, even over an
    // item that would otherwise look like a candidate.
    if let Some(pattern) = never_touch_match(item) {
        return (
            Tier::NeverTouch,
            format!(
                "excluded by the never-touch rules (matches \"{pattern}\"): \
                 security components are considered and left alone"
            ),
        );
    }
    match item.kind {
        Kind::App => tier_app(item, window_days, now_unix),
        Kind::OptionalFeature | Kind::Capability => tier_feature(item),
    }
}

fn tier_app(item: &AuditItem, window_days: u32, now_unix: i64) -> (Tier, String) {
    let strength = item.evidence.strength();
    if strength != EvidenceStrength::None {
        let detail = match item.evidence.last_used_unix {
            Some(last) => format!(
                "usage evidence found ({} source(s), last used {}) — an app \
                 that is still run is not a removal candidate",
                item.evidence.sources.len(),
                crate::time::format_unix_date(last),
            ),
            None => "usage evidence found — an app that is still run is not \
                     a removal candidate"
                .to_owned(),
        };
        return (Tier::NoRecommendation, detail);
    }
    if window_days < MIN_WINDOW_DAYS_FOR_APP_SAFE {
        return (
            Tier::NoRecommendation,
            format!(
                "the usage evidence on this PC only spans {window_days} days \
                 (under {MIN_WINDOW_DAYS_FOR_APP_SAFE}), which is too short to \
                 call any app unused — seasonal apps would look identical"
            ),
        );
    }
    let Some(install_date) = &item.install_date else {
        return (
            Tier::NoRecommendation,
            "no install date is recorded for this app, so there is no way \
             to tell how long it has been installed"
                .to_owned(),
        );
    };
    let Some(install_days) = iso_date_days(install_date) else {
        return (
            Tier::NoRecommendation,
            format!("the recorded install date (\"{install_date}\") could not be read"),
        );
    };
    let age_days = now_unix.div_euclid(86_400) - install_days;
    if age_days <= i64::from(window_days) {
        return (
            Tier::NoRecommendation,
            format!(
                "installed {age_days} days ago, inside the {window_days}-day \
                 evidence window — it may simply be new"
            ),
        );
    }
    (
        Tier::SafeToRemove,
        format!(
            "no usage evidence in a {window_days}-day window, and installed \
             {age_days} days ago — longer than the whole window"
        ),
    )
}

fn tier_feature(item: &AuditItem) -> (Tier, String) {
    // Only an item that is actually present can be a candidate:
    // features must be Enabled, capabilities Installed.
    let present = match item.kind {
        Kind::OptionalFeature => item.state.eq_ignore_ascii_case("Enabled"),
        Kind::Capability => item.state.eq_ignore_ascii_case("Installed"),
        Kind::App => unreachable!("apps are tiered by tier_app"),
    };
    if !present {
        return (
            Tier::NoRecommendation,
            format!(
                "its state is \"{}\" — it is not active, so there is nothing \
                 to reclaim",
                item.state
            ),
        );
    }
    match feature_review_match(item) {
        Some(entry) => (
            Tier::SafeToRemove,
            format!(
                "on the rules v{RULES_VERSION} review list: {} Turning it off \
                 is reversible — it can be re-enabled the same way.",
                entry.rationale
            ),
        ),
        None => (
            Tier::NoRecommendation,
            format!(
                "not covered by the rules v{RULES_VERSION} review list — \
                 features carry no usage evidence, so DeadWeight makes no \
                 recommendation either way"
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, EvidenceSource};

    /// Capture time for tests: 2026-10-24T00:00:00Z.
    const NOW: i64 = 1_792_569_600;

    fn app(name: &str, install_date: Option<&str>, evidence: Evidence) -> AuditItem {
        let mut item = AuditItem::new(name, Kind::App, "installed");
        item.install_date = install_date.map(str::to_owned);
        item.evidence = evidence;
        item
    }

    fn feature(name: &str, kind: Kind, state: &str) -> AuditItem {
        AuditItem::new(name, kind, state)
    }

    #[test]
    fn never_touch_by_name() {
        let item = app(
            "Windows Defender Antivirus",
            Some("2022-01-01"),
            Evidence::none(),
        );
        let (tier, reason) = tier(&item, 400, NOW);
        assert_eq!(tier, Tier::NeverTouch);
        assert!(reason.contains("never-touch"), "{reason}");
    }

    #[test]
    fn never_touch_by_capability_prefix() {
        let item = feature(
            "Microsoft-Windows-Security-IdentityListener~~~~0.0.1.0",
            Kind::Capability,
            "Installed",
        );
        let (tier, _) = tier(&item, 400, NOW);
        assert_eq!(tier, Tier::NeverTouch);
    }

    #[test]
    fn never_touch_wins_over_safe_app() {
        // Old, no evidence, huge window — would be Safe if the
        // never-touch check did not run first.
        let item = app("Microsoft Defender", Some("2020-01-01"), Evidence::none());
        let (tier, _) = tier(&item, 700, NOW);
        assert_eq!(tier, Tier::NeverTouch);
    }

    #[test]
    fn never_touch_wins_over_safe_feature() {
        let mut item = feature("TelnetClient", Kind::OptionalFeature, "Enabled");
        item.publisher = Some("Defender Security".to_owned());
        let (tier, _) = tier(&item, 400, NOW);
        assert_eq!(tier, Tier::NeverTouch);
    }

    #[test]
    fn app_safe_when_old_and_no_evidence() {
        let item = app("Old Utility", Some("2023-01-01"), Evidence::none());
        let (tier, reason) = tier(&item, 200, NOW);
        assert_eq!(tier, Tier::SafeToRemove);
        assert!(reason.contains("no usage evidence"), "{reason}");
    }

    #[test]
    fn app_blocked_when_window_under_90_days() {
        let item = app("Old Utility", Some("2023-01-01"), Evidence::none());
        let (tier, reason) = tier(&item, 60, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("60 days"), "{reason}");
    }

    #[test]
    fn app_blocked_when_installed_inside_window() {
        // Installed 30 days before NOW; window is 200 days.
        let item = app("Fresh App", Some("2026-09-24"), Evidence::none());
        let (tier, reason) = tier(&item, 200, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("may simply be new"), "{reason}");
    }

    #[test]
    fn app_blocked_by_any_evidence() {
        let evidence = Evidence {
            last_used_unix: Some(NOW - 86_400),
            run_count: Some(1),
            sources: vec![EvidenceSource::Prefetch],
            matched_exe: Some("oldutility.exe".to_owned()),
        };
        let item = app("Old Utility", Some("2023-01-01"), evidence);
        let (tier, _) = tier(&item, 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
    }

    #[test]
    fn app_blocked_without_install_date() {
        let item = app("Dateless App", None, Evidence::none());
        let (tier, reason) = tier(&item, 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("no install date"), "{reason}");
    }

    #[test]
    fn feature_on_list_enabled_is_safe() {
        let item = feature("TelnetClient", Kind::OptionalFeature, "Enabled");
        let (tier, reason) = tier(&item, 10, NOW);
        assert_eq!(tier, Tier::SafeToRemove);
        assert!(reason.contains("review list"), "{reason}");
    }

    #[test]
    fn feature_on_list_disabled_is_no_recommendation() {
        let item = feature("TelnetClient", Kind::OptionalFeature, "Disabled");
        let (tier, _) = tier(&item, 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
    }

    #[test]
    fn smb1_carries_security_rationale() {
        let item = feature("SMB1Protocol", Kind::OptionalFeature, "Enabled");
        let (tier, reason) = tier(&item, 400, NOW);
        assert_eq!(tier, Tier::SafeToRemove);
        assert!(reason.contains("security vulnerabilities"), "{reason}");
    }

    #[test]
    fn feature_not_on_list_is_no_recommendation() {
        let item = feature("NetFx3", Kind::OptionalFeature, "Enabled");
        let (tier, reason) = tier(&item, 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("not covered"), "{reason}");
    }

    #[test]
    fn capability_on_list_installed_is_safe() {
        let item = feature("App.XpsViewer~~~~0.0.1.0", Kind::Capability, "Installed");
        let (tier, _) = tier(&item, 400, NOW);
        assert_eq!(tier, Tier::SafeToRemove);
    }

    #[test]
    fn capability_not_present_is_no_recommendation() {
        let item = feature("App.XpsViewer~~~~0.0.1.0", Kind::Capability, "Not Present");
        let (tier, _) = tier(&item, 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
    }
}
