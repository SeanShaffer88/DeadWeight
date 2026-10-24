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
//! - A service or startup item is only ever a **Disable and watch**
//!   candidate when the rules can cite facts: automatic start, a
//!   program outside the Windows directory (services), no usage
//!   evidence for its executable, and no usage evidence for the app
//!   it belongs to. Protected services are never-touch, decided by
//!   the denylist before any other service rule runs.
//!
//! The allow/deny lists below are source data: changing them changes
//! what DeadWeight recommends, so they are versioned with
//! [`RULES_VERSION`], which is printed in every report. A list change
//! is a reviewable diff and must bump the version.
//!
//! Rules changelog:
//! - **v1** (slice 1): apps (evidence + window + install age),
//!   optional features/capabilities (curated review list),
//!   never-touch name/publisher patterns.
//! - **v2** (slice 2): services and startup items join the audit.
//!   Adds the protected-services denylist ([`PROTECTED_SERVICES`]),
//!   the service rules (automatic start + outside the Windows
//!   directory + no usage evidence for the item or its parent app),
//!   and the startup-item rules (no usage evidence for the item or
//!   its parent app; RunOnce is never a candidate). App, feature,
//!   and capability verdicts are unchanged from v1.

use crate::evidence_parse::normalize_for_match;
use crate::model::{AuditItem, EvidenceStrength, Kind};
use crate::service_parse::{start_type_label, SERVICE_AUTO_START};
use crate::time::iso_date_days;

/// Version of the tiering rules in this file. Printed in every
/// report so a reader can tell which rules produced it.
pub const RULES_VERSION: u32 = 2;

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
    /// Candidate for the disable tier: a service or startup item
    /// that can be disabled, watched, and re-enabled before any
    /// removal decision. Landing here is a recommendation only —
    /// disabling is a separate, explicit, journaled action.
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

/// Services DeadWeight will never tier as disable candidates and
/// never disable, with the reason shown to the user. The list is
/// deliberately focused: boot- and session-critical services,
/// security services, and the update stack (DeadWeight never touches
/// security settings or update policy). The disable engine enforces
/// the same list, so a protected service is refused even when the
/// command is typed by hand. Matched case-insensitively on the
/// service name.
pub const PROTECTED_SERVICES: &[(&str, &str)] = &[
    ("RpcSs", "the Remote Procedure Call service, which most other Windows services depend on"),
    ("RpcEptMapper", "the RPC endpoint mapper, which other services need to be reachable"),
    ("DcomLaunch", "the DCOM server process launcher, which Windows needs to start COM components"),
    ("LSM", "the Local Session Manager, which manages user sessions"),
    ("BrokerInfrastructure", "the Background Tasks Infrastructure service, which coordinates background system work"),
    ("Power", "the Power service, which manages power policy"),
    ("PlugPlay", "Plug and Play, which detects devices and installs their drivers"),
    ("SamSs", "the Security Accounts Manager, which stores local account security information"),
    ("WinDefend", "the Microsoft Defender Antivirus service (security software)"),
    ("SecurityHealthService", "the Windows Security service (security software)"),
    ("Sense", "the Microsoft Defender for Endpoint service (security software)"),
    ("wuauserv", "the Windows Update service; DeadWeight never changes update policy"),
    ("UsoSvc", "the Update Orchestrator service, part of Windows Update"),
    ("BITS", "the Background Intelligent Transfer Service, which Windows Update uses to download updates"),
    ("EventLog", "the Windows Event Log service, which records the audit and diagnostic logs"),
    ("ProfSvc", "the User Profile Service, which is required to sign in"),
    ("UserManager", "the User Manager service, which is required for user sessions"),
    ("gpsvc", "the Group Policy client, which applies system and user policy"),
    ("CryptSvc", "Cryptographic Services, which maintains certificate and update catalog stores"),
];

/// Whether a service name is on the protected-services denylist
/// (case-insensitive).
#[must_use]
pub fn is_protected_service(name: &str) -> bool {
    protected_service_reason(name).is_some()
}

/// The reason a service is protected, if it is.
#[must_use]
pub fn protected_service_reason(name: &str) -> Option<&'static str> {
    PROTECTED_SERVICES
        .iter()
        .find(|(protected, _)| protected.eq_ignore_ascii_case(name))
        .map(|(_, reason)| *reason)
}

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
/// `siblings` is the audit's full item list — service and startup
/// tiering consults the parent app's evidence through it.
/// `window_days` is the audit's evidence window and `now_unix` the
/// capture time; app tiering compares the install date against both.
/// (Whether a service's program lives in the Windows directory is
/// the per-item `binary_in_windows_dir` fact the collector computed
/// against the audit's recorded Windows directory.)
#[must_use]
pub fn tier(
    item: &AuditItem,
    siblings: &[AuditItem],
    window_days: u32,
    now_unix: i64,
) -> (Tier, String) {
    match item.kind {
        // Startup items are routed before the generic never-touch
        // patterns on purpose: never-touch does not apply to them.
        // A startup entry is a pointer to a program, and disabling
        // the pointer (reversibly, through StartupApproved) is the
        // disable tier's safest surface; the security stack's own
        // startup entries still need positive usage evidence to be
        // excluded — as with everything here, absence of evidence
        // makes them candidates, never targets of anything stronger.
        Kind::StartupItem => tier_startup(item, siblings),
        Kind::Service => tier_service(item, siblings),
        Kind::App | Kind::OptionalFeature | Kind::Capability => {
            // Never-touch is checked first and always wins, even
            // over an item that would otherwise look like a
            // candidate.
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
                _ => tier_feature(item),
            }
        }
    }
}

/// Why usage evidence blocks a disable-and-watch candidacy, if it
/// does: the item's own executable has recorded usage, or the app it
/// belongs to does. The returned string is the full report reason.
fn evidence_block(item: &AuditItem, siblings: &[AuditItem]) -> Option<String> {
    if item.evidence.strength() != EvidenceStrength::None {
        let detail = match item.evidence.last_used_unix {
            Some(last) => format!(
                "usage evidence found for its executable ({} source(s), last used {}) — \
                 it is still run, so it is not a disable candidate",
                item.evidence.sources.len(),
                crate::time::format_unix_date(last),
            ),
            None => "usage evidence found for its executable — it is still run, \
                     so it is not a disable candidate"
                .to_owned(),
        };
        return Some(detail);
    }
    if let Some(parent_name) = &item.parent_app {
        if let Some(parent) = siblings
            .iter()
            .find(|s| s.kind == Kind::App && &s.name == parent_name)
        {
            if parent.evidence.strength() != EvidenceStrength::None {
                return Some(format!(
                    "it belongs to \"{parent_name}\", which has usage evidence \
                     ({} source(s)) — a helper for an app that is still used is \
                     not a disable candidate",
                    parent.evidence.sources.len(),
                ));
            }
        }
    }
    None
}

/// The "belongs to" clause for candidate reasons: names the parent
/// app (and its own lack of evidence) when the item has one.
fn parent_clause(item: &AuditItem) -> String {
    match &item.parent_app {
        Some(parent) => {
            format!("; the app it belongs to (\"{parent}\") has none either")
        }
        None => String::new(),
    }
}

fn tier_service(item: &AuditItem, siblings: &[AuditItem]) -> (Tier, String) {
    // The protected-services denylist runs before every other
    // service rule: a protected service is never-touch even when its
    // binary lives outside the Windows directory and nothing has
    // ever recorded it running.
    if is_protected_service(&item.name) {
        return (
            Tier::NeverTouch,
            "a protected Windows/security/update service — DeadWeight never \
             recommends disabling core Windows, security, or update services"
                .to_owned(),
        );
    }
    if let Some(pattern) = never_touch_match(item) {
        return (
            Tier::NeverTouch,
            format!(
                "excluded by the never-touch rules (matches \"{pattern}\"): \
                 security components are considered and left alone"
            ),
        );
    }
    let Some(start_type) = item.start_type else {
        return (
            Tier::NoRecommendation,
            "its configuration could not be read (access may be restricted), \
             so its start type is unknown"
                .to_owned(),
        );
    };
    if start_type != SERVICE_AUTO_START {
        let label = start_type_label(start_type, item.delayed_start);
        let detail = if start_type == crate::service_parse::SERVICE_DISABLED {
            format!(
                "its start type is {label} — it already does not start; \
                 there is nothing to disable"
            )
        } else {
            format!(
                "its start type is {label} — only Automatic services are \
                 disable-and-watch candidates, because they are the ones \
                 that start on their own"
            )
        };
        return (Tier::NoRecommendation, detail);
    }
    let Some(binary_path) = &item.binary_path else {
        return (
            Tier::NoRecommendation,
            "its program path could not be read, so there is no executable \
             to check evidence against"
                .to_owned(),
        );
    };
    if item.binary_in_windows_dir {
        return (
            Tier::NoRecommendation,
            format!(
                "its program lives in the Windows folder ({binary_path}) — an \
                 OS component; DeadWeight stays conservative and makes no \
                 recommendation for Windows' own services"
            ),
        );
    }
    if let Some(block) = evidence_block(item, siblings) {
        return (Tier::NoRecommendation, block);
    }
    (
        Tier::DisableAndWatch,
        format!(
            "starts automatically ({}), its program lives outside the \
             Windows folder ({}), and no usage evidence was found for \
             it{} — a candidate to disable and watch; re-enable it if \
             anything misbehaves",
            start_type_label(start_type, item.delayed_start),
            binary_path,
            parent_clause(item),
        ),
    )
}

fn tier_startup(item: &AuditItem, siblings: &[AuditItem]) -> (Tier, String) {
    if item.startup_source.is_some_and(|s| s.is_run_once()) {
        return (
            Tier::NoRecommendation,
            "RunOnce items run once at the next sign-in and remove \
             themselves; not a disable candidate"
                .to_owned(),
        );
    }
    if let Some(block) = evidence_block(item, siblings) {
        return (Tier::NoRecommendation, block);
    }
    let target = item.target.as_deref().unwrap_or("its program");
    (
        Tier::DisableAndWatch,
        format!(
            "no usage evidence was found for its program ({target}){} — \
             a candidate to disable and watch; it can be re-enabled \
             instantly",
            parent_clause(item),
        ),
    )
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
        Kind::Service | Kind::StartupItem => {
            unreachable!("services and startup items are tiered by their own functions")
        }
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

    /// Slice-1 call shape: no siblings, the given window, NOW.
    /// Slice-1 verdicts must be identical under rules v2.
    fn tier1(item: &AuditItem, window: u32) -> (Tier, String) {
        tier(item, &[], window, NOW)
    }

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
        let (tier, reason) = tier1(&item, 400);
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
        let (tier, _) = tier1(&item, 400);
        assert_eq!(tier, Tier::NeverTouch);
    }

    #[test]
    fn never_touch_wins_over_safe_app() {
        // Old, no evidence, huge window — would be Safe if the
        // never-touch check did not run first.
        let item = app("Microsoft Defender", Some("2020-01-01"), Evidence::none());
        let (tier, _) = tier1(&item, 700);
        assert_eq!(tier, Tier::NeverTouch);
    }

    #[test]
    fn never_touch_wins_over_safe_feature() {
        let mut item = feature("TelnetClient", Kind::OptionalFeature, "Enabled");
        item.publisher = Some("Defender Security".to_owned());
        let (tier, _) = tier1(&item, 400);
        assert_eq!(tier, Tier::NeverTouch);
    }

    #[test]
    fn app_safe_when_old_and_no_evidence() {
        let item = app("Old Utility", Some("2023-01-01"), Evidence::none());
        let (tier, reason) = tier1(&item, 200);
        assert_eq!(tier, Tier::SafeToRemove);
        assert!(reason.contains("no usage evidence"), "{reason}");
    }

    #[test]
    fn app_blocked_when_window_under_90_days() {
        let item = app("Old Utility", Some("2023-01-01"), Evidence::none());
        let (tier, reason) = tier1(&item, 60);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("60 days"), "{reason}");
    }

    #[test]
    fn app_blocked_when_installed_inside_window() {
        // Installed 30 days before NOW; window is 200 days.
        let item = app("Fresh App", Some("2026-09-24"), Evidence::none());
        let (tier, reason) = tier1(&item, 200);
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
        let (tier, _) = tier1(&item, 400);
        assert_eq!(tier, Tier::NoRecommendation);
    }

    #[test]
    fn app_blocked_without_install_date() {
        let item = app("Dateless App", None, Evidence::none());
        let (tier, reason) = tier1(&item, 400);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("no install date"), "{reason}");
    }

    #[test]
    fn feature_on_list_enabled_is_safe() {
        let item = feature("TelnetClient", Kind::OptionalFeature, "Enabled");
        let (tier, reason) = tier1(&item, 10);
        assert_eq!(tier, Tier::SafeToRemove);
        assert!(reason.contains("review list"), "{reason}");
    }

    #[test]
    fn feature_on_list_disabled_is_no_recommendation() {
        let item = feature("TelnetClient", Kind::OptionalFeature, "Disabled");
        let (tier, _) = tier1(&item, 400);
        assert_eq!(tier, Tier::NoRecommendation);
    }

    #[test]
    fn smb1_carries_security_rationale() {
        let item = feature("SMB1Protocol", Kind::OptionalFeature, "Enabled");
        let (tier, reason) = tier1(&item, 400);
        assert_eq!(tier, Tier::SafeToRemove);
        assert!(reason.contains("security vulnerabilities"), "{reason}");
    }

    #[test]
    fn feature_not_on_list_is_no_recommendation() {
        let item = feature("NetFx3", Kind::OptionalFeature, "Enabled");
        let (tier, reason) = tier1(&item, 400);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("not covered"), "{reason}");
    }

    #[test]
    fn capability_on_list_installed_is_safe() {
        let item = feature("App.XpsViewer~~~~0.0.1.0", Kind::Capability, "Installed");
        let (tier, _) = tier1(&item, 400);
        assert_eq!(tier, Tier::SafeToRemove);
    }

    #[test]
    fn capability_not_present_is_no_recommendation() {
        let item = feature("App.XpsViewer~~~~0.0.1.0", Kind::Capability, "Not Present");
        let (tier, _) = tier1(&item, 400);
        assert_eq!(tier, Tier::NoRecommendation);
    }

    // ---- Rules v2: services and startup items ----------------------

    use crate::model::StartupSource;

    fn service(
        name: &str,
        start_type: Option<u32>,
        binary_path: Option<&str>,
        in_windows_dir: bool,
    ) -> AuditItem {
        let mut item = AuditItem::new(name, Kind::Service, "Stopped");
        item.start_type = start_type;
        item.binary_path = binary_path.map(str::to_owned);
        item.binary_in_windows_dir = in_windows_dir;
        item
    }

    fn evidence_with(prefetch: bool) -> Evidence {
        if prefetch {
            Evidence {
                last_used_unix: Some(NOW - 86_400),
                run_count: None,
                sources: vec![EvidenceSource::Prefetch],
                matched_exe: Some("tool.exe".to_owned()),
            }
        } else {
            Evidence::none()
        }
    }

    #[test]
    fn protected_service_is_never_touch_despite_third_party_path() {
        // Third-party path, automatic, no evidence: every candidacy
        // fact points at DisableAndWatch — the denylist must win.
        let item = service(
            "WinDefend",
            Some(2),
            Some("C:\\ProgramData\\Defender\\MsMpEng.exe"),
            false,
        );
        let (got, reason) = tier(&item, &[], 400, NOW);
        assert_eq!(got, Tier::NeverTouch);
        assert!(
            reason.contains("protected Windows/security/update service"),
            "{reason}"
        );
        // Case-insensitive.
        let lower = service("wuauserv", Some(2), Some("D:\\Tools\\upd.exe"), false);
        assert_eq!(tier(&lower, &[], 400, NOW).0, Tier::NeverTouch);
    }

    #[test]
    fn windows_dir_automatic_service_is_no_recommendation() {
        let item = service(
            "ExampleOsService",
            Some(2),
            Some("C:\\Windows\\System32\\svchost.exe"),
            true,
        );
        let (tier, reason) = tier(&item, &[], 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("Windows folder"), "{reason}");
    }

    #[test]
    fn third_party_automatic_no_evidence_is_a_candidate() {
        let item = service(
            "ExampleSyncService",
            Some(2),
            Some("C:\\Program Files\\Example\\sync.exe"),
            false,
        );
        let (got, reason) = tier(&item, &[], 400, NOW);
        assert_eq!(got, Tier::DisableAndWatch);
        assert!(reason.contains("starts automatically"), "{reason}");
        assert!(reason.contains("no usage evidence"), "{reason}");
        // Delayed automatic is still automatic.
        let mut delayed = item.clone();
        delayed.delayed_start = true;
        let (got, reason) = tier(&delayed, &[], 400, NOW);
        assert_eq!(got, Tier::DisableAndWatch);
        assert!(reason.contains("Automatic (delayed start)"), "{reason}");
    }

    #[test]
    fn candidate_blocked_when_parent_app_has_evidence() {
        let mut parent = app("Example Sync", Some("2023-01-01"), evidence_with(true));
        parent.install_location = Some("C:\\Program Files\\Example".to_owned());
        let mut item = service(
            "ExampleSyncService",
            Some(2),
            Some("C:\\Program Files\\Example\\sync.exe"),
            false,
        );
        item.parent_app = Some("Example Sync".to_owned());
        let (tier, reason) = tier(&item, &[parent], 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("Example Sync"), "{reason}");
    }

    #[test]
    fn candidate_allowed_when_parent_app_has_no_evidence() {
        let parent = app("Example Sync", Some("2023-01-01"), Evidence::none());
        let mut item = service(
            "ExampleSyncService",
            Some(2),
            Some("C:\\Program Files\\Example\\sync.exe"),
            false,
        );
        item.parent_app = Some("Example Sync".to_owned());
        let (tier, reason) = tier(&item, &[parent], 400, NOW);
        assert_eq!(tier, Tier::DisableAndWatch);
        assert!(reason.contains("Example Sync"), "{reason}");
    }

    #[test]
    fn manual_start_third_party_service_is_no_recommendation() {
        let item = service(
            "ExampleSyncService",
            Some(3),
            Some("C:\\Program Files\\Example\\sync.exe"),
            false,
        );
        let (tier, reason) = tier(&item, &[], 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("Manual"), "{reason}");
    }

    #[test]
    fn service_with_own_evidence_is_no_recommendation() {
        let mut item = service(
            "ExampleSyncService",
            Some(2),
            Some("C:\\Program Files\\Example\\sync.exe"),
            false,
        );
        item.evidence = evidence_with(true);
        let (tier, _) = tier(&item, &[], 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
    }

    #[test]
    fn service_without_start_type_is_no_recommendation() {
        let item = service("ExampleSyncService", None, None, false);
        let (tier, reason) = tier(&item, &[], 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("could not be read"), "{reason}");
    }

    fn startup(name: &str, source: StartupSource, evidence: Evidence) -> AuditItem {
        let mut item = AuditItem::new(name, Kind::StartupItem, "unknown");
        item.target = Some("C:\\Program Files\\Example\\tool.exe".to_owned());
        item.startup_source = Some(source);
        item.evidence = evidence;
        item
    }

    #[test]
    fn startup_no_evidence_is_a_candidate() {
        let item = startup("Example Tool", StartupSource::RunHkcu, Evidence::none());
        let (tier, reason) = tier(&item, &[], 400, NOW);
        assert_eq!(tier, Tier::DisableAndWatch);
        assert!(reason.contains("no usage evidence"), "{reason}");
    }

    #[test]
    fn startup_run_once_is_no_recommendation() {
        let item = startup(
            "OneTime Setup",
            StartupSource::RunOnceHkcu,
            Evidence::none(),
        );
        let (tier, reason) = tier(&item, &[], 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
        assert!(reason.contains("RunOnce"), "{reason}");
        assert!(reason.contains("remove themselves"), "{reason}");
    }

    #[test]
    fn startup_with_evidence_is_no_recommendation() {
        let item = startup("Example Tool", StartupSource::RunHkcu, evidence_with(true));
        let (tier, _) = tier(&item, &[], 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
    }

    #[test]
    fn startup_blocked_by_parent_app_evidence() {
        let parent = app("Example Tool", Some("2023-01-01"), evidence_with(true));
        let mut item = startup("Example Tool", StartupSource::RunHkcu, Evidence::none());
        item.parent_app = Some("Example Tool".to_owned());
        let (tier, _) = tier(&item, &[parent], 400, NOW);
        assert_eq!(tier, Tier::NoRecommendation);
    }

    #[test]
    fn startup_named_like_security_still_not_never_touch() {
        // NeverTouch does not apply to startup items (spec): the
        // generic name patterns must not route them there.
        let item = startup(
            "Windows Defender Tray",
            StartupSource::RunHkcu,
            Evidence::none(),
        );
        let (tier, _) = tier(&item, &[], 400, NOW);
        assert_eq!(tier, Tier::DisableAndWatch);
    }
}
