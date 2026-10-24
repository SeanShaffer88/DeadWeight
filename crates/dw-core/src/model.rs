//! Audit data model: a point-in-time inventory of installed software
//! together with the usage evidence found for each item.
//!
//! An audit is evidence, not a verdict. Every field that Windows does
//! not report stays `None` ("not reported") rather than being filled
//! with an estimate — sizes and dates are never invented.

use serde::{Deserialize, Serialize};

/// Current audit schema version. Bump when the JSON shape changes in a
/// way older readers cannot tolerate; migrations belong with the bump.
/// Version 2 (slice 2) added the `Service` and `StartupItem` kinds
/// plus their fields; older readers cannot parse audits containing
/// them, hence the bump. New fields on existing kinds are all
/// `serde(default)`, so version-2 readers still parse version-1
/// audits.
pub const SCHEMA_VERSION: u32 = 2;

/// The category of an audited item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Kind {
    /// A desktop application from the Uninstall registry keys.
    App,
    /// A Windows optional feature (DISM `/Get-Features`).
    OptionalFeature,
    /// A Windows capability (DISM `/Get-Capabilities`).
    Capability,
    /// A Windows service (Service Control Manager), slice 2.
    Service,
    /// A startup item: a Run/RunOnce registry value or a file in a
    /// Startup folder, slice 2.
    StartupItem,
}

impl Kind {
    /// Short human-readable label used in reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Kind::App => "App",
            Kind::OptionalFeature => "Optional feature",
            Kind::Capability => "Capability",
            Kind::Service => "Service",
            Kind::StartupItem => "Startup item",
        }
    }
}

/// Where a startup item lives. The exact source matters: the disable
/// engine acts on one source at a time, and audit items record theirs
/// so reports (and later, disable commands) never have to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StartupSource {
    /// `HKCU\...\Run`
    RunHkcu,
    /// `HKLM\...\Run`
    RunHklm,
    /// `HKLM\Software\WOW6432Node\...\Run`
    RunHklmWow64,
    /// `HKCU\...\RunOnce`
    RunOnceHkcu,
    /// `HKLM\...\RunOnce`
    RunOnceHklm,
    /// `HKLM\Software\WOW6432Node\...\RunOnce`
    RunOnceHklmWow64,
    /// The per-user Startup folder.
    StartupFolderUser,
    /// The common (all-users) Startup folder.
    StartupFolderCommon,
}

impl StartupSource {
    /// Short CLI token for the source (used by `disable --source`).
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            StartupSource::RunHkcu => "run-hkcu",
            StartupSource::RunHklm => "run-hklm",
            StartupSource::RunHklmWow64 => "run-wow64",
            StartupSource::RunOnceHkcu => "runonce-hkcu",
            StartupSource::RunOnceHklm => "runonce-hklm",
            StartupSource::RunOnceHklmWow64 => "runonce-wow64",
            StartupSource::StartupFolderUser => "folder-user",
            StartupSource::StartupFolderCommon => "folder-common",
        }
    }

    /// Parse a `--source` token back into a source.
    #[must_use]
    pub fn from_token(token: &str) -> Option<StartupSource> {
        match token {
            "run-hkcu" => Some(StartupSource::RunHkcu),
            "run-hklm" => Some(StartupSource::RunHklm),
            "run-wow64" => Some(StartupSource::RunHklmWow64),
            "runonce-hkcu" => Some(StartupSource::RunOnceHkcu),
            "runonce-hklm" => Some(StartupSource::RunOnceHklm),
            "runonce-wow64" => Some(StartupSource::RunOnceHklmWow64),
            "folder-user" => Some(StartupSource::StartupFolderUser),
            "folder-common" => Some(StartupSource::StartupFolderCommon),
            _ => None,
        }
    }

    /// All sources, for help text and exhaustive resolution.
    pub const ALL: [StartupSource; 8] = [
        StartupSource::RunHkcu,
        StartupSource::RunHklm,
        StartupSource::RunHklmWow64,
        StartupSource::RunOnceHkcu,
        StartupSource::RunOnceHklm,
        StartupSource::RunOnceHklmWow64,
        StartupSource::StartupFolderUser,
        StartupSource::StartupFolderCommon,
    ];

    /// Human-readable description of where the item lives.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            StartupSource::RunHkcu => "the current user's Run registry key",
            StartupSource::RunHklm => "the machine-wide Run registry key",
            StartupSource::RunHklmWow64 => "the machine-wide 32-bit Run registry key",
            StartupSource::RunOnceHkcu => "the current user's RunOnce registry key",
            StartupSource::RunOnceHklm => "the machine-wide RunOnce registry key",
            StartupSource::RunOnceHklmWow64 => "the machine-wide 32-bit RunOnce registry key",
            StartupSource::StartupFolderUser => "the current user's Startup folder",
            StartupSource::StartupFolderCommon => "the common Startup folder",
        }
    }

    /// Whether this source is a RunOnce key. RunOnce items run once
    /// and remove themselves, so they are never disable candidates.
    #[must_use]
    pub fn is_run_once(self) -> bool {
        matches!(
            self,
            StartupSource::RunOnceHkcu
                | StartupSource::RunOnceHklm
                | StartupSource::RunOnceHklmWow64
        )
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Where a piece of usage evidence came from. Each source is a
/// different Windows recording mechanism with different coverage —
/// none of them records everything, which is why the report treats
/// missing evidence as "not seen", never as "not used".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// `C:\Windows\Prefetch` file names and file times.
    Prefetch,
    /// Explorer UserAssist run counts and last-run times.
    UserAssist,
    /// Background Activity Moderator execution records.
    Bam,
}

impl EvidenceSource {
    /// Human-readable label used in reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            EvidenceSource::Prefetch => "Prefetch",
            EvidenceSource::UserAssist => "UserAssist",
            EvidenceSource::Bam => "BAM",
        }
    }

    /// All sources, in the fixed order reports list them in.
    pub const ALL: [EvidenceSource; 3] = [
        EvidenceSource::Prefetch,
        EvidenceSource::UserAssist,
        EvidenceSource::Bam,
    ];
}

/// How strong the fused usage evidence for an item is, derived from
/// how many independent sources saw it and how often it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceStrength {
    /// No source recorded any use.
    None,
    /// Exactly one source recorded use.
    Weak,
    /// Two or more sources agree, or the run count is 3 or more.
    Strong,
}

/// The usage evidence found for one item, fused across sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Most recent recorded execution, as Unix epoch seconds.
    pub last_used_unix: Option<i64>,
    /// Highest run count reported by any source that counts runs
    /// (UserAssist). Counts from different sources are never summed —
    /// they overlap — so the maximum is the honest figure.
    pub run_count: Option<u32>,
    /// Which sources recorded use of this item.
    pub sources: Vec<EvidenceSource>,
    /// The executable file name the evidence matched on, when any.
    /// Shown in the report so the match is transparent: evidence is
    /// matched to apps by executable name (a heuristic), and the user
    /// can see exactly what matched.
    pub matched_exe: Option<String>,
}

impl Evidence {
    /// Evidence for an item nothing was found for.
    #[must_use]
    pub fn none() -> Self {
        Self {
            last_used_unix: None,
            run_count: None,
            sources: Vec::new(),
            matched_exe: None,
        }
    }

    /// Derived strength: **Strong** when two or more sources agree or
    /// the run count is 3 or more, **Weak** when exactly one source
    /// recorded use, **None** when no source matched.
    #[must_use]
    pub fn strength(&self) -> EvidenceStrength {
        if self.sources.is_empty() {
            return EvidenceStrength::None;
        }
        if self.sources.len() >= 2 || self.run_count.is_some_and(|count| count >= 3) {
            return EvidenceStrength::Strong;
        }
        EvidenceStrength::Weak
    }
}

impl Default for Evidence {
    fn default() -> Self {
        Self::none()
    }
}

/// One audited item: an installed app, optional feature, capability,
/// service, or startup item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditItem {
    pub name: String,
    pub publisher: Option<String>,
    pub kind: Kind,
    /// State as reported by the inventory source: `installed` for
    /// apps; the DISM state (`Enabled`/`Disabled`,
    /// `Installed`/`Not Present`, …) for features and capabilities;
    /// the run state (`Running`/`Stopped`/…) for services; `unknown`
    /// for startup items — the inventory deliberately does not read
    /// the `StartupApproved` state, so it does not claim one.
    pub state: String,
    /// On-disk size in bytes **as reported by Windows** (for apps, the
    /// Uninstall key's `EstimatedSize`). `None` means Windows does not
    /// report a size — never an estimate made up by DeadWeight.
    pub size_bytes: Option<u64>,
    /// Install date as an ISO date (`YYYY-MM-DD`), when reported.
    pub install_date: Option<String>,
    /// Install location as reported by the Uninstall key, when present.
    pub install_location: Option<String>,
    /// Services only: the SCM start type (`dwStartType`: 0 boot,
    /// 1 system, 2 automatic, 3 manual, 4 disabled), when the
    /// service's configuration could be read.
    #[serde(default)]
    pub start_type: Option<u32>,
    /// Services only: whether automatic start is delayed
    /// (`SERVICE_DELAYED_AUTO_START_INFO`). Delayed automatic is
    /// still start type 2; this flag only refines the label.
    #[serde(default)]
    pub delayed_start: bool,
    /// Services only: the service's binary path with surrounding
    /// quotes and command-line arguments stripped (see
    /// `service_parse::exe_path_from_binary_path`).
    #[serde(default)]
    pub binary_path: Option<String>,
    /// Whether the item's executable lives under the Windows
    /// directory recorded in [`AuditSnapshot::windows_dir`], as
    /// computed by the collector (services and startup items only).
    /// Tiering treats Windows-directory programs as OS components.
    #[serde(default)]
    pub binary_in_windows_dir: bool,
    /// Startup items only: the target as reported — the command line
    /// from a Run/RunOnce value, or the file path for Startup-folder
    /// items.
    #[serde(default)]
    pub target: Option<String>,
    /// Startup items only: which source the item came from.
    #[serde(default)]
    pub startup_source: Option<StartupSource>,
    /// Services and startup items only: the name of the inventoried
    /// app whose install location contains this item's executable,
    /// when one does. Tiering uses it as context: a helper belonging
    /// to an app that is still used is not a disable candidate.
    #[serde(default)]
    pub parent_app: Option<String>,
    pub evidence: Evidence,
}

impl AuditItem {
    /// A new item with no evidence attached yet.
    #[must_use]
    pub fn new(name: &str, kind: Kind, state: &str) -> Self {
        Self {
            name: name.to_owned(),
            publisher: None,
            kind,
            state: state.to_owned(),
            size_bytes: None,
            install_date: None,
            install_location: None,
            start_type: None,
            delayed_start: false,
            binary_path: None,
            binary_in_windows_dir: false,
            target: None,
            startup_source: None,
            parent_app: None,
            evidence: Evidence::none(),
        }
    }
}

/// A complete audit: the inventory plus fused evidence, captured at a
/// point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSnapshot {
    pub schema_version: u32,
    /// Capture time as an ISO-8601 UTC timestamp supplied by the
    /// collector.
    pub captured_at: String,
    /// How far back the usage evidence reaches, in whole days: the
    /// span between the oldest recorded execution found anywhere on
    /// the machine and the capture time. `0` when no dated evidence
    /// could be read at all. Tiering and the report's seasonal warning
    /// are driven by this number.
    pub evidence_window_days: u32,
    /// The machine's Windows directory as reported by the collector
    /// (`%SystemRoot%`, e.g. `C:\Windows`). Tiering compares service
    /// and startup binary paths against it. `None` in audits written
    /// before slice 2; tiering then assumes `C:\Windows`.
    #[serde(default)]
    pub windows_dir: Option<String>,
    pub items: Vec<AuditItem>,
}

impl AuditSnapshot {
    /// Serialize to pretty JSON (the on-disk audit format).
    ///
    /// # Errors
    /// Returns the serialization error if this snapshot cannot be
    /// represented as JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Parse a snapshot from its JSON form.
    ///
    /// # Errors
    /// Returns the parse error when the text is not a valid audit.
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(sources: Vec<EvidenceSource>, run_count: Option<u32>) -> Evidence {
        Evidence {
            last_used_unix: Some(1_700_000_000),
            run_count,
            sources,
            matched_exe: Some("app.exe".to_owned()),
        }
    }

    #[test]
    fn strength_none_without_sources() {
        assert_eq!(Evidence::none().strength(), EvidenceStrength::None);
    }

    #[test]
    fn strength_weak_with_one_source() {
        let ev = evidence(vec![EvidenceSource::Prefetch], Some(1));
        assert_eq!(ev.strength(), EvidenceStrength::Weak);
    }

    #[test]
    fn strength_strong_with_two_sources() {
        let ev = evidence(vec![EvidenceSource::Prefetch, EvidenceSource::Bam], Some(1));
        assert_eq!(ev.strength(), EvidenceStrength::Strong);
    }

    #[test]
    fn strength_strong_with_run_count_three() {
        let ev = evidence(vec![EvidenceSource::UserAssist], Some(3));
        assert_eq!(ev.strength(), EvidenceStrength::Strong);
    }

    #[test]
    fn strength_weak_with_run_count_two() {
        let ev = evidence(vec![EvidenceSource::UserAssist], Some(2));
        assert_eq!(ev.strength(), EvidenceStrength::Weak);
    }

    #[test]
    fn snapshot_json_round_trip() {
        let mut item = AuditItem::new("Example App", Kind::App, "installed");
        item.publisher = Some("Example Co".to_owned());
        item.size_bytes = Some(123_456_789);
        item.install_date = Some("2023-05-01".to_owned());
        item.evidence = evidence(vec![EvidenceSource::UserAssist], Some(7));
        let snapshot = AuditSnapshot {
            schema_version: SCHEMA_VERSION,
            captured_at: "2026-10-24T20:56:00Z".to_owned(),
            evidence_window_days: 212,
            windows_dir: Some("C:\\Windows".to_owned()),
            items: vec![item],
        };
        let json = snapshot.to_json().expect("serialize");
        let back = AuditSnapshot::from_json(&json).expect("parse");
        assert_eq!(back, snapshot);
    }
}
