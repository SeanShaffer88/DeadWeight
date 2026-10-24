//! Evidence matching: fusing per-executable observations from the
//! three sources and matching them to inventoried apps.
//!
//! Matching is by executable name — a heuristic, and the module is
//! written so the heuristic stays honest:
//!
//! - An observation matches an app when the executable's normalized
//!   base name **equals** the app's normalized display name, or when
//!   one is a substring of the other and the shorter side is at least
//!   [`MIN_SUBSTRING_LEN`] characters (short names substring-match
//!   far too eagerly to mean anything).
//! - Exact matches beat substring matches; ties break toward more
//!   sources, then toward the most recent use.
//! - The winning executable's original file name is recorded in the
//!   fused [`Evidence::matched_exe`], so the report shows exactly
//!   what matched instead of hiding the guess.
//!
//! Everything here is platform-independent and unit-tested; the
//! Windows layer only produces [`ExeEvidence`] observations.

use std::collections::BTreeMap;

use dw_core::evidence_parse::normalize_for_match;
use dw_core::model::{Evidence, EvidenceSource};

/// Minimum normalized length for a substring match to count.
pub const MIN_SUBSTRING_LEN: usize = 5;

/// One source's observation of one executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeEvidence {
    /// Original executable file name as recorded (e.g. `Notepad.exe`).
    pub exe_name: String,
    /// Normalized match key (see `dw_core::evidence_parse::exe_base_key`).
    pub base_key: String,
    /// Which source recorded this observation.
    pub source: EvidenceSource,
    /// Last recorded execution, Unix epoch seconds.
    pub last_used_unix: Option<i64>,
    /// Run count, when the source counts runs (UserAssist).
    pub run_count: Option<u32>,
}

/// Merge all observations of one executable into a single [`Evidence`]:
/// sources are the distinct set (in the fixed report order), last use
/// is the maximum, run count is the maximum (counts from different
/// sources overlap and are never summed).
#[must_use]
pub fn fuse_observations(observations: &[ExeEvidence], matched_exe: &str) -> Evidence {
    let mut sources: Vec<EvidenceSource> = Vec::new();
    for source in EvidenceSource::ALL {
        if observations.iter().any(|o| o.source == source) {
            sources.push(source);
        }
    }
    Evidence {
        last_used_unix: observations.iter().filter_map(|o| o.last_used_unix).max(),
        run_count: observations.iter().filter_map(|o| o.run_count).max(),
        sources,
        matched_exe: Some(matched_exe.to_owned()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MatchKind {
    Substring,
    Exact,
}

/// How strongly one executable group matched an app name.
fn match_kind(app_key: &str, exe_key: &str) -> Option<MatchKind> {
    if exe_key.is_empty() || app_key.is_empty() {
        return None;
    }
    if exe_key == app_key {
        return Some(MatchKind::Exact);
    }
    let shorter = exe_key.len().min(app_key.len());
    if shorter >= MIN_SUBSTRING_LEN && (app_key.contains(exe_key) || exe_key.contains(app_key)) {
        return Some(MatchKind::Substring);
    }
    None
}

/// Find the best-matching executable group for an app and return its
/// fused evidence, or `None` when nothing matched.
#[must_use]
pub fn find_evidence(app_name: &str, observations: &[ExeEvidence]) -> Option<Evidence> {
    let app_key = normalize_for_match(app_name);
    if app_key.is_empty() {
        return None;
    }
    // Group observations by executable base key, remembering one
    // original file name per group.
    let mut groups: BTreeMap<&str, (&str, Vec<&ExeEvidence>)> = BTreeMap::new();
    for observation in observations {
        groups
            .entry(observation.base_key.as_str())
            .or_insert_with(|| (observation.exe_name.as_str(), Vec::new()))
            .1
            .push(observation);
    }

    let mut best: Option<(MatchKind, usize, i64, &str, Vec<ExeEvidence>)> = None;
    for (base_key, (exe_name, group)) in groups {
        let Some(kind) = match_kind(&app_key, base_key) else {
            continue;
        };
        let cloned: Vec<ExeEvidence> = group.iter().map(|o| (*o).clone()).collect();
        let fused = fuse_observations(&cloned, exe_name);
        let candidate = (
            kind,
            fused.sources.len(),
            fused.last_used_unix.unwrap_or(i64::MIN),
            exe_name,
            cloned,
        );
        let is_better = match &best {
            None => true,
            Some(current) => {
                (candidate.0, candidate.1, candidate.2) > (current.0, current.1, current.2)
            }
        };
        if is_better {
            best = Some(candidate);
        }
    }
    best.map(|(_, _, _, exe_name, group)| fuse_observations(&group, exe_name))
}

/// The evidence window in whole days: from the oldest dated
/// observation to `now_unix`. `0` when no observation carries a date.
#[must_use]
pub fn evidence_window_days(observations: &[ExeEvidence], now_unix: i64) -> u32 {
    let Some(oldest) = observations.iter().filter_map(|o| o.last_used_unix).min() else {
        return 0;
    };
    let span = now_unix.saturating_sub(oldest);
    if span <= 0 {
        return 0;
    }
    u32::try_from(span / 86_400).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(
        exe_name: &str,
        source: EvidenceSource,
        last_used: Option<i64>,
        run_count: Option<u32>,
    ) -> ExeEvidence {
        ExeEvidence {
            exe_name: exe_name.to_owned(),
            base_key: dw_core::evidence_parse::exe_base_key(exe_name),
            source,
            last_used_unix: last_used,
            run_count,
        }
    }

    #[test]
    fn exact_match_fuses_sources() {
        let observations = vec![
            observation("oldutility.exe", EvidenceSource::Prefetch, Some(100), None),
            observation(
                "OldUtility.exe",
                EvidenceSource::UserAssist,
                Some(200),
                Some(4),
            ),
        ];
        let evidence = find_evidence("Old Utility", &observations).expect("match");
        assert_eq!(evidence.sources.len(), 2);
        assert_eq!(evidence.last_used_unix, Some(200));
        assert_eq!(evidence.run_count, Some(4));
        assert_eq!(evidence.matched_exe.as_deref(), Some("oldutility.exe"));
    }

    #[test]
    fn substring_match_needs_five_chars() {
        let observations = vec![observation(
            "photoeditor.exe",
            EvidenceSource::Bam,
            Some(50),
            None,
        )];
        // App "Photo Editor Pro" normalizes to photoeditorpro, which
        // contains the 11-char exe key.
        assert!(find_evidence("Photo Editor Pro", &observations).is_some());
        // A 3-char exe key must not substring-match anything.
        let tiny = vec![observation("app.exe", EvidenceSource::Bam, Some(50), None)];
        assert!(find_evidence("Some Application", &tiny).is_none());
    }

    #[test]
    fn exe_key_inside_app_and_app_key_inside_exe_both_match() {
        let observations = vec![observation(
            "megacorpviewer.exe",
            EvidenceSource::Prefetch,
            Some(10),
            None,
        )];
        assert!(find_evidence("MegaCorp", &observations).is_some());
    }

    #[test]
    fn no_match_returns_none() {
        let observations = vec![observation(
            "notepad.exe",
            EvidenceSource::Prefetch,
            Some(10),
            None,
        )];
        assert!(find_evidence("Quantum Spreadsheet", &observations).is_none());
    }

    #[test]
    fn exact_match_beats_substring_match() {
        let observations = vec![
            observation("widget.exe", EvidenceSource::Prefetch, Some(999), None),
            observation(
                "widgetstudio.exe",
                EvidenceSource::Prefetch,
                Some(100),
                None,
            ),
        ];
        // "Widget Studio" contains "widget" (substring) and equals
        // "widgetstudio" (exact): the exact group must win despite
        // the substring group's newer timestamp.
        let evidence = find_evidence("Widget Studio", &observations).expect("match");
        assert_eq!(evidence.matched_exe.as_deref(), Some("widgetstudio.exe"));
    }

    #[test]
    fn window_days_from_oldest_observation() {
        let now = 86_400 * 1_000;
        let observations = vec![
            observation("a.exe", EvidenceSource::Bam, Some(now - 86_400 * 30), None),
            observation("b.exe", EvidenceSource::Bam, Some(now - 86_400 * 5), None),
            observation("c.exe", EvidenceSource::Bam, None, None),
        ];
        assert_eq!(evidence_window_days(&observations, now), 30);
        assert_eq!(evidence_window_days(&[], now), 0);
    }
}
