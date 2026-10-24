//! Pure parsing of the raw shapes the usage-evidence sources use:
//! ROT13-encoded UserAssist value names, the binary UserAssist value
//! layout, Windows FILETIME stamps, and Prefetch file names.
//!
//! These formats are forensic layouts, not supported APIs. Every
//! parser here is fallible on purpose: a value whose shape does not
//! match the documented layout yields `None`, never a guess.
//!
//! The UserAssist value layout used here is the widely documented
//! Windows 7-and-later format: a 72-byte binary value with the run
//! count as a little-endian `u32` at offset 4 and the last-run time as
//! a FILETIME (little-endian `u64`) at offset 60.

/// ROT13 substitution over ASCII letters; every other character is
/// passed through unchanged. UserAssist value names are stored
/// ROT13-encoded, and ROT13 is its own inverse, so this one function
/// both encodes and decodes.
#[must_use]
pub fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => char::from_u32(u32::from(c) + 13).unwrap_or(c),
            'n'..='z' | 'N'..='Z' => char::from_u32(u32::from(c) - 13).unwrap_or(c),
            _ => c,
        })
        .collect()
}

/// One parsed UserAssist value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAssistRecord {
    /// How many times the item was run, as recorded by Explorer.
    pub run_count: u32,
    /// Last recorded run, as Unix epoch seconds (`None` when the
    /// stored FILETIME is zero, i.e. never stamped).
    pub last_run_unix: Option<i64>,
}

/// Convert a Windows FILETIME (100-nanosecond intervals since
/// 1601-01-01 UTC) to Unix epoch seconds. Returns `None` for zero
/// (the "never" stamp) and for values before the Unix epoch.
#[must_use]
pub fn filetime_to_unix(filetime: u64) -> Option<i64> {
    /// FILETIME intervals between 1601-01-01 and 1970-01-01.
    const EPOCH_DELTA_100NS: u64 = 116_444_736_000_000_000;
    if filetime < EPOCH_DELTA_100NS {
        return None;
    }
    Some(((filetime - EPOCH_DELTA_100NS) / 10_000_000) as i64)
}

/// Parse a UserAssist binary value in the 72-byte Windows 7+ layout
/// (run count `u32` at offset 4, last-run FILETIME at offset 60).
/// Returns `None` when the value is shorter than 72 bytes — shorter
/// values are the older 16-byte layout or special counters, and this
/// parser does not guess at them.
#[must_use]
pub fn parse_userassist_value(bytes: &[u8]) -> Option<UserAssistRecord> {
    if bytes.len() < 72 {
        return None;
    }
    let run_count = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?);
    let filetime = u64::from_le_bytes(bytes.get(60..68)?.try_into().ok()?);
    Some(UserAssistRecord {
        run_count,
        last_run_unix: filetime_to_unix(filetime),
    })
}

/// Extract the executable name from a Prefetch file name.
/// Prefetch files are named `<EXE NAME>-<8 hex digits>.pf`
/// (e.g. `NOTEPAD.EXE-1A2B3C4D.pf`); the hash suffix distinguishes
/// different paths to the same executable. Returns the executable
/// name, or `None` when the file name does not follow the pattern
/// (auxiliary Prefetch files such as `PfSfPrefetch` bookkeeping do
/// not).
#[must_use]
pub fn exe_name_from_prefetch(file_name: &str) -> Option<String> {
    let stem = file_name
        .strip_suffix(".pf")
        .or_else(|| file_name.strip_suffix(".PF"))?;
    let (name, hash) = stem.rsplit_once('-')?;
    if name.is_empty() || hash.len() != 8 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(name.to_owned())
}

/// The file-name component of a path (splitting on both `\` and `/`),
/// without trailing separators.
#[must_use]
pub fn file_name_of(path: &str) -> &str {
    let trimmed = path.trim_end_matches(['\\', '/']);
    match trimmed.rfind(['\\', '/']) {
        Some(index) => &trimmed[index + 1..],
        None => trimmed,
    }
}

/// Normalize a display name or executable name for evidence matching:
/// lowercase, alphanumeric characters only. `My App 2.0` and
/// `myapp2.exe`'s base both normalize to `myapp2`.
#[must_use]
pub fn normalize_for_match(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// The normalized match key for an executable: file-name component,
/// final extension removed, normalized. `C:\Apps\My App 2.exe`
/// becomes `myapp2`; BAM device paths and UserAssist paths are
/// handled the same way.
#[must_use]
pub fn exe_base_key(path_or_name: &str) -> String {
    let file_name = file_name_of(path_or_name);
    let stem = match file_name.rfind('.') {
        Some(index) if index > 0 => &file_name[..index],
        _ => file_name,
    };
    normalize_for_match(stem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_round_trip() {
        let plain = "C:\\Program Files\\Example\\App.EXE";
        let encoded = rot13(plain);
        assert_ne!(encoded, plain);
        assert_eq!(rot13(&encoded), plain);
    }

    #[test]
    fn rot13_known_value() {
        // The shape of a real UserAssist value name.
        assert_eq!(
            rot13("P:\\Hfref\\Qngn\\ncc.rkr"),
            "C:\\Users\\Data\\app.exe"
        );
        assert_eq!(rot13("HRZR_EHACNGU"), "UEME_RUNPATH");
    }

    #[test]
    fn filetime_epoch_delta_is_zero() {
        assert_eq!(filetime_to_unix(116_444_736_000_000_000), Some(0));
    }

    #[test]
    fn filetime_zero_is_never() {
        assert_eq!(filetime_to_unix(0), None);
    }

    #[test]
    fn filetime_known_stamp() {
        // 2024-02-29T00:00:00Z = 1709164800 Unix = filetime below.
        assert_eq!(
            filetime_to_unix(133_536_384_000_000_000),
            Some(1_709_164_800)
        );
    }

    fn userassist_bytes(run_count: u32, filetime: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 72];
        bytes[4..8].copy_from_slice(&run_count.to_le_bytes());
        bytes[60..68].copy_from_slice(&filetime.to_le_bytes());
        bytes
    }

    #[test]
    fn userassist_parse_full_layout() {
        let record =
            parse_userassist_value(&userassist_bytes(42, 133_536_384_000_000_000)).expect("parse");
        assert_eq!(record.run_count, 42);
        assert_eq!(record.last_run_unix, Some(1_709_164_800));
    }

    #[test]
    fn userassist_parse_zero_filetime() {
        let record = parse_userassist_value(&userassist_bytes(3, 0)).expect("parse");
        assert_eq!(record.run_count, 3);
        assert_eq!(record.last_run_unix, None);
    }

    #[test]
    fn userassist_parse_rejects_short_values() {
        assert_eq!(parse_userassist_value(&[0u8; 16]), None);
        assert_eq!(parse_userassist_value(&[]), None);
    }

    #[test]
    fn prefetch_name_extraction() {
        assert_eq!(
            exe_name_from_prefetch("NOTEPAD.EXE-1A2B3C4D.pf").as_deref(),
            Some("NOTEPAD.EXE")
        );
        assert_eq!(
            exe_name_from_prefetch("SVCHOST.EXE-9F2056B2.PF").as_deref(),
            Some("SVCHOST.EXE")
        );
    }

    #[test]
    fn prefetch_name_rejects_non_pattern() {
        assert_eq!(exe_name_from_prefetch("PfSqmFile.pf"), None);
        assert_eq!(exe_name_from_prefetch("APP.EXE-XYZ.pf"), None);
        assert_eq!(exe_name_from_prefetch("APP.EXE-1A2B3C4D.txt"), None);
        assert_eq!(exe_name_from_prefetch("-1A2B3C4D.pf"), None);
    }

    #[test]
    fn exe_base_key_normalizes() {
        assert_eq!(exe_base_key("C:\\Apps\\My App 2.exe"), "myapp2");
        assert_eq!(
            exe_base_key("\\Device\\HarddiskVolume3\\Tools\\THING.EXE"),
            "thing"
        );
        assert_eq!(exe_base_key("plain"), "plain");
    }

    #[test]
    fn normalize_keeps_digits_drops_punctuation() {
        assert_eq!(normalize_for_match("App-Name_2.0 (x64)"), "appname20x64");
    }
}
