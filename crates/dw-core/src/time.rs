//! Minimal UTC date/time helpers.
//!
//! The core deliberately takes no date/time dependency for a handful of
//! conversions. The civil-date conversions are Howard Hinnant's
//! well-known public-domain algorithms (`civil_from_days` and its
//! inverse `days_from_civil`), exact for the proleptic Gregorian
//! calendar, leap years included.

/// Days from civil date (Hinnant's `days_from_civil`): the number of
/// days between 1970-01-01 and `year`-`month`-`day`.
#[must_use]
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let mut y = year;
    let m = i64::from(month);
    let d = i64::from(day);
    if m <= 2 {
        y -= 1;
    }
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // month index (Mar = 0), [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // day of year (Mar 1 = 0)
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Format Unix epoch seconds as an ISO-8601 UTC timestamp,
/// e.g. `2026-10-24T20:56:00Z`.
#[must_use]
pub fn format_unix_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let day_secs = secs % 86_400;
    let (hour, minute, second) = (day_secs / 3600, (day_secs % 3600) / 60, day_secs % 60);

    // civil_from_days: shift the epoch from 1970-01-01 to 0000-03-01 so
    // leap days fall at the end of a "year", then decompose into
    // 400-year eras.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era, [0, 399]
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year (Mar 1 = 0), [0, 365]
    let mp = (5 * doy + 2) / 153; // month index (Mar = 0), [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    if month <= 2 {
        year += 1;
    }

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Format Unix epoch seconds as an ISO-8601 UTC date (`YYYY-MM-DD`).
#[must_use]
pub fn format_unix_date(secs: i64) -> String {
    if secs < 0 {
        return "1970-01-01".to_owned();
    }
    format_unix_utc(secs as u64)[..10].to_owned()
}

/// Current UTC time as an ISO-8601 timestamp, from the system clock.
#[must_use]
pub fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_utc(secs)
}

/// Parse an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) or a bare
/// date (`YYYY-MM-DD`, taken as midnight UTC) into Unix epoch seconds.
/// Returns `None` for anything that does not match those shapes or has
/// out-of-range fields.
#[must_use]
pub fn parse_iso_utc(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 && bytes.len() != 20 {
        return None;
    }
    let year: i64 = text.get(0..4)?.parse().ok()?;
    let month: u32 = text.get(5..7)?.parse().ok()?;
    let day: u32 = text.get(8..10)?.parse().ok()?;
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if bytes.len() == 10 {
        return Some(days * 86_400);
    }
    if bytes[10] != b'T' || bytes[19] != b'Z' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let hour: i64 = text.get(11..13)?.parse().ok()?;
    let minute: i64 = text.get(14..16)?.parse().ok()?;
    let second: i64 = text.get(17..19)?.parse().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Convert Unix epoch seconds to a Windows FILETIME (100-nanosecond
/// intervals since 1601-01-01 UTC). Negative inputs saturate to 0.
/// This is the timestamp format the `StartupApproved` value carries.
#[must_use]
pub fn filetime_from_unix(unix: i64) -> u64 {
    /// FILETIME intervals between 1601-01-01 and 1970-01-01.
    const EPOCH_DELTA_100NS: i64 = 116_444_736_000_000_000;
    let intervals = unix
        .saturating_mul(10_000_000)
        .saturating_add(EPOCH_DELTA_100NS);
    u64::try_from(intervals).unwrap_or(0)
}

/// Days since the Unix epoch for an ISO date string (`YYYY-MM-DD`).
#[must_use]
pub fn iso_date_days(text: &str) -> Option<i64> {
    parse_iso_utc(text).map(|secs| secs.div_euclid(86_400))
}

/// Convert a registry `InstallDate` value (`YYYYMMDD`, as written by
/// Windows installers in the Uninstall keys) into an ISO date string.
/// Returns `None` when the value is missing, malformed, or carries an
/// out-of-range month/day — installers write this field by hand, so it
/// cannot be trusted blindly.
#[must_use]
pub fn install_date_from_yyyymmdd(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.len() != 8 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year: i64 = raw.get(0..4)?.parse().ok()?;
    let month: u32 = raw.get(4..6)?.parse().ok()?;
    let day: u32 = raw.get(6..8)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1980 {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_1970() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn leap_day_2024() {
        assert_eq!(format_unix_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(format_unix_utc(1_709_251_200), "2024-03-01T00:00:00Z");
    }

    #[test]
    fn parse_round_trips_format() {
        for secs in [0, 1_709_164_800, 1_772_236_800, 1_800_000_000] {
            assert_eq!(parse_iso_utc(&format_unix_utc(secs as u64)), Some(secs));
        }
    }

    #[test]
    fn parse_bare_date_is_midnight() {
        assert_eq!(parse_iso_utc("2024-02-29"), Some(1_709_164_800));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse_iso_utc(""), None);
        assert_eq!(parse_iso_utc("2024-13-01"), None);
        assert_eq!(parse_iso_utc("24-02-29T00:00:00Z"), None);
        assert_eq!(parse_iso_utc("2024-02-29 00:00:00"), None);
    }

    #[test]
    fn install_date_conversion() {
        assert_eq!(
            install_date_from_yyyymmdd("20240315").as_deref(),
            Some("2024-03-15")
        );
        assert_eq!(install_date_from_yyyymmdd("20241301"), None);
        assert_eq!(install_date_from_yyyymmdd("garbage!"), None);
        assert_eq!(install_date_from_yyyymmdd(""), None);
    }

    #[test]
    fn format_date_drops_time() {
        assert_eq!(format_unix_date(1_709_164_800 + 3_600), "2024-02-29");
    }

    #[test]
    fn filetime_conversion_round_trips_with_evidence_parse() {
        assert_eq!(filetime_from_unix(0), 116_444_736_000_000_000);
        assert_eq!(
            crate::evidence_parse::filetime_to_unix(filetime_from_unix(1_709_164_800)),
            Some(1_709_164_800)
        );
        assert_eq!(filetime_from_unix(-5), 116_444_735_950_000_000);
    }
}
