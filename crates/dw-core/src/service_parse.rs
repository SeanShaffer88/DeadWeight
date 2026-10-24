//! Pure helpers for service and startup-item data: normalizing the
//! binary paths the Service Control Manager reports, naming start
//! types and run states, and deciding whether a path lives under the
//! Windows directory.
//!
//! SCM binary paths arrive in several shapes: quoted
//! (`"C:\Program Files\App\svc.exe" -flag`), unquoted with arguments
//! (`C:\Apps\svc.exe /run`), and bare (`C:\Windows\System32\svchost.exe
//! -k group` — arguments historically common). The normalizer is
//! conservative: it returns the executable path Windows will load,
//! and never invents one.

/// `SERVICE_DISABLED` from the Service Control Manager API
/// (`dwStartType` value 4).
pub const SERVICE_DISABLED: u32 = 4;

/// `SERVICE_AUTO_START` (`dwStartType` value 2). Delayed automatic
/// services share this value; the delay is a separate flag.
pub const SERVICE_AUTO_START: u32 = 2;

/// Extract the executable path from an SCM binary path (or a startup
/// command line): surrounding quotes are removed, and arguments are
/// stripped. The rule: a leading quote delimits the path exactly;
/// otherwise the path runs to the end of the first `.exe` (matched
/// case-insensitively); if there is no `.exe`, the path runs to the
/// first ` -` or ` /` argument boundary; failing all that, the whole
/// trimmed string is the path.
#[must_use]
pub fn exe_path_from_binary_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(rest) = trimmed.strip_prefix('"') {
        return match rest.find('"') {
            Some(end) => rest[..end].to_owned(),
            None => rest.to_owned(),
        };
    }
    let lower = trimmed.to_lowercase();
    if let Some(index) = lower.find(".exe") {
        return trimmed[..index + 4].to_owned();
    }
    let cut = [" -", " /"]
        .iter()
        .filter_map(|needle| trimmed.find(needle))
        .min();
    match cut {
        Some(index) => trimmed[..index].trim_end().to_owned(),
        None => trimmed.to_owned(),
    }
}

/// Human-readable label for an SCM start type (`dwStartType`):
/// 0 boot, 1 system, 2 automatic (delayed when the delayed-auto-start
/// flag is set), 3 manual, 4 disabled.
#[must_use]
pub fn start_type_label(start_type: u32, delayed: bool) -> String {
    match start_type {
        0 => "Boot".to_owned(),
        1 => "System".to_owned(),
        2 if delayed => "Automatic (delayed start)".to_owned(),
        2 => "Automatic".to_owned(),
        3 => "Manual".to_owned(),
        4 => "Disabled".to_owned(),
        other => format!("Unknown ({other})"),
    }
}

/// Human-readable label for a service run state
/// (`SERVICE_STATUS.dwCurrentState`).
#[must_use]
pub fn service_state_label(state: u32) -> &'static str {
    match state {
        1 => "Stopped",
        2 => "Start pending",
        3 => "Stop pending",
        4 => "Running",
        5 => "Continue pending",
        6 => "Pause pending",
        7 => "Paused",
        _ => "Unknown",
    }
}

/// Normalize a Windows path for comparison: forward slashes become
/// backslashes, everything lowercases, a leading NT `\??\` prefix is
/// dropped, and trailing separators are removed.
fn normalize_path(path: &str) -> String {
    let mut normalized = path.trim().replace('/', "\\").to_lowercase();
    if let Some(rest) = normalized.strip_prefix("\\??\\") {
        normalized = rest.to_owned();
    }
    while normalized.ends_with('\\') && normalized.len() > 3 {
        normalized.pop();
    }
    normalized
}

/// Whether `path` is the Windows directory itself or lives under it.
/// `%SystemRoot%` and `\SystemRoot` prefixes in the compared path are
/// resolved against `windows_dir` first (service binary paths are
/// sometimes recorded that way). The comparison is a directory-prefix
/// comparison — `C:\WindowsApps\…` is **not** under `C:\Windows`.
#[must_use]
pub fn path_is_under_windows_dir(path: &str, windows_dir: &str) -> bool {
    let dir = normalize_path(windows_dir);
    if dir.is_empty() {
        return false;
    }
    let mut candidate = normalize_path(path);
    for prefix in ["%systemroot%", "\\systemroot"] {
        if let Some(rest) = candidate.strip_prefix(prefix) {
            candidate = format!("{dir}{rest}");
            break;
        }
    }
    candidate == dir || candidate.starts_with(&format!("{dir}\\"))
}

/// The directory portion of a Windows path (everything before the
/// final file name), normalized for comparison. Returns an empty
/// string when the path has no directory portion.
#[must_use]
pub fn parent_dir_normalized(path: &str) -> String {
    let normalized = normalize_path(path);
    match normalized.rfind('\\') {
        Some(index) => normalized[..index].to_owned(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_path_keeps_spaces_and_drops_args() {
        assert_eq!(
            exe_path_from_binary_path("\"C:\\Program Files\\My App\\svc.exe\" -run"),
            "C:\\Program Files\\My App\\svc.exe"
        );
    }

    #[test]
    fn unquoted_path_stops_at_exe_end() {
        assert_eq!(
            exe_path_from_binary_path("C:\\Apps\\svc.exe /service"),
            "C:\\Apps\\svc.exe"
        );
        assert_eq!(
            exe_path_from_binary_path("C:\\Windows\\System32\\svchost.exe -k netsvcs"),
            "C:\\Windows\\System32\\svchost.exe"
        );
        assert_eq!(
            exe_path_from_binary_path("C:\\Apps\\SVC.EXE"),
            "C:\\Apps\\SVC.EXE"
        );
    }

    #[test]
    fn no_exe_falls_back_to_argument_boundary() {
        assert_eq!(
            exe_path_from_binary_path("C:\\Tools\\runner -x"),
            "C:\\Tools\\runner"
        );
        assert_eq!(
            exe_path_from_binary_path("C:\\Tools\\runner /x"),
            "C:\\Tools\\runner"
        );
        assert_eq!(
            exe_path_from_binary_path("  C:\\Tools\\runner  "),
            "C:\\Tools\\runner"
        );
    }

    #[test]
    fn unclosed_quote_takes_the_rest() {
        assert_eq!(
            exe_path_from_binary_path("\"C:\\Apps\\svc.exe"),
            "C:\\Apps\\svc.exe"
        );
        assert_eq!(exe_path_from_binary_path(""), "");
    }

    #[test]
    fn start_type_labels() {
        assert_eq!(start_type_label(0, false), "Boot");
        assert_eq!(start_type_label(1, false), "System");
        assert_eq!(start_type_label(2, false), "Automatic");
        assert_eq!(start_type_label(2, true), "Automatic (delayed start)");
        assert_eq!(start_type_label(3, false), "Manual");
        assert_eq!(start_type_label(4, false), "Disabled");
        assert_eq!(start_type_label(9, false), "Unknown (9)");
    }

    #[test]
    fn service_state_labels() {
        assert_eq!(service_state_label(1), "Stopped");
        assert_eq!(service_state_label(4), "Running");
        assert_eq!(service_state_label(7), "Paused");
        assert_eq!(service_state_label(42), "Unknown");
    }

    #[test]
    fn windows_dir_prefix_matching() {
        assert!(path_is_under_windows_dir(
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows"
        ));
        assert!(path_is_under_windows_dir(
            "c:/windows/syswow64/x.exe",
            "C:\\Windows\\"
        ));
        assert!(!path_is_under_windows_dir(
            "C:\\WindowsApps\\x.exe",
            "C:\\Windows"
        ));
        assert!(!path_is_under_windows_dir(
            "C:\\Program Files\\x.exe",
            "C:\\Windows"
        ));
        assert!(path_is_under_windows_dir(
            "%SystemRoot%\\System32\\x.exe",
            "C:\\Windows"
        ));
        assert!(path_is_under_windows_dir(
            "\\SystemRoot\\System32\\x.exe",
            "D:\\WinNT"
        ));
        assert!(path_is_under_windows_dir(
            "\\??\\C:\\Windows\\x.exe",
            "C:\\Windows"
        ));
    }

    #[test]
    fn parent_dir_extraction() {
        assert_eq!(
            parent_dir_normalized("C:\\Program Files\\App\\app.exe"),
            "c:\\program files\\app"
        );
        assert_eq!(parent_dir_normalized("app.exe"), "");
    }
}
