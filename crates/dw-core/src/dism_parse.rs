//! Pure parsing of DISM inventory output.
//!
//! The collector runs `dism.exe /Online /Get-Features /Format:List`
//! and `dism.exe /Online /Get-Capabilities` and parses the text with
//! the functions here, so the parsing rules are unit-tested against
//! fixtures instead of a live Windows machine.
//!
//! **Limitation:** the parser keys on the English field labels
//! (`Feature Name :`, `Capability Identity :`, `State :`). DISM
//! localizes these labels, so on a non-English Windows install the
//! parse finds nothing — the collector reports that as a warning
//! rather than inventing data.

/// One DISM inventory entry: a feature or capability and its state
/// exactly as DISM reported it (`Enabled`, `Disabled`, `Installed`,
/// `Not Present`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DismEntry {
    pub name: String,
    pub state: String,
}

/// Parse a DISM `/Format:List`-style listing. `name_key` is the field
/// label that starts a record (`Feature Name` or
/// `Capability Identity`); the record's state is its `State` field.
/// Records without a state are dropped, and banner/summary lines are
/// ignored because they never match the name key.
#[must_use]
pub fn parse_dism_listing(text: &str, name_key: &str) -> Vec<DismEntry> {
    let mut entries = Vec::new();
    let mut current_name: Option<String> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key == name_key {
            current_name = Some(value.to_owned());
        } else if key == "State" {
            if let Some(name) = current_name.take() {
                entries.push(DismEntry {
                    name,
                    state: value.to_owned(),
                });
            }
        }
    }
    entries
}

/// Parse `dism.exe /Online /Get-Features /Format:List` output.
#[must_use]
pub fn parse_dism_features(text: &str) -> Vec<DismEntry> {
    parse_dism_listing(text, "Feature Name")
}

/// Parse `dism.exe /Online /Get-Capabilities` output.
#[must_use]
pub fn parse_dism_capabilities(text: &str) -> Vec<DismEntry> {
    parse_dism_listing(text, "Capability Identity")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEATURES_FIXTURE: &str = "\
Deployment Image Servicing and Management tool
Version: 10.0.26100.5074

Image Version: 10.0.26200.8524

Features listing for image.

Feature Name : Microsoft-Windows-StepsRecorder
State : Disabled

Feature Name : TelnetClient
State : Enabled

Feature Name : SMB1Protocol
State : Enabled

The operation completed successfully.
";

    const CAPABILITIES_FIXTURE: &str = "\
Deployment Image Servicing and Management tool
Version: 10.0.26100.5074

Image Version: 10.0.26200.8524

Capability Identity : App.XpsViewer~~~~0.0.1.0
State : Not Present

Capability Identity : Microsoft-Windows-Security-IdentityListener~~~~0.0.1.0
State : Installed

The operation completed successfully.
";

    #[test]
    fn parses_features_fixture() {
        let entries = parse_dism_features(FEATURES_FIXTURE);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "Microsoft-Windows-StepsRecorder");
        assert_eq!(entries[0].state, "Disabled");
        assert_eq!(entries[1].name, "TelnetClient");
        assert_eq!(entries[1].state, "Enabled");
        assert_eq!(entries[2].name, "SMB1Protocol");
    }

    #[test]
    fn parses_capabilities_fixture() {
        let entries = parse_dism_capabilities(CAPABILITIES_FIXTURE);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "App.XpsViewer~~~~0.0.1.0");
        assert_eq!(entries[0].state, "Not Present");
        assert_eq!(entries[1].state, "Installed");
    }

    #[test]
    fn empty_and_banner_only_output_parses_to_nothing() {
        assert!(parse_dism_features("").is_empty());
        assert!(parse_dism_features("Deployment Image Servicing and Management tool\n").is_empty());
    }

    #[test]
    fn feature_parser_ignores_capability_records() {
        assert!(parse_dism_features(CAPABILITIES_FIXTURE).is_empty());
    }
}
