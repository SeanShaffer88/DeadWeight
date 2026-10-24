//! Planning and codecs for the disable tier — pure, no I/O.
//!
//! A *plan* is a validated intent: the denylist and the RunOnce
//! refusal are enforced here, before anything is captured, journaled,
//! or changed, so an engine can never be driven into an action the
//! rules forbid. The engine consults plans on disable; undo never
//! does (undo must always be able to put back what disable did,
//! even if the rules change later).

use dw_core::model::StartupSource;
use dw_core::rules::{is_protected_service, protected_service_reason};
use dw_core::time::filetime_from_unix;

/// One validated disable action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Disable a service by setting its start type to Disabled.
    Service { name: String },
    /// Disable a startup item by writing its StartupApproved value.
    Startup { name: String, source: StartupSource },
}

/// Why an action is refused outright. A refusal is not an error in
/// the tool — it is the safety contract working as designed, and it
/// is reported to the user in plain language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The service is on the protected-services denylist.
    ProtectedService { name: String, reason: String },
    /// RunOnce items are never disable candidates.
    RunOnce { name: String, source: StartupSource },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::ProtectedService { name, reason } => {
                write!(
                    f,
                    "refused: \"{name}\" is on DeadWeight's protected-services \
                     list ({reason}) — protected services are never disabled"
                )
            }
            Refusal::RunOnce { name, source } => write!(
                f,
                "refused: \"{name}\" is a {} item — RunOnce items run once \
                 at the next sign-in and remove themselves; not a disable candidate",
                source.describe()
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Validate a service disable. Fails with a typed
/// [`Refusal::ProtectedService`] for denylisted names.
pub fn plan_disable_service(name: &str) -> Result<Plan, Refusal> {
    if is_protected_service(name) {
        return Err(Refusal::ProtectedService {
            name: name.to_owned(),
            reason: protected_service_reason(name)
                .unwrap_or("a protected Windows/security/update service")
                .to_owned(),
        });
    }
    Ok(Plan::Service {
        name: name.to_owned(),
    })
}

/// Validate a startup disable. Fails with a typed
/// [`Refusal::RunOnce`] for RunOnce sources — the plan layer refuses
/// them so no caller can forget.
pub fn plan_disable_startup(name: &str, source: StartupSource) -> Result<Plan, Refusal> {
    if source.is_run_once() {
        return Err(Refusal::RunOnce {
            name: name.to_owned(),
            source,
        });
    }
    Ok(Plan::Startup {
        name: name.to_owned(),
        source,
    })
}

// ---------------------------------------------------------------------
// StartupApproved codec
//
// The StartupApproved value format is documented by Microsoft and
// used by Task Manager and Settings: 12 bytes — one state byte
// (0x02 = enabled, 0x03 = disabled), three reserved zero bytes, and
// an 8-byte FILETIME timestamp of when the state last changed.
// Windows records the state change there so every tool agrees on
// whether the item runs. DeadWeight writes the same bytes Task
// Manager would, and — crucially — records the item's previous
// bytes verbatim in the journal, so undo restores exactly what was
// there, even bytes this codec does not recognise.
// ---------------------------------------------------------------------

/// The state a StartupApproved value describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupState {
    /// No value, or an enabled value: the item runs at sign-in.
    Enabled,
    /// A disabled value: the item does not run at sign-in.
    Disabled,
    /// Bytes in a shape this codec does not recognise. They are
    /// still restorable — the journal keeps them verbatim.
    Unrecognized(Vec<u8>),
}

impl std::fmt::Display for StartupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartupState::Enabled => write!(f, "enabled (runs at sign-in)"),
            StartupState::Disabled => write!(f, "disabled (does not run at sign-in)"),
            StartupState::Unrecognized(bytes) => write!(
                f,
                "a {}-byte value DeadWeight does not recognise (it would be \
                 recorded exactly and restored exactly on undo)",
                bytes.len()
            ),
        }
    }
}

/// Decode a StartupApproved value (`None` = no value present).
#[must_use]
pub fn decode_startup_state(blob: Option<&[u8]>) -> StartupState {
    match blob {
        None => StartupState::Enabled,
        Some(bytes) if bytes.len() == 12 && bytes[0] == 0x03 => StartupState::Disabled,
        Some(bytes) if bytes.len() == 12 && bytes[0] == 0x02 => StartupState::Enabled,
        Some(bytes) => StartupState::Unrecognized(bytes.to_vec()),
    }
}

/// Build the 12-byte StartupApproved value for a state, stamped
/// with `unix_time` (converted to a Windows FILETIME).
#[must_use]
pub fn startup_blob(disabled: bool, unix_time: i64) -> [u8; 12] {
    let mut blob = [0u8; 12];
    blob[0] = if disabled { 0x03 } else { 0x02 };
    blob[4..12].copy_from_slice(&filetime_from_unix(unix_time).to_le_bytes());
    blob
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_service_plan_is_refused_with_reason() {
        let err = plan_disable_service("WinDefend").unwrap_err();
        assert!(matches!(err, Refusal::ProtectedService { .. }));
        assert!(err.to_string().contains("protected"), "{err}");
        // Case-insensitive, like the rules.
        assert!(plan_disable_service("wuauserv").is_err());
        assert!(plan_disable_service("ExampleSvc").is_ok());
    }

    #[test]
    fn run_once_plan_is_refused() {
        let err = plan_disable_startup("Setup", StartupSource::RunOnceHkcu).unwrap_err();
        assert!(matches!(err, Refusal::RunOnce { .. }));
        assert!(plan_disable_startup("Tool", StartupSource::RunHkcu).is_ok());
        assert!(plan_disable_startup("Tool", StartupSource::StartupFolderUser).is_ok());
    }

    #[test]
    fn codec_round_trips_states_and_stamps_time() {
        let disabled = startup_blob(true, 1_792_569_600);
        assert_eq!(disabled.len(), 12);
        assert_eq!(disabled[0], 0x03);
        assert_eq!(&disabled[1..4], &[0, 0, 0]);
        let filetime = u64::from_le_bytes(disabled[4..12].try_into().unwrap());
        assert_eq!(filetime, filetime_from_unix(1_792_569_600));
        assert_eq!(
            decode_startup_state(Some(&disabled)),
            StartupState::Disabled
        );
        let enabled = startup_blob(false, 1_792_569_600);
        assert_eq!(enabled[0], 0x02);
        assert_eq!(decode_startup_state(Some(&enabled)), StartupState::Enabled);
        assert_eq!(decode_startup_state(None), StartupState::Enabled);
        assert_eq!(
            decode_startup_state(Some(&[9, 9])),
            StartupState::Unrecognized(vec![9, 9])
        );
    }
}
