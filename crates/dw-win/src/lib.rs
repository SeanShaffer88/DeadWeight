//! DeadWeight Windows layer: the collector and the disable tier.
//!
//! The collector reads the live system through supported Windows
//! interfaces and emits an [`AuditSnapshot`]:
//!
//! - installed apps from the Uninstall registry keys,
//! - optional features and capabilities via DISM,
//! - services from the Service Control Manager and startup items
//!   from the Run/RunOnce keys and Startup folders,
//! - usage evidence from Prefetch, UserAssist, and BAM, fused and
//!   matched onto apps by executable name (see
//!   [`match_evidence`] for the matching rules and their limits).
//!
//! Collection is fault-tolerant per source: one failing source
//! yields fewer items (or less evidence) plus an entry in
//! [`CollectOutcome::warnings`], never a failed collection — unless
//! the entire inventory failed. Collection itself never writes to
//! the system. The crate's only system writes are the disable
//! tier's two operations in [`action`] (a service's start type, a
//! startup item's StartupApproved value), executed only through
//! the journaled engine.
//!
//! Runtime behaviour on a real Windows machine is **Unverified**
//! until the field test in the project brief has compared collector
//! output against the equivalent system tools.

pub mod action;
pub mod match_evidence;
pub mod store;

#[cfg(target_os = "windows")]
mod win;

#[cfg(target_os = "windows")]
pub use win::action_win::{find_startup_sources, WindowsPlatform};
#[cfg(target_os = "windows")]
pub use win::restore::SystemRestorePoints;

use dw_core::model::AuditSnapshot;

/// The result of a successful collection: the audit snapshot plus a
/// warning for every source that could not be read.
#[derive(Debug)]
pub struct CollectOutcome {
    pub snapshot: AuditSnapshot,
    pub warnings: Vec<String>,
}

/// Why a collection could not be produced at all.
#[derive(Debug)]
pub enum CollectError {
    /// The collector only runs on Windows.
    UnsupportedPlatform,
    /// Every inventory source failed; the warnings say why.
    TotalFailure { warnings: Vec<String> },
}

impl std::fmt::Display for CollectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollectError::UnsupportedPlatform => {
                f.write_str("The audit collector only runs on Windows.")
            }
            CollectError::TotalFailure { warnings } => write!(
                f,
                "every inventory source failed ({} warning(s)): {}",
                warnings.len(),
                warnings.join("; ")
            ),
        }
    }
}

impl std::error::Error for CollectError {}

/// Collect an audit of the live system.
///
/// # Errors
/// - [`CollectError::UnsupportedPlatform`] on non-Windows systems.
/// - [`CollectError::TotalFailure`] when every inventory source failed.
pub fn collect() -> Result<CollectOutcome, CollectError> {
    #[cfg(target_os = "windows")]
    {
        win::collect()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(CollectError::UnsupportedPlatform)
    }
}
