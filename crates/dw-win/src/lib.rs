//! DeadWeight Windows collector (slice 1, read-only).
//!
//! Reads the live system through supported Windows interfaces and
//! emits a slice-1 [`AuditSnapshot`]:
//!
//! - installed apps from the Uninstall registry keys,
//! - optional features and capabilities via DISM,
//! - usage evidence from Prefetch, UserAssist, and BAM, fused and
//!   matched onto apps by executable name (see
//!   [`match_evidence`] for the matching rules and their limits).
//!
//! Collection is fault-tolerant per source: one failing source
//! yields fewer items (or less evidence) plus an entry in
//! [`CollectOutcome::warnings`], never a failed collection — unless
//! the entire inventory failed. Nothing in this crate writes to the
//! system: DeadWeight v1 is read-only, and the registry wrapper
//! deliberately has no write operations.
//!
//! Runtime behaviour on a real Windows machine is **Unverified**
//! until the field test in the project brief has compared collector
//! output against the equivalent system tools.

pub mod match_evidence;
pub mod store;

#[cfg(target_os = "windows")]
mod win;

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
