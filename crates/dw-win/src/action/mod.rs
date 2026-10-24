//! The disable tier: plan, journal, engine, export.
//!
//! Slice 2 adds DeadWeight's only mutation surface, and it is
//! deliberately narrow: services (start type only — a running
//! service is never stopped) and startup items (their
//! StartupApproved value only — the Run entry or shortcut itself is
//! never touched). Apps, optional features, and capabilities are
//! never mutated, and there is no scheduled-task, driver, or
//! uninstall functionality anywhere in the product.
//!
//! Every action runs the engine's fixed order — validate, capture
//! prior state, attempt a restore point, journal `Planned`, mutate,
//! verify, mark `Applied` — and every action can be undone from
//! the journal. The pure pieces (planning, the StartupApproved
//! codec, the journal, the engine state machine, export) are
//! platform-independent and unit-tested; the Windows operations
//! live behind [`PlatformOps`] in the `win` module.

pub mod engine;
pub mod export;
pub mod journal;
pub mod plan;

pub use engine::{ActionOutcome, Engine, EngineError, PlatformOps, RestorePointOps};
pub use journal::{EntryKind, EntryStatus, Journal, JournalEntry, PriorState};
