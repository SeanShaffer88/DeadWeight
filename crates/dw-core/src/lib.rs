#![forbid(unsafe_code)]

//! DeadWeight core: the audit model, forensic evidence parsing, DISM
//! output parsing, the versioned tiering rules, and the report
//! renderer.
//!
//! Everything in this crate is pure and platform-independent: nothing
//! here touches a live system. The collector in `dw-win` reads
//! Windows, translates what it finds into this crate's model, and the
//! rules here decide what the evidence means.

pub mod dism_parse;
pub mod evidence_parse;
pub mod model;
pub mod report;
pub mod rules;
pub mod service_parse;
pub mod time;
