//! Windows-only smoke test: the collector runs end to end against
//! the live system (in CI, a windows-latest runner). It asserts only
//! what must be true on any real Windows install — collection
//! succeeds and the inventory finds items — because per-source
//! availability (DISM elevation, BAM access) legitimately varies.
#![cfg(target_os = "windows")]

#[test]
fn collect_succeeds_and_inventories_something() {
    let outcome = dw_win::collect().expect("collection should succeed on Windows");
    assert!(
        !outcome.snapshot.items.is_empty(),
        "a Windows machine always has installed apps or features"
    );
    // The snapshot must survive its own JSON round-trip.
    let json = outcome.snapshot.to_json().expect("serialize");
    let back = dw_core::model::AuditSnapshot::from_json(&json).expect("parse own output");
    assert_eq!(back.items.len(), outcome.snapshot.items.len());
}
