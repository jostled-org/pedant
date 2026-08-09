//! Journeys through the real Cargo, rather than a fixture's stand-in.

use crate::baseline_store::VendoredWorkspace;
use crate::fixtures::write;
use crate::process_guard::Completed;
use crate::real_vendor::RealVendorFixture;

// ---------------------------------------------------------------------------
// Journeys through the real Cargo
// ---------------------------------------------------------------------------

#[test]
fn supply_chain_init_then_verify_is_clean() {
    let fixture = RealVendorFixture::new();
    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    let verify = fixture.supply_chain("verify");
    assert!(verify.success(), "verify failed: {}", verify.transcript());
    assert!(
        verify.stdout.contains("All dependencies match baselines."),
        "{}",
        verify.transcript()
    );
}

#[test]
fn supply_chain_verify_reports_missing_baseline() {
    let fixture = RealVendorFixture::new();
    let verify = fixture.run(&[
        "supply-chain",
        "verify",
        "--baseline-path",
        fixture.baselines().argument(),
        "--fail-on",
        "new-dependency",
    ]);
    assert_eq!(verify.code(), Some(1), "{}", verify.transcript());
    assert_reports_new_dependency(&verify);
}

#[test]
fn supply_chain_verify_fail_on_none_does_not_fail() {
    let fixture = RealVendorFixture::new();
    let verify = fixture.run(&[
        "supply-chain",
        "verify",
        "--baseline-path",
        fixture.baselines().argument(),
        "--fail-on",
        "none",
    ]);
    assert!(verify.success(), "verify failed: {}", verify.transcript());
    assert_reports_new_dependency(&verify);
}

#[test]
fn supply_chain_verify_debug_package_emits_hashed_inputs() {
    let fixture = RealVendorFixture::new();
    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    let verify = fixture.debug_package("serde");
    assert!(verify.success(), "verify failed: {}", verify.transcript());
    let stderr = verify.stderr.as_ref();
    assert!(stderr.contains("debug-package: serde@"), "{stderr}");
    assert!(stderr.contains("source_hash:"), "{stderr}");
    assert!(stderr.contains("file: ./"), "{stderr}");
    assert!(stderr.contains("sha256="), "{stderr}");
}

#[test]
fn supply_chain_update_prunes_stale_versions_and_removed_crates() {
    let fixture = RealVendorFixture::new();
    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    let serde_dir = fixture.baselines().path().join("cargo/serde");
    write(&serde_dir.join("0.0.0.json"), "{}");
    let removed_dir = fixture.baselines().path().join("cargo/removed-crate");
    write(&removed_dir.join("9.9.9.json"), "{}");

    let update = fixture.supply_chain("update");
    assert!(update.success(), "update failed: {}", update.transcript());

    assert!(serde_dir.is_dir(), "expected serde baseline dir to remain");
    assert!(
        !serde_dir.join("0.0.0.json").exists(),
        "expected stale serde version to be pruned"
    );
    assert!(
        !removed_dir.exists(),
        "expected removed crate baseline dir to be pruned"
    );
}

/// A crate with no baseline is reported as a new dependency, named, and with
/// the capabilities that make the report worth reading.
///
/// Both fragments are required. `capabilities:` is the detail of exactly one
/// finding level, but a report that named no package would still carry it.
fn assert_reports_new_dependency(verify: &Completed) {
    for fragment in ["[cargo] serde@", "capabilities:"] {
        assert!(
            verify.stdout.contains(fragment),
            "the report must carry {fragment:?}: {}",
            verify.transcript()
        );
    }
}
