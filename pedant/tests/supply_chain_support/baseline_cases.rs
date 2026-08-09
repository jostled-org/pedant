//! Baselines: what an attestation persists, what a re-run prunes, and what an
//! older persisted document must still mean.

use crate::baseline_store::VendoredWorkspace;
use crate::fixtures::{VendorFixture, manifest, manifest_with_msrv, write, write_library_crate};
use crate::process_guard::Completed;

/// A baseline persisted before snapshot-backed attestation recorded a partial
/// analysis. Reading it must still work, and its incompleteness must still
/// suppress a capability claim.
#[test]
fn supply_chain_verify_without_rust_version_keeps_generic_incomplete_message() {
    let fixture = VendorFixture::new();
    write_library_crate(
        &fixture.crate_dir("legacy-partial"),
        &manifest("legacy-partial", "0.2.0"),
        "pub fn api() {}\n",
    );
    write(
        &fixture.baselines().path_for("legacy-partial", "0.1.0"),
        legacy_partial_baseline("legacy-partial", None),
    );

    let verify = fixture.supply_chain("verify");
    assert!(
        verify.stdout.contains("capability comparison skipped"),
        "a persisted partial analysis must still suppress the diff: {}",
        verify.transcript()
    );
    assert!(
        verify.stdout.contains("analyzed=0 skipped=1"),
        "expected the persisted summary: {}",
        verify.transcript()
    );
    assert!(
        !verify.stdout.contains("rust-version"),
        "no MSRV was recorded, so none may be reported: {}",
        verify.transcript()
    );
}

/// The MSRV both sides of a skipped comparison recorded reaches the report, so
/// a reader can tell which toolchain each document was written for.
#[test]
fn supply_chain_verify_reports_the_msrv_of_both_sides_of_a_skipped_comparison() {
    let fixture = VendorFixture::new();
    write_library_crate(
        &fixture.crate_dir("legacy-msrv"),
        &manifest_with_msrv("legacy-msrv", "0.2.0", "1.70"),
        "pub fn api() {}\n",
    );
    write(
        &fixture.baselines().path_for("legacy-msrv", "0.1.0"),
        legacy_partial_baseline("legacy-msrv", Some("1.65")),
    );

    let verify = fixture.supply_chain("verify");
    for fragment in [
        "capability comparison skipped",
        "rust-version=1.65",
        "rust-version=1.70",
    ] {
        assert!(
            verify.stdout.contains(fragment),
            "the summary must carry {fragment:?}: {}",
            verify.transcript()
        );
    }
}

/// An analysis that could not be completed is not capability drift, so the
/// threshold that fails on drift reports it and still exits clean.
#[test]
fn supply_chain_verify_fail_on_new_capability_passes_over_incomplete_analysis() {
    let fixture = VendorFixture::new();
    write_library_crate(
        &fixture.crate_dir("threshold-partial"),
        &manifest("threshold-partial", "0.2.0"),
        "pub fn api() {}\n",
    );
    write(
        &fixture.baselines().path_for("threshold-partial", "0.1.0"),
        legacy_partial_baseline("threshold-partial", None),
    );

    let verify = verify_failing_on_new_capability(&fixture);
    assert!(
        verify.success(),
        "an incomplete analysis sits below the new-capability threshold: {}",
        verify.transcript()
    );
    assert!(
        verify.stdout.contains("capability comparison skipped"),
        "the run must still say why it could not compare: {}",
        verify.transcript()
    );
    assert!(
        !verify.stdout.contains("new capabilities"),
        "a comparison that was skipped may claim no drift: {}",
        verify.transcript()
    );
}

/// An upgrade that reaches the filesystem where the prior version did not is
/// capability drift, and the threshold that names it must fail on it.
#[test]
fn supply_chain_verify_fail_on_new_capability_fails_on_a_gained_capability() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("capability-growth");
    write_library_crate(
        &crate_dir,
        &manifest("capability-growth", "0.1.0"),
        "pub fn api() {}\n",
    );

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    write(
        &crate_dir.join("Cargo.toml"),
        manifest("capability-growth", "0.2.0"),
    );
    write(
        &crate_dir.join("src/lib.rs"),
        "use std::fs;\npub fn api() { let _ = fs::metadata(\".\"); }\n",
    );

    let verify = verify_failing_on_new_capability(&fixture);
    assert_eq!(
        verify.code(),
        Some(1),
        "a gained capability must fail the run: {}",
        verify.transcript()
    );
    for fragment in [
        "capability-growth@0.2.0",
        "upgraded from 0.1.0",
        "new capabilities: file_read",
    ] {
        assert!(
            verify.stdout.contains(fragment),
            "the report must carry {fragment:?}: {}",
            verify.transcript()
        );
    }
}

/// Verify at the threshold that fails on capability drift and nothing weaker.
fn verify_failing_on_new_capability(fixture: &VendorFixture) -> Completed {
    fixture.run(&[
        "supply-chain",
        "verify",
        "--baseline-path",
        fixture.baselines().argument(),
        "--fail-on",
        "new-capability",
    ])
}

/// A baseline in the shape written before snapshot-backed attestation existed:
/// a partial analysis, and whatever MSRV context the document carried.
///
/// A document that recorded no MSRV omits the key rather than writing null,
/// because that is how the documents already on disk are written.
fn legacy_partial_baseline(crate_name: &str, rust_version: Option<&str>) -> String {
    let mut document = serde_json::json!({
      "spec_version": "0.1.0",
      "source_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "crate_name": crate_name,
      "crate_version": "0.1.0",
      "analysis_tier": "syntactic",
      "timestamp": 1,
      "analysis_completeness": {
        "analyzed_files": 0,
        "skipped_files": 1,
        "skipped_paths": ["./src/lib.rs"],
        "skipped_details": [{"path": "./src/lib.rs", "error": "expected `;`"}]
      },
      "profile": { "findings": [] }
    });
    if let Some(version) = rust_version {
        document["rust_version"] = serde_json::json!(version);
    }
    document.to_string()
}

#[test]
fn debug_package_ignores_invalid_unreachable_src_file() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("test-lib");
    write_library_crate(
        &crate_dir,
        &manifest("test-lib", "0.1.0"),
        "pub fn hello() {}\n",
    );
    write(&crate_dir.join("src/minicore.rs"), "b'\n");

    let debug = fixture.debug_package("test-lib");
    let stderr = debug.stderr.as_ref();
    assert!(stderr.contains("debug-package: test-lib@"), "{stderr}");
    assert!(stderr.contains("file: ./src/lib.rs"), "{stderr}");
    assert!(!stderr.contains("minicore"), "{stderr}");
}

#[test]
fn debug_package_includes_reachable_nested_modules_from_entry_file() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("test-nested");
    write_library_crate(
        &crate_dir,
        &manifest("test-nested", "0.1.0"),
        "mod nested;\npub fn hello() {}\n",
    );
    write(
        &crate_dir.join("src/nested/mod.rs"),
        "mod leaf;\npub fn mid() {}\n",
    );
    write(&crate_dir.join("src/nested/leaf.rs"), "pub fn deep() {}\n");

    let debug = fixture.debug_package("test-nested");
    let stderr = debug.stderr.as_ref();
    assert!(stderr.contains("debug-package: test-nested@"), "{stderr}");
    assert!(stderr.contains("file: ./src/lib.rs"), "{stderr}");
    assert!(stderr.contains("file: ./src/nested/mod.rs"), "{stderr}");
    assert!(stderr.contains("file: ./src/nested/leaf.rs"), "{stderr}");
}

#[test]
fn debug_package_includes_autobin_entrypoints_without_scanning_entire_src_tree() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("test-bins");
    write(
        &crate_dir.join("Cargo.toml"),
        manifest("test-bins", "0.1.0"),
    );
    write(&crate_dir.join("src/main.rs"), "fn main() {}\n");
    write(&crate_dir.join("src/bin/tool.rs"), "fn main() {}\n");
    write(&crate_dir.join("src/fixture.rs"), "b'\n");

    let debug = fixture.debug_package("test-bins");
    let stderr = debug.stderr.as_ref();
    assert!(stderr.contains("debug-package: test-bins@"), "{stderr}");
    assert!(stderr.contains("file: ./src/main.rs"), "{stderr}");
    assert!(stderr.contains("file: ./src/bin/tool.rs"), "{stderr}");
    assert!(!stderr.contains("fixture"), "{stderr}");
}

#[test]
fn verify_ignores_invalid_unreachable_src_file() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("test-verify");
    write_library_crate(
        &crate_dir,
        &manifest("test-verify", "0.1.0"),
        "mod inner;\npub fn api() {}\n",
    );
    write(&crate_dir.join("src/inner/mod.rs"), "pub fn helper() {}\n");
    write(&crate_dir.join("src/broken_fixture.rs"), "b'\n");

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    let verify = fixture.supply_chain("verify");
    assert!(verify.success(), "verify failed: {}", verify.transcript());
    assert!(
        verify.stdout.contains("All dependencies match baselines."),
        "{}",
        verify.transcript()
    );
    assert!(
        !verify.stderr.contains("broken_fixture"),
        "{}",
        verify.transcript()
    );
}

#[test]
fn init_and_verify_round_trip_uses_only_reachable_files() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("round-trip");
    write_library_crate(
        &crate_dir,
        &manifest("round-trip", "0.2.0"),
        "mod sub;\npub fn entry() {}\n",
    );
    write(&crate_dir.join("src/sub/mod.rs"), "pub fn leaf() {}\n");
    write(&crate_dir.join("src/orphan.rs"), "b'\n");

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());
    assert!(
        fixture
            .baselines()
            .path_for("round-trip", "0.2.0")
            .is_file(),
        "expected a baseline for round-trip 0.2.0"
    );

    let verify = fixture.supply_chain("verify");
    assert!(verify.success(), "verify failed: {}", verify.transcript());
    assert!(
        verify.stdout.contains("All dependencies match baselines."),
        "{}",
        verify.transcript()
    );

    let debug = fixture.debug_package("round-trip");
    let stderr = debug.stderr.as_ref();
    assert!(stderr.contains("file: ./src/lib.rs"), "{stderr}");
    assert!(stderr.contains("file: ./src/sub/mod.rs"), "{stderr}");
    assert!(!stderr.contains("orphan"), "{stderr}");
}

#[test]
fn supply_chain_init_persists_rust_version_in_baseline() {
    let fixture = VendorFixture::new();
    write_library_crate(
        &fixture.crate_dir("with-msrv"),
        &manifest_with_msrv("with-msrv", "0.1.0", "1.70"),
        "pub fn api() {}\n",
    );

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    let baseline = fixture.baselines().read("with-msrv", "0.1.0");
    assert_eq!(baseline.rust_version.as_deref(), Some("1.70"));
    assert!(!baseline.source_hash.is_empty());
    let completeness = baseline
        .analysis_completeness
        .as_ref()
        .expect("a snapshot-backed attestation records its completeness");
    assert!(completeness.skipped_details.is_empty());
}

#[test]
fn supply_chain_init_omits_rust_version_when_absent_from_manifest() {
    let fixture = VendorFixture::new();
    write_library_crate(
        &fixture.crate_dir("no-msrv"),
        &manifest("no-msrv", "0.1.0"),
        "pub fn api() {}\n",
    );

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    let raw = std::fs::read_to_string(fixture.baselines().path_for("no-msrv", "0.1.0")).unwrap();
    assert!(
        !raw.contains("rust_version"),
        "baseline JSON should omit rust_version when the manifest has none: {raw}"
    );
}

#[test]
fn supply_chain_verify_debug_package_reports_rust_version() {
    let fixture = VendorFixture::new();
    write_library_crate(
        &fixture.crate_dir("debug-msrv"),
        &manifest_with_msrv("debug-msrv", "0.1.0", "1.70"),
        "pub fn api() {}\n",
    );

    let debug = fixture.debug_package("debug-msrv");
    let stderr = debug.stderr.as_ref();
    assert!(stderr.contains("debug-package: debug-msrv@"), "{stderr}");
    assert!(stderr.contains("rust-version: 1.70"), "{stderr}");
    assert!(
        stderr.contains("analysis: analyzed_files=1 skipped_files=0"),
        "{stderr}"
    );
}

#[test]
fn update_prunes_and_rehashes_using_reachable_file_set() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("evolving");
    write_library_crate(
        &crate_dir,
        &manifest("evolving", "0.1.0"),
        "pub fn v1() {}\n",
    );
    write(&crate_dir.join("src/junk.rs"), "b'\n");

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());
    assert!(fixture.baselines().path_for("evolving", "0.1.0").is_file());

    write(&crate_dir.join("Cargo.toml"), manifest("evolving", "0.2.0"));
    write(
        &crate_dir.join("src/lib.rs"),
        "mod extra;\npub fn v2() {}\n",
    );
    write(&crate_dir.join("src/extra/mod.rs"), "pub fn added() {}\n");

    let update = fixture.supply_chain("update");
    assert!(update.success(), "update failed: {}", update.transcript());
    assert!(
        !fixture.baselines().path_for("evolving", "0.1.0").exists(),
        "stale v0.1.0 baseline should be pruned"
    );
    assert!(
        fixture.baselines().path_for("evolving", "0.2.0").is_file(),
        "expected v0.2.0 baseline"
    );

    let verify = fixture.supply_chain("verify");
    assert!(
        verify.success(),
        "verify after update failed: {}",
        verify.transcript()
    );
    assert!(
        verify.stdout.contains("All dependencies match baselines."),
        "{}",
        verify.transcript()
    );
}

/// A workspace that resolves several versions of one crate (common transitively,
/// e.g. getrandom 0.2/0.3/0.4) must keep an exact baseline for every resolved
/// version after `update`. Regression for the prune_stale_baselines map that
/// keyed on crate name alone and so retained only one version. Closes #60.
#[test]
fn update_retains_concurrent_versions_of_one_crate() {
    let fixture = VendorFixture::new();
    for version in ["0.2.17", "0.4.3"] {
        write_library_crate(
            &fixture.crate_dir(&format!("dup-{version}")),
            &manifest("dup", version),
            "pub fn f() {}\n",
        );
    }

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());
    assert!(
        fixture.baselines().path_for("dup", "0.2.17").is_file()
            && fixture.baselines().path_for("dup", "0.4.3").is_file(),
        "init must write both versions"
    );

    let update = fixture.supply_chain("update");
    assert!(update.success(), "update failed: {}", update.transcript());
    assert!(
        fixture.baselines().path_for("dup", "0.2.17").is_file(),
        "update pruned the concurrent version dup@0.2.17, losing its exact-hash baseline"
    );
    assert!(
        fixture.baselines().path_for("dup", "0.4.3").is_file(),
        "update pruned the concurrent version dup@0.4.3, losing its exact-hash baseline"
    );
}
