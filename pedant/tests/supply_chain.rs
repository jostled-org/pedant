//! Cargo supply-chain journeys through the spawned `pedant` binary.
//!
//! Every child here runs under the guard in `supply_chain_support`, because a
//! `supply-chain` command runs Cargo and Cargo runs a tree of its own. This
//! root states the claims; the support tree owns the fixtures, the tables, and
//! the child lifecycle.

#[path = "package_support/process_guard.rs"]
mod process_guard;

#[path = "supply_chain_support/fake_cargo.rs"]
mod fake_cargo;

#[path = "supply_chain_support/baseline_store.rs"]
mod baseline_store;

#[path = "supply_chain_support/fixtures.rs"]
mod fixtures;

#[path = "supply_chain_support/real_vendor.rs"]
mod real_vendor;

#[path = "supply_chain_support/journey.rs"]
mod journey;

#[path = "supply_chain_support/guard_cases.rs"]
mod guard_cases;

/// The tracked Cargo classifier's runtime contract, exercised through guarded
/// child shells. Same `#[path]` reason as the modules above.
#[path = "supply_chain_support/cargo_classifier_cases.rs"]
mod cargo_classifier_cases;

#[cfg(feature = "resolution-test-support")]
#[path = "supply_chain_support/probe_receipt.rs"]
mod probe_receipt;

/// What an attestation persists and prunes. Same `#[path]` reason as the
/// modules above.
#[path = "supply_chain_support/baseline_cases.rs"]
mod baseline_cases;

#[path = "supply_chain_support/inline_path_cases.rs"]
mod inline_path_cases;

/// Journeys through the real Cargo. Same `#[path]` reason.
#[path = "supply_chain_support/real_cargo_cases.rs"]
mod real_cargo_cases;

use baseline_store::VendoredWorkspace;
use fixtures::{VendorFixture, manifest, manifest_with_msrv, write, write_library_crate};
use pedant_process_guard::run_fixture;
use pedant_types::Capability;

/// Every closure failure the specification calls security-fatal, counted here
/// rather than read off the table. A loop over an emptied or truncated table
/// runs no row and reports clean; counted against what the specification
/// requires, a dropped row fails instead.
const SECURITY_FATAL_FAILURES: usize = 8;

/// The termination paths a guarded child must survive: a clean exit, a budget
/// overrun, and an early Cargo failure. Counted for the same reason.
const GUARDED_TERMINATION_PATHS: usize = 3;

#[test]
fn process_tree_fixture() {
    run_fixture().expect("the process-tree fixture should run");
}

/// The union of a package's primary target closures is exactly what a
/// supply-chain command hashes, and any selected-source failure aborts every
/// command with the baseline store byte-for-byte unchanged.
#[test]
fn supply_chain_snapshot_journey_is_root_only_complete_and_failure_atomic() {
    journey::primary_target_union_is_root_only_and_complete();
    assert_eq!(
        journey::FAILURE_ROWS.len(),
        SECURITY_FATAL_FAILURES,
        "every security-fatal closure failure must still have a row"
    );
    for row in journey::FAILURE_ROWS {
        journey::selected_failure_is_fatal_and_atomic(row);
    }
}

/// A guarded child owns the whole tree Cargo starts, on every exit path.
#[test]
fn supply_chain_process_guard_reaps_descendants_on_success_timeout_and_early_error() {
    assert_eq!(
        guard_cases::GUARD_ROWS.len(),
        GUARDED_TERMINATION_PATHS,
        "every termination path must still have a row"
    );
    for row in guard_cases::GUARD_ROWS {
        guard_cases::guarded_run_leaves_no_descendant(row);
    }
}

/// Capability projection reads the `FileIr` the snapshot already stored, so
/// every selected source is parsed once and projected once.
#[cfg(feature = "resolution-test-support")]
#[test]
fn snapshot_capability_projection_reuses_stored_file_ir() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("reused");
    write_library_crate(
        &crate_dir,
        &manifest("reused", "0.4.0"),
        "mod util;\npub fn api() {}\n",
    );
    write(
        &crate_dir.join("src/main.rs"),
        "mod util;\nfn main() { util::read(); }\n",
    );
    write(
        &crate_dir.join("src/util.rs"),
        "use std::fs;\npub fn read() { let _ = fs::metadata(\".\"); }\n",
    );
    write(&crate_dir.join("build.rs"), "fn main() {}\n");
    let receipt = fixture.script_dir().join("probe-receipt.json");

    let init = fixture.run_with_env(
        &[
            "supply-chain",
            "init",
            "--baseline-path",
            fixture.baselines().argument(),
        ],
        &[(
            probe_receipt::RECEIPT_ENV,
            receipt.to_str().expect("a temporary path"),
        )],
    );
    assert!(init.success(), "init failed: {}", init.transcript());

    let expected_files = [
        ("./build.rs", crate_dir.join("build.rs")),
        ("./src/lib.rs", crate_dir.join("src/lib.rs")),
        ("./src/main.rs", crate_dir.join("src/main.rs")),
        ("./src/util.rs", crate_dir.join("src/util.rs")),
    ];
    probe_receipt::consume(
        &receipt,
        &probe_receipt::Expected {
            name: "reused",
            version: "0.4.0",
            files: &expected_files,
        },
    )
    .unwrap_or_else(|reason| panic!("the child receipt is not acceptable: {reason}"));
    assert!(
        !receipt.exists(),
        "the parent owns the receipt and removes it with the workspace"
    );

    let completeness = fixture
        .baselines()
        .read("reused", "0.4.0")
        .analysis_completeness
        .expect("a snapshot-backed attestation records its completeness");
    assert_eq!(completeness.analyzed_files, 4);
    assert_eq!(completeness.skipped_files, 0);
}

/// Cargo-default Rust 2015 syntax remains analyzable through the spawned
/// supply-chain command, and facts after the repaired alias keep their source
/// coordinates in the persisted attestation.
#[test]
fn supply_chain_accepts_legacy_bare_callable_traits_without_moving_later_facts() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("legacy-callable");
    write_library_crate(
        &crate_dir,
        "[package]\nname = \"legacy-callable\"\nversion = \"0.1.0\"\n",
        "type Action = Fn(&u8) + Send + Sync;\n\
         type MutableAction = FnMut(&u8);\n\
         type OnceAction = FnOnce(&u8);\n\
         use std::net::TcpStream;\n\n\
         pub fn connect() {\n\
             let _socket = TcpStream::connect(\"127.0.0.1:9\");\n\
         }\n",
    );

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    let baseline = fixture.baselines().read("legacy-callable", "0.1.0");
    let finding = baseline
        .profile
        .findings
        .iter()
        .find(|finding| finding.capability == Capability::Network)
        .expect("the later network import remains detectable");
    assert_eq!(finding.location.file.as_ref(), "./src/lib.rs");
    assert_eq!(
        (finding.location.line, finding.location.column),
        (4, 1),
        "compatibility parsing must retain the original source span"
    );
}

/// Workspace-inherited package fields reach the attestation, which a
/// per-manifest reader could never resolve.
#[test]
fn supply_chain_workspace_discovery_uses_project_members_and_validated_versions() {
    let fixture = VendorFixture::new();
    let root = fixture.crate_dir("inherited-dep");
    write(
        &root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\n\n[workspace.package]\nversion = \"2.5.1\"\nrust-version = \"1.70\"\n",
    );
    write_library_crate(
        &root.join("member"),
        "[package]\nname = \"inherited-dep\"\nversion.workspace = true\nrust-version.workspace = true\nedition = \"2024\"\n",
        "pub fn inherited() {}\n",
    );

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    let baseline = fixture.baselines().read("inherited-dep", "2.5.1");
    assert_eq!(baseline.crate_name.as_ref(), "inherited-dep");
    assert_eq!(
        baseline.crate_version.as_ref(),
        "2.5.1",
        "the workspace-inherited version must reach the attestation"
    );
    assert_eq!(
        baseline.rust_version.as_deref(),
        Some("1.70"),
        "the workspace-inherited MSRV must reach the attestation"
    );
}

/// Invalid Rust that belongs to no Cargo target of a vendored workspace stays
/// outside every closure.
#[test]
fn supply_chain_ignores_invalid_fixture_rust_outside_workspace_targets() {
    let fixture = VendorFixture::new();
    let root = fixture.crate_dir("workspace-dep");
    write(
        &root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\n",
    );
    write_library_crate(
        &root.join("member"),
        &manifest("workspace-dep", "0.1.0"),
        "pub fn real_code() {}\n",
    );
    write(
        &root.join("test_data/lexer/err/byte_char_literals.rs"),
        "b'\n",
    );

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());
}

/// Invalid Rust no primary target reaches stays outside the hash, and the
/// attestation it produces is still complete.
#[test]
fn supply_chain_init_and_verify_ignore_unselected_vendored_parse_failures() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("unselected-failure-dep");
    write_library_crate(
        &crate_dir,
        &manifest("unselected-failure-dep", "0.1.0"),
        "pub fn api() {}\n",
    );
    write(
        &crate_dir.join("src/fixture.rs"),
        "#[allow(unknown_lints, bare_trait_objects)]\ntype Action = Fn(&u8) + Send + Sync;\n",
    );

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    let completeness = fixture
        .baselines()
        .read("unselected-failure-dep", "0.1.0")
        .analysis_completeness
        .expect("a snapshot-backed attestation records its completeness");
    assert_eq!(completeness.analyzed_files, 1);
    assert!(
        completeness.skipped_details.is_empty(),
        "an unselected source is excluded, not skipped: {completeness:?}"
    );

    let verify = fixture.supply_chain("verify");
    assert!(verify.success(), "verify failed: {}", verify.transcript());

    let debug = fixture.debug_package("unselected-failure-dep");
    assert!(
        debug
            .stderr
            .contains("analysis: analyzed_files=1 skipped_files=0"),
        "{}",
        debug.transcript()
    );
    assert!(
        !debug.stderr.contains("fixture"),
        "an unselected source must never appear: {}",
        debug.transcript()
    );
}

/// An upgrade whose new sources cannot be closed leaves the prior baseline
/// exactly as it was.
#[test]
fn supply_chain_upgrade_rejects_selected_parse_failure_without_baseline_mutation() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("upgrade-subject");
    write_library_crate(
        &crate_dir,
        &manifest("upgrade-subject", "0.1.0"),
        "pub fn api() {}\n",
    );

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());
    let before = fixture.baselines().bytes();

    write(
        &crate_dir.join("Cargo.toml"),
        manifest("upgrade-subject", "0.2.0"),
    );
    write(&crate_dir.join("src/lib.rs"), "pub fn api( {}\n");

    let update = fixture.supply_chain("update");
    assert_eq!(
        update.code(),
        Some(2),
        "a selected parse failure must be fatal: {}",
        update.transcript()
    );
    assert!(
        update.stderr.contains("is not valid Rust"),
        "{}",
        update.transcript()
    );
    assert_eq!(
        fixture.baselines().bytes(),
        before,
        "a failed update must leave every baseline byte unchanged"
    );
    assert!(
        fixture
            .baselines()
            .path_for("upgrade-subject", "0.1.0")
            .is_file(),
        "the prior version's baseline must survive a failed update"
    );
}

/// The MSRV a prior baseline recorded survives an upgrade that cannot be
/// analyzed, because nothing is rewritten.
#[test]
fn supply_chain_upgrade_preserves_msrv_context_on_selected_parse_failure() {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("msrv-subject");
    write_library_crate(
        &crate_dir,
        &manifest_with_msrv("msrv-subject", "0.1.0", "1.65"),
        "pub fn api() {}\n",
    );

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());
    let before = fixture.baselines().bytes();

    write(
        &crate_dir.join("Cargo.toml"),
        manifest_with_msrv("msrv-subject", "0.2.0", "1.70"),
    );
    write(&crate_dir.join("src/lib.rs"), "mod ghost;\n");

    for command in ["update", "verify"] {
        let run = fixture.supply_chain(command);
        assert_eq!(
            run.code(),
            Some(2),
            "{command} must refuse an unclosable upgrade: {}",
            run.transcript()
        );
        assert_eq!(
            fixture.baselines().bytes(),
            before,
            "{command} mutated the baseline store"
        );
    }

    assert_eq!(
        fixture
            .baselines()
            .read("msrv-subject", "0.1.0")
            .rust_version
            .as_deref(),
        Some("1.65"),
        "the prior MSRV context must survive the refused upgrade"
    );
}
