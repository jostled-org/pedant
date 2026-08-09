//! The written-down acceptance identities, and where they must be mirrored.
//!
//! `.manifest.toml` is local tooling; `.github/workflows/ci.yml` is committed
//! and is what actually runs on a clone. A key whose value only the manifest
//! carries proves nothing about CI, and a script the key names but the
//! repository never commits fails the job on a fresh checkout rather than here.
//! Both facts are modelled below so [`super::authority_acceptance`] can bind
//! them together.

/// The acceptance keys this plan adds or widens, with their exact values.
pub const CI_KEYS: &[(&str, &str)] = &[
    (
        "fmt_process_guard",
        "cargo fmt --manifest-path test-support/process-guard/Cargo.toml --check",
    ),
    (
        "clippy_process_guard",
        "cargo clippy --locked --manifest-path test-support/process-guard/Cargo.toml --all-targets -- -D warnings",
    ),
    (
        "published_manifests",
        "docs/scripts/check_published_manifests.sh",
    ),
    (
        "shellcheck",
        "shellcheck -x docs/scripts/check_*.sh docs/scripts/cargo_infrastructure.sh \
         docs/scripts/verify_step.sh docs/scripts/verify_affected.sh \
         docs/scripts/run_resolution_proof.sh",
    ),
];

/// The `pedant check` prefix the resolution test-coverage key must carry.
pub const RESOLUTION_CHECK_KEY: &str = "pedant_resolution_test_check";

/// The command that key must hold, before its path list.
pub const RESOLUTION_CHECK_PREFIX: &str = "pedant check --format github";

/// Every affected root and `#[path]` support tree, in the key's exact order.
///
/// This is the coverage set, so a helper added to one of these trees is checked
/// by the acceptance run, and a tree dropped from the key fails here.
///
/// A support tree is named whole rather than child by child. Naming two of
/// `substrate_support`'s three files left the third — `declaration_scan.rs` —
/// checked by nothing, and this table would have agreed, because it compares
/// itself with the key rather than with the directory.
///
/// `pedant-mcp/tests/fixture_support` is the one tree named after no single
/// root: four roots of that crate read one committed fixture, and four copies
/// of the path to it were four chances to leave one stale. It is listed here
/// for the same reason as every other tree — a helper nothing checks is the
/// failure this table exists to prevent, and a shared tree is checked by no
/// root's own entry.
pub const RESOLUTION_CHECK_PATHS: &[&str] = &[
    "pedant-types/tests/serialization.rs",
    "pedant-types/tests/serialization_support",
    "pedant-syntax/tests/enclosing_unit.rs",
    "pedant-lang/tests/detection.rs",
    "pedant-lang/tests/capability.rs",
    "pedant-lang/tests/capability_support",
    "pedant-snippet/tests/interfaces.rs",
    "pedant-core/tests/substrate.rs",
    "pedant-core/tests/substrate_support",
    "pedant-core/tests/semantic.rs",
    "pedant-core/tests/semantic_support",
    "pedant/tests/supply_chain.rs",
    "pedant/tests/supply_chain_support",
    "pedant-mcp/tests/index.rs",
    "pedant-mcp/tests/index_support",
    "pedant-mcp/tests/watcher.rs",
    "pedant-mcp/tests/watcher_support",
    "pedant-mcp/tests/tools.rs",
    "pedant-mcp/tests/tools_support",
    "pedant-mcp/tests/integration.rs",
    "pedant-mcp/tests/integration_support",
    "pedant-mcp/tests/fixture_support",
    "test-support/process-guard/src",
];

/// The workflow the manifest keys describe. It is the artifact CI executes, so
/// a manifest value it does not carry is a value no job runs.
pub const WORKFLOW: &str = ".github/workflows/ci.yml";

/// The ignore file that decides whether a named script reaches a clone.
pub const GITIGNORE: &str = ".gitignore";

/// The directory every acceptance-named script lives in. Its contents are
/// ignored wholesale and re-included one file at a time, so a script this
/// repository runs in CI and does not re-include is a script CI cannot read.
pub const SCRIPT_DIRECTORY: &str = "docs/scripts/";

/// The directive `shellcheck -x` follows into a sourced helper. A helper left
/// out of the commit fails the lint exactly as a missing subject would.
pub const SOURCE_DIRECTIVE: &str = "# shellcheck source=";
