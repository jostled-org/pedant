//! The strict Tier 2 project journey.
//!
//! `--semantic` is an explicit request, so project mode either resolves every
//! selected target through one verified context or refuses with exit 2. There
//! is no Tier 1 fallback and no mixed-tier report. Nested Cargo output stays
//! beneath the fixture's own `target/pedant-semantic` path, which the
//! production loader selects.

use std::time::Duration;

use crate::fixture::{ProjectFixture, RunOptions, analyzed_targets, json_payload};
use crate::process_guard::{BUDGET, Completed};

/// A cold rust-analyzer context indexes the discovered sysroot before it can
/// answer the first project query.
const SEMANTIC_BUDGET: Duration = Duration::from_secs(180);

/// A two-target package whose sources rust-analyzer resolves the same way the
/// parse-only tier reads them: plain Rust, LF endings, no conditional module.
const SEMANTIC_CORPUS: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "src/lib.rs",
        "pub mod left;\npub mod right;\n\npub fn run() {\n    left::up();\n}\n",
    ),
    (
        "src/left.rs",
        "pub fn up() {\n    crate::right::down();\n}\n",
    ),
    (
        "src/right.rs",
        "pub fn down() {\n    crate::left::up();\n}\n",
    ),
    ("src/main.rs", "fn main() {\n    demo::run();\n}\n"),
];

/// A repository whose root library declares a module behind a feature.
///
/// The syntactic closure keeps `src/gated.rs`, because Tier 1 evaluates no
/// predicate, while rust-analyzer activates no feature and holds one source for
/// the crate. The two path sets disagree, so the verified Tier 2 handshake
/// refuses before any query runs.
const UNRESOLVABLE_CORPUS: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[features]\nextra = []\n",
    ),
    (
        "src/lib.rs",
        "#[cfg(feature = \"extra\")]\npub mod gated;\n\npub fn run() {}\n",
    ),
    ("src/gated.rs", "pub fn only_with_extra() {}\n"),
];

/// A repository whose manifests Tier 1 reads and rust-analyzer cannot load.
///
/// The declared version requirement is not a semver requirement. Tier 1 reads
/// dependency names, kinds, and in-root paths and never parses that field, so
/// the project loads and selects its library; Cargo refuses the manifest itself,
/// which its dependency-free retry cannot get past either, so the root has no
/// semantic context at all. That is a different refusal from a target whose
/// names could not be resolved against a context that did load.
const UNLOADABLE_CORPUS: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nabsent = \"not-a-version\"\n",
    ),
    ("src/lib.rs", "pub fn run() {}\n"),
];

/// Every selected target is judged at Tier 2 from one context, or the run fails
/// all-target with exit 2 and no syntactic success.
pub(crate) fn semantic_is_single_context_all_target_or_error() {
    assert_eq!(
        BUDGET,
        Duration::from_secs(120),
        "ordinary guarded journeys retain the shared 120-second ceiling"
    );
    assert_eq!(
        RunOptions::default().budget,
        BUDGET,
        "default run options inherit the shared process ceiling"
    );
    assert_eq!(
        SEMANTIC_BUDGET,
        Duration::from_secs(180),
        "only this rust-analyzer-backed journey receives the wider ceiling"
    );
    let options = RunOptions {
        budget: SEMANTIC_BUDGET,
        ..RunOptions::default()
    };
    assert_eq!(
        options.budget, SEMANTIC_BUDGET,
        "the semantic journey applies its localized ceiling"
    );
    let fixture = ProjectFixture::build(SEMANTIC_CORPUS);
    let run = fixture.project_gate_with(&["--semantic", "--format", "json"], &options);
    assert!(
        !run.timed_out(),
        "the Tier 2 journey must finish inside its budget: {}",
        run.transcript()
    );
    let payload = json_payload(&run);
    assert_eq!(
        payload["analysis_tier"], "semantic",
        "an explicit semantic request never reports a syntactic success: {}",
        run.stdout
    );
    assert_eq!(
        analyzed_targets(&payload),
        [".#lib:demo", ".#bin:demo"],
        "every selected target sits under the one semantic summary"
    );

    let refused =
        ProjectFixture::build(UNRESOLVABLE_CORPUS).project_gate_with(&["--semantic"], &options);
    assert_refusal(&refused, "cannot be resolved");

    let unloadable =
        ProjectFixture::build(UNLOADABLE_CORPUS).project_gate_with(&["--semantic"], &options);
    assert_refusal(&unloadable, "has no loadable semantic context");
}

/// A refused Tier 2 request exits 2, names its class, and publishes nothing.
fn assert_refusal(refused: &Completed, expected: &str) {
    assert_eq!(
        refused.code(),
        Some(2),
        "{expected}: a refused Tier 2 request is fatal: {}",
        refused.transcript()
    );
    assert!(
        refused.stderr.contains(expected),
        "{expected}: the refusal names why Tier 2 was not reached: {}",
        refused.stderr
    );
    assert!(
        refused.stdout.is_empty(),
        "{expected}: no partial or syntactic success is published: {}",
        refused.transcript()
    );
}
