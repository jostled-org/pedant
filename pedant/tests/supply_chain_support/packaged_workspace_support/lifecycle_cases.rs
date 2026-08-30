//! What one packaged-workspace row must do on every path out of it.
//!
//! The claims are the script's own status, the order it drove the tools in, the
//! target root every Cargo call inherited, no process of one row surviving into
//! the next, and a temporary directory holding no proof-owned staging root —
//! held over a clean run, an ordinary failure, every infrastructure signature
//! the tracked classifier states, and an interrupt.
//!
//! A row selects its stage the way an operator does, through the argument list.
//! After one required repository root, two words build one pinned tool and
//! stop, no words run the release proof, and anything else has to be refused
//! before a tool runs — so the tool stage is driven here rather than left to
//! the two indexed commands that call it.

use super::row::{Fault, ORDINARY_STATUS, PINNED_BINARIES, RowRoot};
use super::verdict::{
    INFRASTRUCTURE_STATUS, SIGNALLED_STATUS, assert_refusal, assert_refused_before_anything_ran,
    assert_row_is_clean, assert_stated_cost_shape, expected_operations, tool_stage_operations,
    warm_the_tool_root,
};
use crate::cargo_classifier_cases::INFRASTRUCTURE_MATCHES;

/// An argument list that names a tool stage and then keeps talking.
const OVERLONG_STAGE: &[&str] = &[
    "--install-tools",
    "cargo-semver-checks",
    "--and-skip-the-check",
];

/// A two-word argument list naming a tool this proof does not pin.
///
/// A near miss rather than nonsense, because the name a caller gets wrong is
/// the one that looks right.
const UNKNOWN_TOOL_STAGE: &[&str] = &["--install-tools", "cargo-semver-checksum"];

/// How many signatures the classifier states, so a table that lost a row is a
/// failure rather than a shorter loop.
///
/// Two tables meet here and equality between them is not the claim: emptying
/// the one that lives in [`crate::cargo_classifier_cases`] would leave the two
/// agreeing and every row below unrun.
const INFRASTRUCTURE_SIGNATURES: usize = 9;

/// Which Cargo operation carries each signature, so classification is proved at
/// every stage the script runs rather than only at the cheapest one.
const INFRASTRUCTURE_OPERATIONS: &[&str] = &[
    "install",
    "package",
    "metadata",
    "generate-lockfile",
    "check",
    "install",
    "package",
    "metadata",
    "check",
];

/// The packaged-workspace proof keeps an ordinary failure, reclassifies every
/// infrastructure signature, honours TERM, and leaves nothing behind on any of
/// them.
pub(super) fn verify_bounded_cleanup() {
    successful_proof_drives_every_operation_in_order(&RowRoot::new());
    tool_stage_builds_only_the_tool_it_was_named(&RowRoot::new());
    overlong_stage_is_refused_before_anything_runs(&RowRoot::new());
    unknown_tool_name_is_refused_before_anything_runs(&RowRoot::new());
    ordinary_failure_keeps_its_status(&RowRoot::new());
    assert_eq!(
        INFRASTRUCTURE_MATCHES.len(),
        INFRASTRUCTURE_SIGNATURES,
        "every classifier signature must still be stated"
    );
    assert_eq!(
        INFRASTRUCTURE_OPERATIONS.len(),
        INFRASTRUCTURE_SIGNATURES,
        "every classifier signature must still have a row"
    );
    for (sample, operation) in INFRASTRUCTURE_MATCHES
        .iter()
        .copied()
        .zip(INFRASTRUCTURE_OPERATIONS.iter().copied())
    {
        infrastructure_signature_is_reclassified(&RowRoot::new(), sample, operation);
    }
    signalled_proof_leaves_with_its_signal(&RowRoot::new());
}

/// A clean run installs both pinned tools, proves their versions, stages the
/// release, packages all eight members, and compiles the archive workspace — in
/// that order, and with the inherited target root on every Cargo call.
fn successful_proof_drives_every_operation_in_order(root: &RowRoot) {
    let label = "a clean packaged-workspace proof";
    let fault = Fault::None;
    let completed = root.run(&fault);

    assert_row_is_clean(root, label, &completed, 0, fault.surviving_tool_builds());
    assert_eq!(
        root.record().operations(),
        expected_operations(),
        "{label}: the proof drove the tools in the wrong order"
    );
    assert_stated_cost_shape(label, &completed, "verify", "cold");
}

/// The tool stage builds the one tool it was named, proves that build's
/// version, states what it cost, and stages no release.
///
/// The stage exists because both tool builds together outrun the verification
/// slice the release proof has to fit in, so what it must not do is as
/// important as what it must: a stage that installed the pair would put the run
/// back over the slice, and one that went on to stage the release would spend
/// the slice twice.
fn tool_stage_builds_only_the_tool_it_was_named(root: &RowRoot) {
    let label = "a tool stage naming cargo-semver-checks";
    let fault = Fault::None;
    let completed = root.run_stage(&fault, &["--install-tools", "cargo-semver-checks"]);

    assert_row_is_clean(root, label, &completed, 0, &["cargo-semver-checks"]);
    assert_eq!(
        root.record().operations(),
        tool_stage_operations("cargo-semver-checks"),
        "{label}: the tool stage must build and prove one tool, and nothing else"
    );
    assert_stated_cost_shape(label, &completed, "install", "cold");
}

/// A stage invocation that keeps talking past its two words is refused before
/// any tool runs.
///
/// The argument list is the whole request. A proof that read only the first
/// word would install one tool for a caller that asked for something else
/// entirely, and answer zero to a question it never looked at.
fn overlong_stage_is_refused_before_anything_runs(root: &RowRoot) {
    let label = "a tool stage carrying a third argument";
    let completed = root.run_stage(&Fault::None, OVERLONG_STAGE);

    assert_refused_before_anything_ran(root, label, &completed, &[]);
    assert_refusal(
        label,
        &completed,
        "unknown arguments [--install-tools cargo-semver-checks --and-skip-the-check]",
    );
}

/// A tool stage naming a tool this proof does not pin is refused before any
/// state moves.
///
/// The row runs over a target that already holds both pinned builds, because a
/// late refusal is invisible on a cold one. A proof that left the name to the
/// installer would first create its staging root and ask both binaries their
/// versions to read the warm state, and those two probes are recorded; the
/// staging root it made would then be swept by the EXIT trap, leaving the same
/// exit status and the same empty tree as a refusal that read the name where it
/// counted the words. Zero operations is what tells the two apart.
fn unknown_tool_name_is_refused_before_anything_runs(root: &RowRoot) {
    let label = "a tool stage naming a tool the proof does not pin";
    warm_the_tool_root(root);

    let completed = root.run_stage(&Fault::None, UNKNOWN_TOOL_STAGE);

    assert_refused_before_anything_ran(root, label, &completed, PINNED_BINARIES);
    assert_refusal(
        label,
        &completed,
        "unknown arguments [--install-tools cargo-semver-checksum]",
    );
}

/// A Cargo operation that fails for an ordinary reason keeps its exact status,
/// and the proof still releases everything it owns.
fn ordinary_failure_keeps_its_status(root: &RowRoot) {
    let label = "an ordinary packaging failure";
    let fault = Fault::Ordinary {
        operation: "package",
    };
    let completed = root.run(&fault);

    assert_row_is_clean(
        root,
        label,
        &completed,
        ORDINARY_STATUS,
        fault.surviving_tool_builds(),
    );
}

/// Every infrastructure signature leaves through 75, whichever operation wrote
/// it, and takes the staging root with it.
fn infrastructure_signature_is_reclassified(root: &RowRoot, sample: &str, operation: &str) {
    let label: Box<str> = format!("an unavailable machine during {operation}").into();
    let fault = Fault::Infrastructure { operation, sample };
    let completed = root.run(&fault);

    assert_row_is_clean(
        root,
        &label,
        &completed,
        INFRASTRUCTURE_STATUS,
        fault.surviving_tool_builds(),
    );
}

/// A proof that receives TERM leaves with the signal's status and releases the
/// staging root it owns on the way out.
///
/// The interrupted tool orphans a descendant, which is the point: the script
/// leaves that tree to whoever started it, so the guard's teardown is what
/// clears it and the row states only that no such process reaches the next row.
/// What the script itself has to do under TERM is run its trap — status 143 and
/// an empty temporary root, both of which fail when that trap or its cleanup is
/// removed.
fn signalled_proof_leaves_with_its_signal(root: &RowRoot) {
    let label = "an interrupted packaged-workspace proof";
    let fault = Fault::Interrupt {
        operation: "install",
    };
    let completed = root.run(&fault);

    assert_row_is_clean(
        root,
        label,
        &completed,
        SIGNALLED_STATUS,
        fault.surviving_tool_builds(),
    );
}
