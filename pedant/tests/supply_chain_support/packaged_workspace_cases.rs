//! Lifecycle contract of the tracked packaged-workspace release proof.
//!
//! `.github/scripts/check_packaged_workspace.sh` clones the repository, builds
//! two pinned tools, lets release-plz stage eight versions, packages every
//! member, and compiles the extracted archives against each other. The indexed
//! proof runs that against the real registry and the real Cargo; nothing about
//! it is cheap, and nothing about it is deterministic enough to state what
//! happens when a package step exits 3, when a volume fills mid-install, or
//! when the operator presses Ctrl-C.
//!
//! That is what this tree owns. [`row`] installs the fake tools and runs one
//! row, [`verdict`] states what a finished row must show, and this module holds
//! the lifecycle claims: the script's own status, the order it drove the tools
//! in, the target root every Cargo call inherited, no process of one row
//! surviving into the next, and a temporary directory holding no proof-owned
//! staging root. The other two
//! questions a release proof raises have the same shape and a module each —
//! [`graph_cases`] for what the packaged graph must refuse, [`budget_cases`]
//! for what the run is allowed to cost.
//!
//! A row selects its stage the way an operator does, through the argument list.
//! Two words build one pinned tool and stop, none runs the release proof, and
//! anything else has to be refused before a tool runs — so the tool stage is
//! driven here rather than left to the two indexed commands that call it.

/// The repository, staged tree, and fake tools every row is given. Same
/// `#[path]` reason as the modules `supply_chain.rs` declares.
#[path = "packaged_workspace_support/fixture.rs"]
mod fixture;

/// One row's root, and the fault its fake tools carry. Same `#[path]` reason.
#[path = "packaged_workspace_support/row.rs"]
mod row;

/// What every finished row must show. Same `#[path]` reason.
#[path = "packaged_workspace_support/verdict.rs"]
mod verdict;

/// Linux `/bin/sh` does not guarantee that `exec` can dispatch the `command`
/// shell builtin. The budget fakes must delegate through the builtin itself,
/// or every packaged-workspace row exits 127 before reaching its subject.
#[test]
fn fake_budget_tools_do_not_exec_a_shell_builtin() {
    for (name, source) in [("date", fixture::FAKE_DATE), ("du", fixture::FAKE_DU)] {
        assert!(
            !source.contains("exec command"),
            "the fake {name} tool must not exec the command builtin"
        );
        assert!(
            source.contains(&format!("command -p {name}")),
            "the fake {name} tool must delegate through the portable command builtin"
        );
    }
}

/// The packaged graphs the proof has to refuse. Same `#[path]` reason.
#[path = "packaged_workspace_support/graph_cases.rs"]
mod graph_cases;

/// What the proof is allowed to cost, and which budget says so. Same `#[path]`
/// reason.
#[path = "packaged_workspace_support/budget_cases.rs"]
mod budget_cases;

use crate::cargo_classifier_cases::INFRASTRUCTURE_MATCHES;
use fixture::{FIRST_PARTY_EDGES, RELEASE_ORDER, STAGED_VERSION, staged_manifest};
use row::{Fault, ORDINARY_STATUS, PINNED_BINARIES, RowRoot};
use verdict::{
    INFRASTRUCTURE_STATUS, SIGNALLED_STATUS, assert_refusal, assert_refused_before_anything_ran,
    assert_row_is_clean, assert_stated_cost_shape, expected_operations, tool_stage_operations,
    warm_the_tool_root,
};

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
#[test]
fn packaged_workspace_cleanup_is_bounded_on_success_failure_infrastructure_and_interrupt() {
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

/// Every unreleaseable packaged graph is refused before compilation begins.
#[test]
fn packaged_graph_refuses_every_unreleaseable_shape() {
    graph_cases::verify_packaged_graph_refusals();
}

/// 14.T3 (Invariant 25): a release whose dependency graph holds an optional,
/// feature-gated edge is staged, packaged, and resolved from the archives, in
/// the order that edge forces.
///
/// The released workspace grew one such edge, and it is why `pedant-syntax`
/// releases before `pedant-core`. What that costs is invisible in this
/// repository until publication: Cargo replaces the path edge with a registry
/// edge while packaging an optional dependency exactly as it does an
/// unconditional one, so a consumer released before its dependency asks
/// crates.io for a version that does not exist yet.
///
/// This row drives the whole protocol against tools that compile nothing, and
/// claims nothing about compilation — the indexed packaged-workspace proof owns
/// that. What it owns is the four documents between the release and the
/// archives: the order, the manifests the archives carry, the workspace those
/// archives are resolved in, and the caller's own repository.
#[test]
fn packaged_workspace_go_dependency_order_models_release_protocol() {
    let root = RowRoot::new();
    let label = "the dependency-ordered release protocol";
    let completed = root.run(&Fault::None);

    assert_row_is_clean(&root, label, &completed, 0, PINNED_BINARIES);
    assert_release_order_precedes_every_consumer(label);
    assert_archives_carry_the_staged_release(&root, label);
    assert_archive_workspace_answers_for_every_inbound_edge(&root, label);
}

/// Every dependency is released before the package that requires it, whether or
/// not a feature selects the edge, and the model still holds the gated one.
///
/// The second reading is what stops the first from going quiet. An order check
/// over a fixture whose edges had all become unconditional would keep passing
/// while the shape this predicate exists for was gone.
fn assert_release_order_precedes_every_consumer(label: &str) {
    let position = |name: &str| {
        RELEASE_ORDER
            .iter()
            .position(|released| *released == name)
            .unwrap_or_else(|| panic!("{label}: the release order does not name {name}"))
    };
    for (consumer, dependency, _) in FIRST_PARTY_EDGES {
        assert!(
            position(dependency) < position(consumer),
            "{label}: {dependency} must be released before {consumer}"
        );
    }
    assert_eq!(
        FIRST_PARTY_EDGES
            .iter()
            .filter(|(_, _, gated)| *gated)
            .count(),
        1,
        "{label}: the fixture models exactly one optional, feature-gated edge"
    );
}

/// The eight archives are the staged release, and each carries the exact
/// manifest release-plz staged for it.
///
/// The manifest is compared whole rather than by version, because the
/// requirement is the other half of the same claim: an archive that carried the
/// staged version while still requiring a dependency's previous one is the
/// failure a registry publication reports and this repository cannot.
fn assert_archives_carry_the_staged_release(root: &RowRoot, label: &str) {
    let expected: Box<[Box<str>]> = RELEASE_ORDER
        .iter()
        .map(|name| format!("{name}-{STAGED_VERSION}.crate").into())
        .collect();
    assert_eq!(
        root.archives(),
        expected,
        "{label}: the packaging left archives other than this release's"
    );
    for name in RELEASE_ORDER {
        assert_eq!(
            root.packaged_manifest(name, STAGED_VERSION),
            staged_manifest(name),
            "{label}: the {name} archive carries a manifest release-plz never staged"
        );
    }
}

/// The generated workspace compiles the extracted archives and patches every
/// package something in it requires, so no first-party requirement is left for
/// crates.io to answer.
///
/// The patch table is read as the whole table rather than searched for entries.
/// A missing entry lets a first-party requirement resolve from the registry,
/// which is the failure this proof exists for; an extra one redirects a
/// requirement nothing states, which Cargo reports as an unused patch and the
/// proof refuses.
fn assert_archive_workspace_answers_for_every_inbound_edge(root: &RowRoot, label: &str) {
    let manifest = root.archive_manifest();
    for name in RELEASE_ORDER {
        assert!(
            manifest.contains(&format!("\"{name}-{STAGED_VERSION}\",")),
            "{label}: the archive workspace omits the {name} member"
        );
    }
    let patched: Box<[&str]> = manifest
        .lines()
        .filter_map(|line| line.split_once(" = { path = "))
        .map(|(name, _)| name)
        .collect();
    let inbound: Box<[&str]> = RELEASE_ORDER
        .iter()
        .copied()
        .filter(|name| {
            FIRST_PARTY_EDGES
                .iter()
                .any(|(_, dependency, _)| dependency == name)
        })
        .collect();
    assert_eq!(
        patched, inbound,
        "{label}: the archive workspace patches the wrong set of first-party packages"
    );
    for name in inbound {
        assert!(
            manifest.contains(&format!(
                "{name} = {{ path = \"{name}-{STAGED_VERSION}\" }}"
            )),
            "{label}: {name} is patched to something other than its extracted archive"
        );
    }
}

/// The packaged proof selects its warm budget and refuses every overrun.
#[test]
fn packaged_workspace_budget_selects_state_and_refuses_every_overrun() {
    budget_cases::verify_packaged_workspace_budgets();
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
        root.operations(),
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
        root.operations(),
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
