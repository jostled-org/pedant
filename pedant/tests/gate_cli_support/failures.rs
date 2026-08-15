//! The buffered exit-2 failure contract: every project, target, snapshot,
//! resolution, graph, and analysis refusal discards every buffered verdict.

use crate::fixture::{
    CROSSING_DOWN, CROSSING_UP, ProjectFixture, RunOptions, boundary_config, json_payload,
    simple_project,
};

/// The second workspace member's sources and the configuration that puts the
/// refusal there, after `alpha` already produced a verdict.
struct LaterTarget {
    /// Writes `beta`'s sources, which is where the refusal must land.
    beta: fn(&ProjectFixture),
    /// The `[gate.module-boundary]` body, when the class needs a ceiling.
    config: Option<&'static str>,
    /// The consumed owner's own words, when one refused.
    refusal: Option<&'static str>,
}

/// How far the run gets before the failure class refuses it.
enum Reach {
    /// The project itself is refused, built from exactly these files.
    Project(&'static [(&'static str, &'static str)]),
    /// A later target is refused, so an earlier verdict has to be discarded.
    Later(LaterTarget),
}

/// One failure class the operator can reach, and the stderr fragment it must
/// state.
struct FailureRow {
    label: &'static str,
    reach: Reach,
    /// The `ProjectGateError` variant this row proves, which the structural
    /// coverage predicate in `ownership.rs` reads back.
    variant: &'static str,
    /// The refusal class, exactly as the owning error spells it.
    expected: &'static str,
}

/// `alpha`'s exact node count, which the graph-capacity ceiling sits on.
///
/// The value is not trusted: the control run below requires `alpha` to be
/// admitted and to publish its deny under this same ceiling, so a count that
/// drifted fails there rather than turning this row into a no-op.
const ALPHA_NODES: &str = "max-nodes = 8";

/// `alpha`'s exact selected-edge count, which the analysis ceiling sits on.
const ALPHA_SELECTED_EDGES: &str = "max-selected-edges = 4";

/// Every failure class, from the two that refuse the project itself to the four
/// that land after an earlier target already produced a verdict.
const FAILURE_ROWS: &[FailureRow] = &[
    FailureRow {
        label: "no primary target",
        reach: Reach::Project(&[("Cargo.toml", "[workspace]\nmembers = []\n")]),
        variant: "NoPrimaryTarget",
        expected: "declares no library, binary, or build-script target",
    },
    FailureRow {
        label: "project load",
        reach: Reach::Project(&[("Cargo.toml", "[package]\nname = \n")]),
        variant: "ProjectLoad",
        expected: "cannot be loaded",
    },
    FailureRow {
        label: "snapshot",
        reach: Reach::Later(LaterTarget {
            beta: write_unsnapshottable_beta,
            config: None,
            refusal: None,
        }),
        variant: "Snapshot",
        expected: "cannot be snapshotted",
    },
    FailureRow {
        label: "syntactic resolution",
        reach: Reach::Later(LaterTarget {
            beta: write_unresolvable_beta,
            config: None,
            refusal: Some("the names imports bind did not settle"),
        }),
        variant: "Resolution",
        expected: "cannot be resolved",
    },
    FailureRow {
        label: "graph capacity",
        reach: Reach::Later(LaterTarget {
            beta: write_wide_beta,
            config: Some(ALPHA_NODES),
            refusal: Some("the node collection cannot exceed"),
        }),
        variant: "GraphBuild",
        expected: "cannot be projected into a graph",
    },
    FailureRow {
        label: "analysis capacity",
        reach: Reach::Later(LaterTarget {
            beta: write_crossing_beta,
            config: Some(ALPHA_SELECTED_EDGES),
            refusal: Some("the selection admits"),
        }),
        variant: "Analysis",
        expected: "cannot be analyzed",
    },
];

/// Every `ProjectGateError` variant the rows above reach, in row order.
pub(crate) fn covered_refusals() -> Vec<&'static str> {
    FAILURE_ROWS.iter().map(|row| row.variant).collect()
}

/// Every failure returns exit 2, names its context, and buffers away every
/// verdict an earlier target could have produced.
pub(crate) fn failures_are_buffered_and_exit_two() {
    for row in FAILURE_ROWS {
        match &row.reach {
            Reach::Project(files) => project_failure_is_fatal(row, files),
            Reach::Later(later) => later_target_failure_discards_earlier_verdicts(row, later),
        }
    }

    missing_project_root_is_fatal();
}

/// The project is refused before any target is judged.
fn project_failure_is_fatal(row: &FailureRow, files: &[(&str, &str)]) {
    let fixture = ProjectFixture::build(files);
    let refused = fixture.project_gate(&["--format", "json"]);
    assert_eq!(
        refused.code(),
        Some(2),
        "{}: must exit 2: {}",
        row.label,
        refused.transcript()
    );
    assert!(
        refused.stdout.is_empty(),
        "{}: no success payload or earlier verdict survives: {}",
        row.label,
        refused.stdout
    );
    assert!(
        refused.stderr.contains(row.expected),
        "{}: contextual refusal, got: {}",
        row.label,
        refused.stderr
    );
}

fn missing_project_root_is_fatal() {
    let fixture = simple_project();
    let absent = fixture.scratch_arg("absent");
    let refused = fixture.gate_with(&["--project", absent.as_str()], &RunOptions::default());
    assert_eq!(
        refused.code(),
        Some(2),
        "an unresolvable root is fatal: {}",
        refused.transcript()
    );
    assert!(
        refused.stderr.contains("cannot be resolved"),
        "the refusal names the root: {}",
        refused.stderr
    );
}

/// `alpha` holds a boundary-crossing cycle, so the first selected target of
/// every row below always has a deny verdict to lose.
fn discard_workspace(later: &LaterTarget, beta: fn(&ProjectFixture)) -> ProjectFixture {
    let fixture = ProjectFixture::build(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"alpha\", \"beta\"]\nresolver = \"3\"\n",
        ),
        (
            "alpha/Cargo.toml",
            "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        ),
        ("alpha/src/lib.rs", "pub mod left;\npub mod right;\n"),
        ("alpha/src/left.rs", CROSSING_UP),
        ("alpha/src/right.rs", CROSSING_DOWN),
        (
            "beta/Cargo.toml",
            "[package]\nname = \"beta\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        ),
    ]);
    if let Some(body) = later.config {
        fixture.write(".pedant.toml", &boundary_config(body));
    }
    beta(&fixture);
    fixture
}

/// The first workspace member produces a verdict; the second refuses, so
/// nothing at all is published.
fn later_target_failure_discards_earlier_verdicts(row: &FailureRow, later: &LaterTarget) {
    earlier_target_really_denies(row, later);

    let fixture = discard_workspace(later, later.beta);
    let refused = fixture.project_gate(&["--format", "json"]);
    assert_eq!(
        refused.code(),
        Some(2),
        "{}: a later failure is fatal: {}",
        row.label,
        refused.transcript()
    );
    assert!(
        refused.stdout.is_empty(),
        "{}: the earlier target's deny verdict must not be published: {}",
        row.label,
        refused.stdout
    );
    assert!(
        refused.stderr.contains("beta#lib:beta") && refused.stderr.contains(row.expected),
        "{}: the refusal names the failing root target and its class: {}",
        row.label,
        refused.stderr
    );
    if let Some(refusal) = later.refusal {
        assert!(
            refused.stderr.contains(refusal),
            "{}: the consumed owner's own refusal reaches stderr: {}",
            row.label,
            refused.stderr
        );
    }
}

/// The same workspace and configuration with a clean second member.
///
/// Without this the discard claim would be untestable: a row whose ceiling
/// silently refused `alpha` instead, or whose `alpha` stopped denying, would
/// still show an exit 2 and an empty stdout.
fn earlier_target_really_denies(row: &FailureRow, later: &LaterTarget) {
    let fixture = discard_workspace(later, write_clean_beta);
    let admitted = fixture.project_gate(&["--format", "json"]);
    assert_eq!(
        admitted.code(),
        Some(1),
        "{}: the earlier target denies under this configuration: {}",
        row.label,
        admitted.transcript()
    );
    let payload = json_payload(&admitted);
    assert_eq!(
        payload["gate_verdicts"][0]["evidence"]["evidence"]["target"], "alpha#lib:alpha",
        "{}: the discarded verdict belongs to the earlier target: {}",
        row.label, admitted.stdout
    );
}

fn write_clean_beta(fixture: &ProjectFixture) {
    fixture.write("beta/src/lib.rs", "pub fn b() {}\n");
}

/// A module declaration with no source behind it.
fn write_unsnapshottable_beta(fixture: &ProjectFixture) {
    fixture.write("beta/src/lib.rs", "mod ghost;\n");
}

/// A re-export chain deeper than the import fixed point's bounded rounds, which
/// is refused rather than reported with unfilled tail bindings.
fn write_unresolvable_beta(fixture: &ProjectFixture) {
    const DEPTH: u32 = 9;
    let declarations: String = (0..=DEPTH).map(|at| format!("pub mod m{at};\n")).collect();
    fixture.write("beta/src/lib.rs", &declarations);
    fixture.write("beta/src/m0.rs", "pub fn leaf() {}\n");
    for at in 1..=DEPTH {
        fixture.write(
            &format!("beta/src/m{at}.rs"),
            &format!("pub use crate::m{}::leaf;\n", at - 1),
        );
    }
}

/// More declarations than the node ceiling `alpha` exactly fills.
fn write_wide_beta(fixture: &ProjectFixture) {
    fixture.write(
        "beta/src/lib.rs",
        "pub mod one;\npub mod two;\npub mod three;\n",
    );
    for module in ["one", "two", "three"] {
        fixture.write(
            &format!("beta/src/{module}.rs"),
            "pub fn f1() {}\npub fn f2() {}\n",
        );
    }
}

/// More cross-boundary calls than the selected-edge ceiling `alpha` exactly
/// fills.
fn write_crossing_beta(fixture: &ProjectFixture) {
    fixture.write("beta/src/lib.rs", "pub mod x;\npub mod y;\n");
    fixture.write(
        "beta/src/x.rs",
        "pub fn item() { crate::y::a(); crate::y::b(); crate::y::c(); crate::y::d(); }\n",
    );
    fixture.write(
        "beta/src/y.rs",
        "pub fn a() {}\npub fn b() {}\npub fn c() {}\npub fn d() {}\n",
    );
}
