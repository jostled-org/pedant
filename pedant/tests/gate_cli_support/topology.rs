//! Selected-topology journeys: which relationships the fixed selection admits,
//! and which structural rules the admitted topology triggers.
//!
//! Each row spawns the real binary over a real temporary Cargo repository. The
//! exact selected-edge count of a row is read from the consumed owner's own
//! ceiling refusal rather than recomputed here, so no test duplicates the
//! graph's arithmetic.

use crate::fixture::{
    ProjectFixture, ROOT_MANIFEST, boundary_field, crossing_project, json_payload,
    split_module_project,
};

/// One isolated cross-boundary relationship row.
struct RelationRow {
    label: &'static str,
    left: &'static str,
    right: &'static str,
    /// The exact number of edges the fixed selection admits.
    selected_edges: u32,
    /// Every rule that must fire, in output order.
    rules: &'static [&'static str],
}

/// Resolved `Call`, `Import`, `Implementation`, and `Reference` rows, then the
/// rows whose only cross-boundary candidates are excluded.
const RELATION_ROWS: &[RelationRow] = &[
    RelationRow {
        label: "call",
        left: "pub fn item() { crate::right::a(); crate::right::b(); crate::right::c(); crate::right::d(); }\n",
        right: "pub fn a() {}\npub fn b() {}\npub fn c() {}\npub fn d() {}\n",
        selected_edges: 6,
        rules: &["misplaced-symbol", "low-module-cohesion"],
    },
    RelationRow {
        label: "import",
        left: "use crate::right::A;\nuse crate::right::B;\nuse crate::right::C;\nuse crate::right::D;\n",
        right: "pub struct A;\npub struct B;\npub struct C;\npub struct D;\n",
        selected_edges: 6,
        rules: &["low-module-cohesion"],
    },
    RelationRow {
        label: "implementation",
        left: "pub struct L1;\npub struct L2;\npub struct L3;\npub struct L4;\nimpl crate::right::T for L1 {}\nimpl crate::right::T for L2 {}\nimpl crate::right::T for L3 {}\nimpl crate::right::T for L4 {}\n",
        right: "pub trait T {}\n",
        selected_edges: 10,
        rules: &["low-module-cohesion"],
    },
    RelationRow {
        label: "reference",
        left: "pub fn item() -> (crate::right::A, crate::right::B, crate::right::C, crate::right::D) { todo!() }\n",
        right: "pub struct A;\npub struct B;\npub struct C;\npub struct D;\n",
        selected_edges: 6,
        rules: &["misplaced-symbol", "low-module-cohesion"],
    },
    RelationRow {
        label: "possible only",
        left: "pub fn item() { unknown_a(); unknown_b(); unknown_c(); unknown_d(); }\n",
        right: "pub fn a() {}\n",
        selected_edges: 2,
        rules: &[],
    },
];

/// The refusal the selected-edge ceiling states, which is where a row reads the
/// exact count the fixed selection admitted.
fn selected_edge_count(fixture: &ProjectFixture, label: &str) -> u32 {
    fixture.write(".pedant.toml", &boundary_field("max-selected-edges", "0"));
    let refused = fixture.project_gate(&[]);
    fixture.remove(".pedant.toml");
    assert_eq!(
        refused.code(),
        Some(2),
        "{label}: a zero selected-edge ceiling must refuse: {}",
        refused.transcript()
    );
    let marker = "the selection admits ";
    let stated = refused.stderr.split(marker).nth(1).unwrap_or_else(|| {
        panic!(
            "{label}: the refusal states the admitted count: {}",
            refused.stderr
        )
    });
    stated
        .split(' ')
        .next()
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("{label}: the stated count is a number: {stated}"))
}

/// Every rule name a run reported, in output order.
///
/// The names are borrowed from the parsed payload, which the caller keeps
/// alive: a rule name is compared and never stored, so neither this reader nor
/// its callers need to own one.
fn reported_rules(payload: &serde_json::Value) -> Vec<&str> {
    payload["gate_verdicts"]
        .as_array()
        .expect("project mode reports gate_verdicts")
        .iter()
        .map(|verdict| verdict["rule"].as_str().expect("a rule name is a string"))
        .collect()
}

/// The live topology admits exactly the resolved code relations, and excludes
/// `Possible` candidates and dependency edges.
pub(crate) fn structural_rules_follow_resolved_only_evidence() {
    for row in RELATION_ROWS {
        let fixture = split_module_project(row.left, row.right);
        assert_eq!(
            selected_edge_count(&fixture, row.label),
            row.selected_edges,
            "{}: the fixed selection admits an exact edge count",
            row.label
        );
        let run = fixture.project_gate(&["--format", "json"]);
        let payload = json_payload(&run);
        assert_eq!(
            reported_rules(&payload),
            row.rules,
            "{}: exact verdict set, transcript {}",
            row.label,
            run.transcript()
        );
    }

    dependency_edges_contribute_nothing();
    within_partition_cycles_are_clean();
    boundary_crossing_cycles_fire();
}

/// A declared path dependency mints `DependsOn` edges the selection excludes,
/// so the admitted count is exactly the count without that dependency.
fn dependency_edges_contribute_nothing() {
    let sources: &[(&str, &str)] = &[
        ("src/lib.rs", "pub mod left;\npub mod right;\n"),
        ("src/left.rs", "pub fn item() { crate::right::a(); }\n"),
        ("src/right.rs", "pub fn a() {}\n"),
        (
            "vendor/helper/Cargo.toml",
            "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        ),
        ("vendor/helper/src/lib.rs", "pub fn helper_fn() {}\n"),
    ];
    let with_dependency = ProjectFixture::build(
        &[
            &[(
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nhelper = { path = \"vendor/helper\" }\n",
            )],
            sources,
        ]
        .concat(),
    );
    let without_dependency =
        ProjectFixture::build(&[&[("Cargo.toml", ROOT_MANIFEST)], sources].concat());
    let admitted = selected_edge_count(&without_dependency, "no dependency");
    assert!(
        admitted > 0,
        "the corpus must admit edges for the comparison to mean anything"
    );
    assert_eq!(
        selected_edge_count(&with_dependency, "dependency"),
        admitted,
        "a dependency edge must not enter the selected topology"
    );
}

/// The exact number of edges the within-partition cycle corpus admits.
const WITHIN_PARTITION_EDGES: u32 = 3;

/// A cycle wholly inside one declared partition is not a boundary crossing.
///
/// The admitted count is required first: an empty verdict list is also what a
/// corpus that built no cycle, or no edge at all, would produce.
fn within_partition_cycles_are_clean() {
    let fixture = ProjectFixture::build(&[
        ("Cargo.toml", ROOT_MANIFEST),
        ("src/lib.rs", "pub mod inner;\n"),
        ("src/inner.rs", "pub fn a() { b(); }\npub fn b() { a(); }\n"),
    ]);
    assert_eq!(
        selected_edge_count(&fixture, "within partition"),
        WITHIN_PARTITION_EDGES,
        "the corpus admits its exact edge count before any verdict is read"
    );
    let run = fixture.project_gate(&["--format", "json"]);
    assert!(run.success(), "a clean cycle failed: {}", run.transcript());
    let payload = json_payload(&run);
    assert!(
        reported_rules(&payload).is_empty(),
        "a same-partition cycle produces no verdict: {}",
        run.stdout
    );
}

/// A cycle across two declared partitions is denied, and a nine-member cycle
/// exceeds the default `large-scc` ceiling.
fn boundary_crossing_cycles_fire() {
    let crossing = crossing_project();
    let run = crossing.project_gate(&["--format", "json"]);
    assert_eq!(
        run.code(),
        Some(1),
        "a denied crossing exits 1: {}",
        run.transcript()
    );
    let denied = json_payload(&run);
    assert!(
        reported_rules(&denied).contains(&"boundary-crossing-scc"),
        "a multi-partition cycle is denied: {}",
        run.stdout
    );

    let ring = ProjectFixture::build(&[
        ("Cargo.toml", ROOT_MANIFEST),
        ("src/lib.rs", "pub mod ring;\n"),
        ("src/ring.rs", &nine_member_ring()),
    ]);
    let large = ring.project_gate(&["--format", "json"]);
    let reported = json_payload(&large);
    assert!(
        reported_rules(&reported).contains(&"large-scc"),
        "nine cyclic members exceed the default ceiling: {}",
        large.stdout
    );
}

fn nine_member_ring() -> String {
    (0..9)
        .map(|at| format!("pub fn f{at}() {{ f{}(); }}\n", (at + 1) % 9))
        .collect()
}
