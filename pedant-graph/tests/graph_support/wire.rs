//! Tier propagation and the exact version-1 serialized contract.

use pedant_graph::{
    GraphCertainty, GraphCollection, GraphDependencyKind, GraphEdgeKind, GraphReferenceKind,
    build_rust_graph,
};
use pedant_types::{ResolutionGap, ResolutionReport, ResolutionTier};

use super::corpus::MINIMAL_CORPUS;
use super::fixture;
use super::promotion::promoted_resolution;
use super::render;

/// The exact compact serialization of the minimal corpus.
const MINIMAL_JSON: &str = r#"{"schema_version":1,"tier":"syntactic","nodes":[{"id":0,"language":"rust","name":"app","kind":{"category":"container","level":"library"},"location":null},{"id":1,"language":"rust","name":"src/lib.rs","kind":{"category":"file"},"location":{"kind":"file","path":"src/lib.rs"}},{"id":2,"language":"rust","name":"run","kind":{"category":"function","declaration":"function"},"location":{"kind":"span","file":1,"span":{"file":"src/lib.rs","start":{"line":0,"column":7},"end":{"line":0,"column":10}}}},{"id":3,"language":"rust","name":"work","kind":{"category":"function","declaration":"function"},"location":{"kind":"span","file":1,"span":{"file":"src/lib.rs","start":{"line":1,"column":7},"end":{"line":1,"column":11}}}}],"containment":[{"parent":0,"child":1},{"parent":0,"child":2},{"parent":0,"child":3}],"references":[{"id":0,"source":2,"language":"rust","kind":"call","text":"work","span":{"file":"src/lib.rs","start":{"line":0,"column":15},"end":{"line":0,"column":19}},"gaps":[],"edges":[0]}],"edges":[{"id":0,"source":2,"target":3,"kind":"call","certainty":"resolved","origin":{"kind":"reference","reference":0}}]}"#;

/// Every graph-owned object and tag the version-1 contract specifies.
const REQUIRED_FRAGMENTS: &[&str] = &[
    r#"{"category":"file"}"#,
    r#"{"category":"container","level":"library"}"#,
    r#"{"category":"container","level":"module"}"#,
    r#"{"category":"function","declaration":"function"}"#,
    r#"{"category":"function","declaration":"method"}"#,
    r#"{"category":"type","declaration":"struct"}"#,
    r#"{"category":"type","declaration":"enum"}"#,
    r#"{"category":"type","declaration":"union"}"#,
    r#"{"category":"type","declaration":"trait"}"#,
    r#"{"category":"type","declaration":"type_alias"}"#,
    r#"{"category":"value","declaration":"constant"}"#,
    r#"{"category":"value","declaration":"static"}"#,
    r#""location":null"#,
    r#""location":{"kind":"file","path":"src/lib.rs"}"#,
    r#""location":{"kind":"span","file":"#,
    // Every reference-kind token is required twice over, once per object that
    // can carry it: a record states its `text` next, an edge its `certainty`.
    // An unqualified `"kind":"<token>"` fragment is satisfied by either object
    // and by the edge-origin tag, so neither enum would be pinned alone.
    r#""kind":"call","text":"#,
    r#""kind":"import","text":"#,
    r#""kind":"implementation","text":"#,
    r#""kind":"reference","text":"#,
    r#""kind":"call","certainty":"#,
    r#""kind":"import","certainty":"#,
    r#""kind":"implementation","certainty":"#,
    r#""kind":"reference","certainty":"#,
    r#""kind":"depends_on","certainty":"#,
    r#""certainty":"resolved""#,
    r#""certainty":"possible""#,
    r#""gaps":[]"#,
    r#""gaps":["external_definition"]"#,
    r#""edges":[]"#,
    r#""origin":{"kind":"reference","reference":"#,
    r#""origin":{"kind":"dependency","evidence":{"alias":"helper","kind":"normal","predicate":null}}"#,
    r#""origin":{"kind":"dependency","evidence":{"alias":"gated","kind":"normal","predicate":"cfg(unix)"}}"#,
    r#""origin":{"kind":"dependency","evidence":{"alias":"harness","kind":"development","predicate":"cfg(test)"}}"#,
    r#""schema_version":1"#,
    r#""tier":"syntactic""#,
];

/// Every shape only a promoted graph reaches.
const PROMOTED_FRAGMENTS: &[&str] = &[
    r#""tier":"semantic""#,
    r#""gaps":["conditional_compilation"]"#,
    r#""gaps":["missing_definition"]"#,
];

/// Vocabulary a layout or renderer contract would introduce. None may appear.
const LAYOUT_VOCABULARY: &[&str] = &[
    "\"x\"",
    "\"y\"",
    "\"width\"",
    "\"height\"",
    "\"color\"",
    "\"rank\"",
    "\"layout\"",
    "\"position\"",
    "\"style\"",
    "\"shape\"",
    "\"route\"",
    "\"cluster\"",
];

/// Repeated serialization of equal inputs is byte-identical and exact.
pub fn assert_json_is_exact_and_deterministic() {
    let (_fixture, resolved) = fixture::resolve_library(MINIMAL_CORPUS);
    let graph = build_rust_graph(&resolved.snapshot, &resolved.resolution)
        .expect("the minimal corpus projects");
    let first = serde_json::to_string(&graph).expect("the graph serializes");
    let second = serde_json::to_string(&graph).expect("the graph serializes again");
    assert_eq!(first, second, "repeated serialization is byte-identical");
    assert_eq!(first, MINIMAL_JSON, "the version-1 wire shape changed");

    let rebuilt = build_rust_graph(&resolved.snapshot, &resolved.resolution)
        .expect("a second build over equal inputs succeeds");
    assert_eq!(
        serde_json::to_string(&rebuilt).expect("the rebuilt graph serializes"),
        first,
        "equal inputs produce byte-identical output"
    );
    assert_layout_free(&first);
}

/// Every graph-owned variant, tag, explicit null, and empty array appears.
pub fn assert_json_covers_every_variant() {
    let (_corpus, _resolved, graph) = fixture::project_corpus_library();
    let text = serde_json::to_string(&graph).expect("the corpus graph serializes");

    let (_build, _script, build_graph) = fixture::project_build_script();
    let build_text =
        serde_json::to_string(&build_graph).expect("the build-script graph serializes");

    let missing: Vec<&str> = REQUIRED_FRAGMENTS
        .iter()
        .copied()
        .filter(|fragment| !text.contains(fragment))
        .collect();
    assert!(
        missing.is_empty(),
        "version-1 shapes are missing: {missing:?}"
    );
    assert!(
        build_text.contains(
            r#""origin":{"kind":"dependency","evidence":{"alias":"builder","kind":"build","predicate":null}}"#
        ),
        "the build dependency table has no serialized form"
    );
    assert!(
        build_text.contains(r#"{"category":"container","level":"build_script"}"#),
        "a unit container states the Cargo target kind it was built for"
    );

    let tags = [
        (
            serde_json::to_string(&GraphReferenceKind::Implementation),
            "GraphReferenceKind::Implementation",
            "\"implementation\"",
        ),
        (
            serde_json::to_string(&GraphEdgeKind::DependsOn),
            "GraphEdgeKind::DependsOn",
            "\"depends_on\"",
        ),
        (
            serde_json::to_string(&GraphCertainty::Possible),
            "GraphCertainty::Possible",
            "\"possible\"",
        ),
        (
            serde_json::to_string(&GraphDependencyKind::Development),
            "GraphDependencyKind::Development",
            "\"development\"",
        ),
        (
            serde_json::to_string(&GraphCollection::Node),
            "GraphCollection::Node",
            "\"node\"",
        ),
        (
            serde_json::to_string(&GraphCollection::Reference),
            "GraphCollection::Reference",
            "\"reference\"",
        ),
        (
            serde_json::to_string(&GraphCollection::Edge),
            "GraphCollection::Edge",
            "\"edge\"",
        ),
    ];
    for (rendered, subject, expected) in tags {
        assert_eq!(
            rendered.unwrap_or_else(|error| panic!("{subject} does not serialize: {error}")),
            expected,
            "{subject} must serialize as the lower-snake-case token {expected}"
        );
    }

    assert_layout_free(&text);
    assert_layout_free(&build_text);
}

fn assert_layout_free(text: &str) {
    let found: Vec<&str> = LAYOUT_VOCABULARY
        .iter()
        .copied()
        .filter(|key| text.contains(key))
        .collect();
    assert!(found.is_empty(), "the wire shape is layout-free: {found:?}");
}

/// Two tiers over one snapshot change only resolution evidence.
pub fn assert_tiers_change_only_evidence() {
    let (_corpus, syntactic) = fixture::resolve_corpus_library();
    let promoted = promoted_resolution(&syntactic.snapshot, syntactic.resolution.report());

    let evidence_delta = stated_evidence_delta(syntactic.resolution.report(), promoted.report());

    let first = build_rust_graph(&syntactic.snapshot, &syntactic.resolution)
        .expect("the syntactic corpus projects");
    let second =
        build_rust_graph(&syntactic.snapshot, &promoted).expect("the promoted report projects");

    assert_eq!(first.tier(), ResolutionTier::Syntactic);
    assert_eq!(second.tier(), ResolutionTier::Semantic);
    assert_structure_is_tier_free((&first, &second));
    assert_evidence_follows_the_reports((&first, &second), &evidence_delta);

    assert_promoted_wire_shape(&second);
}

/// Which records the promoted report restates, proved to be a deliberate,
/// non-empty set.
fn stated_evidence_delta(before: &ResolutionReport, after: &ResolutionReport) -> Vec<usize> {
    assert_eq!(after.tier(), ResolutionTier::Semantic);
    assert_eq!(
        before.resolutions().len(),
        after.resolutions().len(),
        "the restated report answers exactly the records the first one did"
    );
    let evidence_delta: Vec<usize> = before
        .resolutions()
        .iter()
        .zip(after.resolutions())
        .enumerate()
        .filter(|(_, (left, right))| {
            left.candidates() != right.candidates() || left.gaps() != right.gaps()
        })
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        evidence_delta,
        [13, 14],
        "the paired report must state a deliberate, non-empty evidence delta"
    );
    evidence_delta
}

/// Everything but resolution evidence is identical across the two tiers.
fn assert_structure_is_tier_free(graphs: (&pedant_graph::CodeGraph, &pedant_graph::CodeGraph)) {
    let (first, second) = graphs;
    assert_eq!(
        render::nodes(first),
        render::nodes(second),
        "nodes and source associations are identical across tiers"
    );
    assert_eq!(
        render::containment(first),
        render::containment(second),
        "containment is identical across tiers"
    );
    assert_eq!(
        render::reference_sites(first),
        render::reference_sites(second),
        "every reference keeps its id, source, language, kind, text, and span"
    );
}

/// Graph evidence changes exactly where the two reports differ, and each
/// restated record keeps the gap and the certainty its report states.
fn assert_evidence_follows_the_reports(
    graphs: (&pedant_graph::CodeGraph, &pedant_graph::CodeGraph),
    evidence_delta: &[usize],
) {
    let (first, second) = graphs;
    assert_eq!(
        first.references().len(),
        second.references().len(),
        "both tiers keep one record per stated reference"
    );
    let changed: Vec<usize> = first
        .references()
        .iter()
        .zip(second.references())
        .enumerate()
        .filter(|(_, (left, right))| {
            left.gaps() != right.gaps() || left.edges().len() != right.edges().len()
        })
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        changed, evidence_delta,
        "graph evidence changes exactly where the reports differ"
    );
    assert_eq!(
        second.references()[13].gaps(),
        [ResolutionGap::ConditionalCompilation],
        "the promoted record keeps its stated gap"
    );
    assert_eq!(
        second
            .edge(second.references()[13].edges()[0])
            .map(pedant_graph::GraphEdge::certainty),
        Some(GraphCertainty::Possible),
        "a downgraded candidate keeps its exact certainty"
    );
    assert!(
        second.references()[14].edges().is_empty()
            && second.references()[14].gaps() == [ResolutionGap::MissingDefinition],
        "a withdrawn candidate leaves its record and its gap in place"
    );
}

/// The promoted graph's own serialized form.
///
/// The tier token and both promoted gap tokens reach the wire only here: every
/// other case serializes a syntactic graph, so a serde change spelling the tier
/// or a gap another way would ship unread.
fn assert_promoted_wire_shape(promoted: &pedant_graph::CodeGraph) {
    let text = serde_json::to_string(promoted).expect("the promoted graph serializes");
    let missing: Vec<&str> = PROMOTED_FRAGMENTS
        .iter()
        .copied()
        .filter(|fragment| !text.contains(fragment))
        .collect();
    assert!(
        missing.is_empty(),
        "the promoted wire shape is missing: {missing:?}"
    );
    assert!(
        !text.contains(r#""tier":"syntactic""#),
        "a promoted graph must not carry the syntactic tier token"
    );
    assert_layout_free(&text);
}
