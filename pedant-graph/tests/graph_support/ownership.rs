//! Structural ownership: what this crate's production sources may name, in
//! which order, and how many times.
//!
//! Behavioural cases own error values and payloads. These cases own only
//! reachability, dominance, and single ownership — the properties a passing
//! behavioural run cannot distinguish from a lucky one.

use std::collections::BTreeSet;

use super::inventory::{PRODUCTION_SOURCES, SOURCES};
use super::scan::{
    code_only, discovered_sources, function_body, method_body, parsed, position_of, source,
};
use super::surface::{
    declared_error_variants, declared_items, derived_paths, public_constructors, public_fields,
};

/// The entry points a pure projection may never reach.
///
/// Each is the exact production spelling a widening change would introduce.
const FORBIDDEN_ENTRY_POINTS: &[&str] = &[
    "RustProject::load",
    "snapshot_resolution",
    "snapshot_target",
    "snapshot_package",
    "SemanticContext",
    "RustResolver",
    "resolve_syntactic",
    "resolve_semantic",
    "syn::parse_file",
    "parse_source",
    "std::fs",
    "std::process",
    "Command::new",
    "include_str!",
];

/// Spellings that would let a production path abort instead of refuse.
///
/// Every source is scanned for every spelling, because a crate that keeps none
/// of them anywhere costs nothing to hold to that rule and a check narrowed to
/// three files would miss the fourth.
const PANIC_SPELLINGS: &[&str] = &["unwrap(", "expect(", "panic!", "unreachable!", "todo!"];

/// The sole assembly-state construction site, in source spelling.
///
/// The parsed body renders `::` with spaces around it, so the token form is
/// derived from this one constant rather than written a second time.
const STATE_CONSTRUCTOR: &str = "ProjectionState::new";

/// The exact signature the sole projection-state constructor declares.
const STATE_CONSTRUCTOR_SIGNATURE: &str =
    "pub(crate) fn new(limits: GraphLimits, capacity: ProjectionCapacity)";

/// The sole checked insertion owner every minted identity passes through.
const INSERTION_OWNER: &str = "fn admit";

/// Every `GraphBuildError` variant, beside the exact sources allowed to build
/// it, in the order [`SOURCES`] lists them.
///
/// Every variant has exactly one owning source. Two are the store's own —
/// `src/graph.rs` refuses an edge whose record it does not hold and refuses a
/// collection at its ceiling — and the validation owner states every other, so
/// a projection pass or an index table that built a refusal of its own fails
/// here rather than stating a join nothing else checks.
const ERROR_OWNERS: &[(&str, &[&str])] = &[
    (
        "GraphBuildError::RootTargetMismatch",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::SnapshotFingerprintMismatch",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::MissingUnitBinding",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::DanglingUnitBinding",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::SharedUnitBinding",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::MissingDependencyUnit",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::MissingSourceNode",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::RepeatedUnitSource",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::ReferenceRecordMismatch",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::MissingDefinitionNode",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::MissingReferenceRecord",
        // The store refuses an edge whose record it does not hold; the
        // validation owner refuses a plan whose report-order slot names no
        // reference at all. Both are the same claim about a record that answers
        // for nothing, one made at the store and one made before it.
        &["src/graph.rs", "src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::UnknownContainmentNode",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::MultiplyContained",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::UnparentedNode",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::RootHasParent",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::ContainmentCycle",
        &["src/rust/validation.rs"],
    ),
    ("GraphBuildError::CapacityExceeded", &["src/graph.rs"]),
];

/// The validators the planner must reach, in the order it reaches them.
const PLANNED_VALIDATORS: &[&str] = &[
    "check_root_target",
    "check_snapshot_identity",
    "resolved_references",
    "stated_binding",
    "snapshot_instance",
    "distinct_binding",
    "definition_identity",
    "definition_fragment",
    "placed_slot",
    "dependency_unit",
];

/// The validators the planner reaches through the identity table it derives.
const IDENTIFIED_VALIDATORS: &[&str] = &["instantiated_source"];

/// The validator the source placement must reach before it states a source.
///
/// A unit that instantiates one path twice would mint a second file node for a
/// source the placement then holds no records for, so the repeat is refused
/// where the unit's own sources are read.
const PLACED_VALIDATORS: &[&str] = &["distinct_source"];

/// The validator the assembly tables must reach before a binding is dropped.
const BOUND_VALIDATORS: &[&str] = &["unit_scope"];

/// The validators the claim owner must reach before it states a key.
///
/// A claim names a fragment, the unit that placed it, and the bytes it was
/// derived from. Each of those is a join, and a claim that read one without
/// proving it could answer a later build for a source this snapshot never had.
const CLAIMED_VALIDATORS: &[&str] = &["planned_unit", "source_digest"];

/// The validators the assembler must reach before it seals a graph.
const ASSEMBLED_VALIDATORS: &[&str] = &[
    "planned_definition",
    "planned_reference",
    "fragment_source",
    "fragment_unit",
    "unit_container",
    "source_node",
    "definition_node",
    "check_containment_forest",
];

/// The discovered source set equals the model, is non-empty, and names no
/// loader, snapshot, parser, semantic, or resolver entry point.
pub fn assert_pure_projection_sources() {
    let modelled: BTreeSet<String> = PRODUCTION_SOURCES
        .iter()
        .map(|path| (*path).into())
        .collect();
    assert!(!modelled.is_empty(), "the production source model is empty");
    assert_eq!(
        discovered_sources(),
        modelled,
        "the production source set must equal the written-down inventory"
    );
    assert_eq!(
        SOURCES
            .iter()
            .map(|entry| entry.path)
            .collect::<BTreeSet<_>>(),
        PRODUCTION_SOURCES.iter().copied().collect::<BTreeSet<_>>(),
        "every modelled source must carry its compile-time text"
    );

    let offenders = sources_naming(FORBIDDEN_ENTRY_POINTS);
    assert!(
        offenders.is_empty(),
        "graph production sources reach beyond their supplied facts: {offenders:?}"
    );
}

/// Every modelled source that names one of `spellings`, in [`SOURCES`] order.
///
/// Comments are dropped first, so prose describing a forbidden spelling does
/// not read as the thing it describes.
fn sources_naming(spellings: &[&str]) -> Vec<String> {
    let mut offenders: Vec<String> = Vec::new();
    for entry in SOURCES {
        let code = code_only(entry.text);
        offenders.extend(
            spellings
                .iter()
                .filter(|spelling| code.contains(**spelling))
                .map(|spelling| format!("{} names {spelling}", entry.path)),
        );
    }
    offenders
}

/// Both public builders delegate to one private projection entry over their
/// own `snapshot` and `resolution` parameters and nothing else.
pub fn assert_public_builders_delegate() {
    let ordinary = function_body("src/rust/entry.rs", "build_rust_graph");
    let bounded = function_body("src/rust/entry.rs", "build_rust_graph_with_limits");
    assert_eq!(
        ordinary, "{ projection :: project (snapshot , resolution , GraphLimits :: default ()) }",
        "the ordinary builder must delegate to the shared projection entry"
    );
    assert_eq!(
        bounded, "{ projection :: project (snapshot , resolution , limits) }",
        "the bounded builder must delegate to the shared projection entry"
    );
    let module = code_only(source("src/rust/mod.rs"));
    assert!(
        module.contains("pub use entry::{build_rust_graph, build_rust_graph_with_limits};"),
        "the Rust module root declares and re-exports only"
    );
    assert!(
        !module.contains("fn "),
        "the Rust module root must define no function"
    );
}

/// Both identity checks precede planning, and the sole assembly-state
/// constructor precedes every record-producing pass.
pub fn assert_identity_checks_dominate() {
    let entry = function_body("src/rust/projection.rs", "project");
    let validated = position_of(&entry, "validate", "the projection entry");
    let planned = position_of(&entry, "plan", "the projection entry");
    let assembled = position_of(&entry, "assembly :: assemble", "the projection entry");
    assert!(
        validated < planned && planned < assembled,
        "the projection entry validates, then plans, then assembles"
    );
    let checks = function_body("src/rust/projection.rs", "validate");
    let root = position_of(&checks, "check_root_target", "the identity checks");
    let identity = position_of(&checks, "check_snapshot_identity", "the identity checks");
    assert!(
        root < identity,
        "the root target is proved before the snapshot identity"
    );

    let assembly = function_body("src/rust/assembly.rs", "assemble");
    let construction = position_of(&assembly, &token_form(STATE_CONSTRUCTOR), "the assembler");
    for pass in [
        "assemble_containers",
        "assemble_sources",
        "assemble_definitions",
        "assemble_containment",
        "assemble_references",
        "assemble_dependencies",
        "assemble_candidates",
    ] {
        let at = position_of(&assembly, pass, "the assembler");
        assert!(
            construction < at,
            "{pass} must run after the assembly state exists"
        );
    }
    let sites: Vec<&str> = SOURCES
        .iter()
        .filter(|entry| code_only(entry.text).contains(STATE_CONSTRUCTOR))
        .map(|entry| entry.path)
        .collect();
    assert_eq!(
        sites,
        vec!["src/rust/assembly.rs"],
        "the assembly state has exactly one construction site"
    );
    assert_eq!(
        code_only(source("src/rust/index.rs"))
            .matches(STATE_CONSTRUCTOR_SIGNATURE)
            .count(),
        1,
        "the assembly state has exactly one constructor, spelled {STATE_CONSTRUCTOR_SIGNATURE}"
    );
}

/// One source spelling as the parsed body renders it.
fn token_form(spelling: &str) -> String {
    spelling.replace("::", " :: ")
}

/// All three insertion owners mint their identity through one checked helper.
pub fn assert_one_checked_insertion_owner() {
    for (method, collection) in [
        ("insert_node", "GraphCollection::Node"),
        ("insert_reference", "GraphCollection::Reference"),
        ("insert_edge", "GraphCollection::Edge"),
    ] {
        let body = method_body("src/graph.rs", method);
        let admit = position_of(&body, "self . admit", method);
        let mutation = position_of(&body, ". push (", method);
        assert!(
            admit < mutation,
            "{method} must admit an identity before it mutates the store"
        );
        assert!(
            body.contains(&collection.replace("::", " :: ")),
            "{method} must name {collection}"
        );
    }
    let admit = method_body("src/graph.rs", "admit");
    assert!(
        admit.contains("u32 :: try_from"),
        "the insertion owner must prove the fixed-width ceiling"
    );
    assert!(
        admit.contains("self . limits . ceiling (collection)"),
        "the insertion owner must prove the configured ceiling"
    );
    assert_eq!(
        code_only(source("src/graph.rs"))
            .matches(INSERTION_OWNER)
            .count(),
        1,
        "there is exactly one checked insertion owner, spelled {INSERTION_OWNER}"
    );
}

/// Every defensive validator is reachable from the shared projection entry,
/// every error variant is built only by the source that owns it, and no
/// production source can abort instead of refusing.
pub fn assert_defensive_paths_are_wired() {
    for (reader, validators) in [
        ("src/rust/projection.rs", PLANNED_VALIDATORS),
        ("src/rust/identity.rs", IDENTIFIED_VALIDATORS),
        ("src/rust/fragment.rs", PLACED_VALIDATORS),
        ("src/rust/index.rs", BOUND_VALIDATORS),
        ("src/rust/claim.rs", CLAIMED_VALIDATORS),
        ("src/rust/assembly.rs", ASSEMBLED_VALIDATORS),
    ] {
        assert_validators_are_reached(reader, validators);
    }
    let entry = function_body("src/rust/assembly.rs", "assemble");
    let finish = position_of(&entry, "state . finish", "the assembler");
    let forest = position_of(&entry, "check_containment_forest", "the assembler");
    assert!(
        forest < finish,
        "containment must be validated before the graph is constructed"
    );

    assert_eq!(
        declared_error_variants(),
        ERROR_OWNERS
            .iter()
            .map(|(variant, _)| variant
                .strip_prefix("GraphBuildError::")
                .unwrap_or_else(|| panic!("{variant} is not a GraphBuildError variant"))
                .to_owned())
            .collect::<BTreeSet<_>>(),
        "every declared refusal must state which sources may build it"
    );
    for (variant, owners) in ERROR_OWNERS {
        let sites: Vec<&str> = SOURCES
            .iter()
            .filter(|entry| code_only(entry.text).contains(variant))
            .map(|entry| entry.path)
            .collect();
        assert_eq!(
            sites, *owners,
            "{variant} must be constructed by exactly its owning sources"
        );
    }
    let aborting = sources_naming(PANIC_SPELLINGS);
    assert!(
        aborting.is_empty(),
        "a production source may refuse but never abort: {aborting:?}"
    );
}

/// Every named validator is declared by the validation owner and reached by the
/// source the model says reaches it.
///
/// A validator answering a borrow of what it was handed states its own
/// lifetime, so both spellings the declaration can take are admitted. The name
/// is still bound on both sides — by the opening parenthesis or by the opening
/// angle bracket — so a longer name that merely starts with a modelled one
/// answers for neither.
fn assert_validators_are_reached(reader: &str, validators: &[&str]) {
    let validation = source("src/rust/validation.rs");
    let text = source(reader);
    for validator in validators {
        let declarations = [
            format!("pub(crate) fn {validator}("),
            format!("pub(crate) fn {validator}<"),
        ];
        assert!(
            declarations
                .iter()
                .any(|declaration| validation.contains(declaration)),
            "{validator} is not declared by the validation owner"
        );
        assert!(
            text.contains(validator),
            "{validator} is not reached from {reader}"
        );
    }
}

/// Public records keep private fields and private constructors, and the graph
/// value implements neither `Clone` nor `Deserialize`.
pub fn assert_lifecycle_surface_is_closed() {
    let mut offenders: Vec<String> = Vec::new();
    for entry in SOURCES {
        let file = parsed(entry.path);
        let items = declared_items(&file.items);
        offenders.extend(public_fields(&items, entry.path));
        offenders.extend(public_constructors(&items, entry.path));
    }
    assert!(
        offenders.is_empty(),
        "public graph records must keep private fields and constructors: {offenders:?}"
    );

    assert_graph_value_derives();
    let graph = code_only(source("src/graph.rs"));
    for forbidden in ["impl Clone for CodeGraph", "impl<'de> Deserialize"] {
        assert!(
            !graph.contains(forbidden),
            "src/graph.rs must not carry {forbidden}"
        );
    }
    assert!(
        !SOURCES
            .iter()
            .any(|entry| code_only(entry.text).contains("Deserialize")),
        "no graph record may be deserializable"
    );
}

/// The graph value derives `Serialize` and neither `Clone` nor `Deserialize`.
///
/// Every attribute of the `CodeGraph` item is read, because a second
/// `#[derive(Clone)]` above the serializing one would ship a cloneable graph
/// against the documented decision while the serializing line stayed clean.
fn assert_graph_value_derives() {
    let file = parsed("src/graph.rs");
    let declared = declared_items(&file.items)
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Struct(found) if found.ident == "CodeGraph" => Some(found),
            _ => None,
        })
        .unwrap_or_else(|| panic!("src/graph.rs declares no CodeGraph struct"));
    let derived = derived_paths(&declared.attrs);
    assert!(
        derived.contains("Serialize"),
        "CodeGraph must derive Serialize, deriving {derived:?}"
    );
    for forbidden in ["Clone", "Deserialize"] {
        assert!(
            !derived.contains(forbidden),
            "CodeGraph must not derive {forbidden}, deriving {derived:?}"
        );
    }
}
