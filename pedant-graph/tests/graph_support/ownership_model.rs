//! The written-down model the structural ownership cases are read against.
//!
//! Split from the cases beside it for the source-file budget alone, the way
//! `packaged_workspace_claims` sits beside `packaged_workspace`. A model and
//! the predicates that hold the tree to it are two jobs, and only one of them
//! changes when a module moves.

/// The entry points a pure projection may never reach.
///
/// Each is the exact production spelling a widening change would introduce.
pub const FORBIDDEN_ENTRY_POINTS: &[&str] = &[
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
pub const PANIC_SPELLINGS: &[&str] = &["unwrap(", "expect(", "panic!", "unreachable!", "todo!"];

/// The sole assembly-state construction site, in source spelling.
///
/// The parsed body renders `::` with spaces around it, so the token form is
/// derived from this one constant rather than written a second time.
pub const STATE_CONSTRUCTOR: &str = "ProjectionState::new";

/// The exact signature the sole projection-state constructor declares.
pub const STATE_CONSTRUCTOR_SIGNATURE: &str =
    "pub(crate) fn new(limits: GraphLimits, capacity: ProjectionCapacity)";

/// The sole checked insertion owner every minted identity passes through.
pub const INSERTION_OWNER: &str = "fn admit";

/// Every `GraphBuildError` variant, beside the exact sources allowed to build
/// it, in the order [`SOURCES`] lists them.
///
/// Two are the store's own — `src/graph.rs` refuses an edge whose record it
/// does not hold and refuses a collection at its ceiling — and five belong to
/// the containment walk. Every other is built by one of the two join-validation
/// owners, so a projection pass, a placement, or an assembly table that built a
/// refusal of its own fails here rather than stating a join nothing else
/// checks.
///
/// Three variants name both join owners. Each is one claim made twice over
/// values of different kinds: a unit binding a snapshot does not hold and a plan
/// position no unit was planned for; a source the snapshot never read and a
/// source no unit instantiates; a reference record the store does not hold and
/// a plan slot naming no reference. Merging either pair would mean one of them
/// stopped being checked where it can actually go wrong.
pub const ERROR_OWNERS: &[(&str, &[&str])] = &[
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
        &["src/projection/validation.rs", "src/rust/validation.rs"],
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
        &["src/projection/validation.rs", "src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::RepeatedUnitSource",
        &["src/projection/validation.rs"],
    ),
    (
        "GraphBuildError::ReferenceRecordMismatch",
        &["src/projection/validation.rs"],
    ),
    (
        "GraphBuildError::MissingDefinitionNode",
        &["src/projection/validation.rs"],
    ),
    (
        "GraphBuildError::UnnamedDefinitionKind",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::UnnamedReferenceKind",
        &["src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::MissingReferenceRecord",
        // The store refuses an edge whose record it does not hold; the
        // validation owner refuses a plan whose report-order slot names no
        // reference at all. Both are the same claim about a record that answers
        // for nothing, one made at the store and one made before it.
        &["src/graph.rs", "src/projection/validation.rs"],
    ),
    (
        "GraphBuildError::UnknownContainmentNode",
        &["src/projection/forest.rs"],
    ),
    (
        "GraphBuildError::MultiplyContained",
        &["src/projection/forest.rs"],
    ),
    (
        "GraphBuildError::UnparentedNode",
        &["src/projection/forest.rs"],
    ),
    (
        "GraphBuildError::RootHasParent",
        &["src/projection/forest.rs"],
    ),
    (
        "GraphBuildError::ContainmentCycle",
        &["src/projection/forest.rs"],
    ),
    ("GraphBuildError::CapacityExceeded", &["src/graph.rs"]),
];

/// The neutral validators the Rust planner must reach, in the order it reaches
/// them.
pub const PLANNED_VALIDATORS: &[&str] = &[
    "resolved_references",
    "definition_identity",
    "definition_fragment",
    "placed_slot",
    "instantiated_source",
];

/// The Rust-specific validators the Rust planner must reach, in the order it
/// reaches them.
pub const RUST_PLANNED_VALIDATORS: &[&str] = &[
    "check_root_target",
    "check_snapshot_identity",
    "stated_binding",
    "snapshot_instance",
    "distinct_binding",
    "dependency_unit",
];

/// The neutral validators the placement owner must reach before it states a
/// source or an identity.
///
/// A unit that instantiates one path twice would mint a second file node for a
/// source the placement then holds no records for, so the repeat is refused
/// where the unit's own sources are read. A definition whose span names a source
/// only another unit instantiates is refused where its identity is stated.
pub const PLACED_VALIDATORS: &[&str] = &["distinct_source", "instantiated_source"];

/// The neutral validator the source projection must reach before it states a
/// record.
pub const PROJECTED_VALIDATORS: &[&str] = &["definition_identity"];

/// The Rust vocabulary validators the source projection must reach before it
/// states a record.
///
/// The shared report vocabulary carries kinds no Rust projection has a node or
/// a record for. Reading one is a join like any other, so the refusal it earns
/// is built by the adapter's validation owner rather than by the pass that met
/// it.
pub const RUST_PROJECTED_VALIDATORS: &[&str] = &["definition_kind", "reference_kind"];

/// The neutral validator the assembly tables must reach before a binding is
/// dropped.
pub const BOUND_VALIDATORS: &[&str] = &["unit_scope"];

/// The neutral validator the claim owner must reach before it states a key.
///
/// A claim names a fragment and the unit that placed it, and a claim that read
/// the unit without proving it could answer a later build for a source this
/// snapshot never had.
pub const CLAIMED_VALIDATORS: &[&str] = &["planned_unit"];

/// The Rust validator the claim owner must reach before it states a key.
///
/// The bytes a projection was derived from are the snapshot's own, so a digest
/// read without proving the snapshot holds that source would key a projection
/// against nothing.
pub const RUST_CLAIMED_VALIDATORS: &[&str] = &["source_digest"];

/// The neutral validators the assembler must reach before it seals a graph.
pub const ASSEMBLED_VALIDATORS: &[&str] = &[
    "planned_definition",
    "planned_reference",
    "fragment_source",
    "fragment_unit",
    "unit_container",
    "source_node",
    "definition_node",
];

/// The containment rule the assembler must reach, declared by its own owner.
pub const CONTAINMENT_VALIDATORS: &[&str] = &["check_containment_forest"];

/// The source that declares every neutral one-join validator.
pub const VALIDATION_OWNER: &str = "src/projection/validation.rs";

/// The source that declares every Rust-specific one-join validator.
pub const RUST_VALIDATION_OWNER: &str = "src/rust/validation.rs";

/// The source that declares the whole-relation containment rule.
pub const CONTAINMENT_OWNER: &str = "src/projection/forest.rs";
