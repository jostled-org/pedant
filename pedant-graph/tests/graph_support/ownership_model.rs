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
/// Every variant has exactly one owning source. Two are the store's own —
/// `src/graph.rs` refuses an edge whose record it does not hold and refuses a
/// collection at its ceiling — five belong to the containment walk, and the
/// join-validation owner states every other, so a projection pass or an index
/// table that built a refusal of its own fails here rather than stating a join
/// nothing else checks.
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
        &["src/graph.rs", "src/rust/validation.rs"],
    ),
    (
        "GraphBuildError::UnknownContainmentNode",
        &["src/rust/containment_check.rs"],
    ),
    (
        "GraphBuildError::MultiplyContained",
        &["src/rust/containment_check.rs"],
    ),
    (
        "GraphBuildError::UnparentedNode",
        &["src/rust/containment_check.rs"],
    ),
    (
        "GraphBuildError::RootHasParent",
        &["src/rust/containment_check.rs"],
    ),
    (
        "GraphBuildError::ContainmentCycle",
        &["src/rust/containment_check.rs"],
    ),
    ("GraphBuildError::CapacityExceeded", &["src/graph.rs"]),
];

/// The validators the planner must reach, in the order it reaches them.
pub const PLANNED_VALIDATORS: &[&str] = &[
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
pub const IDENTIFIED_VALIDATORS: &[&str] = &["instantiated_source"];

/// The validators the source projection must reach before it states a record.
///
/// The shared report vocabulary carries kinds no Rust projection has a node or
/// a record for. Reading one is a join like any other, so the refusal it earns
/// is built by the validation owner rather than by the pass that met it.
pub const PROJECTED_VALIDATORS: &[&str] = &["definition_kind", "reference_kind"];

/// The validator the source placement must reach before it states a source.
///
/// A unit that instantiates one path twice would mint a second file node for a
/// source the placement then holds no records for, so the repeat is refused
/// where the unit's own sources are read.
pub const PLACED_VALIDATORS: &[&str] = &["distinct_source"];

/// The validator the assembly tables must reach before a binding is dropped.
pub const BOUND_VALIDATORS: &[&str] = &["unit_scope"];

/// The validators the claim owner must reach before it states a key.
///
/// A claim names a fragment, the unit that placed it, and the bytes it was
/// derived from. Each of those is a join, and a claim that read one without
/// proving it could answer a later build for a source this snapshot never had.
pub const CLAIMED_VALIDATORS: &[&str] = &["planned_unit", "source_digest"];

/// The validators the assembler must reach before it seals a graph.
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

/// The source that declares every one-join validator.
pub const VALIDATION_OWNER: &str = "src/rust/validation.rs";

/// The source that declares the whole-relation containment rule.
pub const CONTAINMENT_OWNER: &str = "src/rust/containment_check.rs";
