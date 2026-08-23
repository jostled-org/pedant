//! The written-down model the structural ownership cases are read against.
//!
//! Split from the cases beside it for the source-file budget alone, the way
//! `packaged_workspace_claims` sits beside `packaged_workspace`. A model and
//! the predicates that hold the tree to it are two jobs, and only one of them
//! changes when a module moves.

/// The entry points a pure projection may never reach.
///
/// Each is the exact production spelling a widening change would introduce.
/// Both adapters are named, because each has a loader and a resolver of its own
/// and a scan that knew one of them would let the other's arrive. The Go loader
/// is named by the call rather than by its type, because the adapter's own
/// argument type is spelled `GoProjectResolution` and carries that prefix.
pub const FORBIDDEN_ENTRY_POINTS: &[&str] = &[
    "RustProject::load",
    "GoProject::load",
    "snapshot_resolution",
    "snapshot_target",
    "snapshot_package",
    "SemanticContext",
    "RustResolver",
    "GoResolver",
    "resolve_syntactic",
    "resolve_semantic",
    "syn::parse_file",
    "parse_source",
    "std::fs",
    "std::process",
    "Command::new",
    "include_str!",
];

/// The Go vocabulary, in the exact production spelling it would arrive under.
///
/// One table, forbidden over a different source set by each predicate that
/// names it: the neutral family, the Rust adapter, and the cache may name none
/// of these, and outside the Go adapter only the crate root that declares it
/// behind its own feature may. Two tables would let a type added to one escape
/// the other's scan.
pub const GO_VOCABULARY: &[&str] = &[
    "GoProject",
    "GoProjectResolution",
    "GoResolutionLimits",
    "GoResolutionSnapshot",
    "GoResolutionUnit",
    "GoResolver",
    "GoSnapshotEdge",
    "GoSnapshotModuleId",
    "GoSnapshotUnitId",
    "GoUnitBinding",
    "build_go_graph",
    "go-resolution",
    "go_resolution",
    "resolution::go",
];

/// The Rust vocabulary, in the exact production spelling it would arrive under.
///
/// The counterpart of [`GO_VOCABULARY`], forbidden over the neutral family and
/// over the Go adapter. The retained cache handle is Rust's too: it is the one
/// surface a Rust build keeps a projection on, and a Go source naming it would
/// be retaining through a store no Go claim keys.
pub const RUST_VOCABULARY: &[&str] = &[
    "GraphCache",
    "RustResolutionSnapshot",
    "RustResolutionUnit",
    "RustSnapshotEdge",
    "RustSnapshotFingerprint",
    "RustSnapshotUnitId",
    "RustTargetResolution",
    "RustUnitBinding",
];

/// Every pass the sole assembler runs after its state exists, in order.
///
/// Modelled beside the neutral owner rather than beside either adapter: one
/// assembler answers for every language, so which passes it runs and in which
/// order is nobody's language.
pub const ASSEMBLY_PASSES: &[&str] = &[
    "assemble_containers",
    "assemble_sources",
    "assemble_definitions",
    "assemble_declared_containers",
    "assemble_containment",
    "check_containment_forest",
    "assemble_references",
    "assemble_dependencies",
    "assemble_candidates",
    "state . finish",
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
        &["src/projection/validation.rs"],
    ),
    (
        "GraphBuildError::MissingUnitBinding",
        &[
            "src/go/validation.rs",
            "src/projection/validation.rs",
            "src/rust/validation.rs",
        ],
    ),
    (
        "GraphBuildError::DanglingUnitBinding",
        &["src/projection/validation.rs"],
    ),
    (
        "GraphBuildError::SharedUnitBinding",
        &["src/projection/validation.rs"],
    ),
    (
        "GraphBuildError::RepeatedUnitContainer",
        &["src/projection/validation.rs"],
    ),
    (
        "GraphBuildError::MissingUnitDeclaration",
        &["src/go/validation.rs"],
    ),
    (
        "GraphBuildError::RepeatedUnitDeclaration",
        &["src/go/validation.rs"],
    ),
    (
        "GraphBuildError::MissingDependencyUnit",
        &["src/projection/validation.rs"],
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
        &["src/go/validation.rs", "src/projection/validation.rs"],
    ),
    (
        "GraphBuildError::UnnamedDefinitionKind",
        &["src/projection/validation.rs"],
    ),
    (
        "GraphBuildError::UnnamedReferenceKind",
        &["src/projection/validation.rs"],
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
        "GraphBuildError::SharedUnitRoot",
        &["src/projection/forest.rs"],
    ),
    (
        "GraphBuildError::ContainmentCycle",
        &["src/projection/forest.rs"],
    ),
    ("GraphBuildError::CapacityExceeded", &["src/graph.rs"]),
];

/// The neutral validators the Rust planner must reach before it plans anything.
///
/// Placing the report's own records is the neutral placement owner's job, so
/// the validators that placement reaches are modelled there. What is left to a
/// planner is the pairing of every reference with the record that answered it,
/// the refusal a binding that names no snapshot instance earns, and the refusal
/// two report units naming one build unit earn — all three neutral, because
/// what a graph cannot do with an absent instance or a doubled join is the same
/// in every language, whichever identity the adapter looked up.
pub const PLANNED_VALIDATORS: &[&str] =
    &["resolved_references", "bound_instance", "distinct_binding"];

/// The Rust-specific validators the Rust planner must reach, in the order it
/// reaches them.
pub const RUST_PLANNED_VALIDATORS: &[&str] = &[
    "check_root_target",
    "check_snapshot_identity",
    "stated_binding",
];

/// The neutral validator both adapters' snapshot-identity checks must reach.
///
/// Which two fingerprints answer for a pairing is the adapter's; that unequal
/// fingerprints refuse the build is not, and one owner states it for both.
pub const FINGERPRINT_VALIDATORS: &[&str] = &["matching_fingerprint"];

/// The neutral validators the placement owner must reach before it states a
/// source or an identity.
///
/// A unit that instantiates one path twice would mint a second file node for a
/// source the placement then holds no records for, so the repeat is refused
/// where the unit's own sources are read. A definition whose span names a source
/// only another unit instantiates is refused where its identity is stated.
pub const PLACED_VALIDATORS: &[&str] = &[
    "distinct_source",
    "instantiated_source",
    "definition_identity",
    "definition_fragment",
    "placed_slot",
];

/// The neutral validator every adapter's source projection must reach before
/// it states a record.
///
/// One: the refusal a definition kind the adapter's own reading does not name
/// earns. Everything else a fragment is made of is derived by the shared draft
/// owner, so the joins it proves are modelled there instead.
pub const PROJECTED_VALIDATORS: &[&str] = &["stated_definition_kind"];

/// The neutral validators the shared drafts must reach before they copy a
/// site's answer.
///
/// A reference site, its candidates, and a dependency edge's two endpoints are
/// the shared report's and the shared snapshot's, so the drafts copy them once
/// for every adapter, and every join and every unnamed kind is refused against
/// the current report where that copy is made.
pub const DRAFTED_VALIDATORS: &[&str] = &[
    "definition_identity",
    "optional_identity",
    "stated_reference_kind",
    "dependency_unit",
];

/// The Go validators the Go planner must reach, in the order it reaches them.
pub const GO_PLANNED_VALIDATORS: &[&str] = &["check_snapshot_identity"];

/// The neutral validators the Go placement owner must reach before it states a
/// unit.
///
/// Three it shares with the Rust planner: the dangling binding, the build unit
/// two report units both bound, and the table slot a stated unit position owns.
/// Its sibling list below is what stays Go-specific.
pub const GO_PLACED_NEUTRAL_VALIDATORS: &[&str] =
    &["bound_instance", "distinct_binding", "unit_slot"];

/// The Go validators the Go placement owner must reach before it states a unit.
pub const GO_PLACED_VALIDATORS: &[&str] = &[
    "stated_binding",
    "package_declaration",
    "distinct_declaration",
    "holder_kind",
];

/// The neutral validators the assembly tables must reach before a binding is
/// dropped or overwritten.
pub const BOUND_VALIDATORS: &[&str] = &["unit_scope", "unit_slot", "unbound_container"];

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
    "stated_definition",
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

/// The source that declares every Go-specific one-join validator.
pub const GO_VALIDATION_OWNER: &str = "src/go/validation.rs";

/// The source that declares the whole-relation containment rule.
pub const CONTAINMENT_OWNER: &str = "src/projection/forest.rs";
