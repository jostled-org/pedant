//! The written-down model the Go projection cases are read against.
//!
//! Split from the cases beside it the way `ownership_model` is split from
//! `ownership`: a model and the predicates that hold the tree to it are two
//! jobs, and only one of them changes when a module moves.
//!
//! Everything here is compiled under every feature profile, because the model
//! is what proves a Go module or a Go predicate appeared. A model that vanished
//! with the feature would prove nothing about the build that has it.

/// Every predicate the Go projection registers at the one root.
pub const GO_PREDICATES: &[&str] = &[
    "go_and_rust_public_graph_api_shapes_are_parallel_and_language_specific",
    "go_graph_containment_is_total_acyclic_and_relation_free",
    "go_graph_copies_every_reference_candidate_certainty_and_gap",
    "go_graph_is_deterministic_and_rust_graph_bytes_stay_exact",
    "go_graph_limits_refuse_before_partial_records",
    "go_graph_projects_one_package_and_definition_node_per_report_claim",
    "go_graph_refuses_stale_resolution_before_allocation",
    "go_graph_uses_existing_queries_and_rust_cache_answers_stay_exact",
    "go_graph_uses_schema_v1_without_new_wire_branches",
    "go_graph_validation_and_limits_dominate_draft_allocation",
    "go_local_replacement_projects_one_resolved_dependency_edge",
    "go_shared_source_has_one_store_entry_and_two_unit_file_nodes",
];

/// The container level every admitted Go module's node takes.
pub const MODULE_LEVEL: &str = "module";

/// The container level every Go package context's node takes.
pub const PACKAGE_LEVEL: &str = "package";

/// The two public Go builders, beside the Rust builders they are parallel to.
///
/// Each pair takes the same argument positions and answers the same result, and
/// only the two snapshot-bound argument types differ. A Go builder that grew a
/// third argument, or answered a Go-specific result, would make a consumer read
/// two boundaries instead of one.
pub const PAIRED_BUILDERS: &[(&str, &str)] = &[
    ("build_go_graph", "build_rust_graph"),
    ("build_go_graph_with_limits", "build_rust_graph_with_limits"),
];

/// The language type names each adapter's own boundary is written in.
///
/// The first entry of each pair is the Go spelling and the second is the Rust
/// one, so a signature comparison can elide exactly the words that are allowed
/// to differ.
pub const PAIRED_ARGUMENT_TYPES: &[(&str, &str)] = &[
    ("GoResolutionSnapshot", "RustResolutionSnapshot"),
    ("GoProjectResolution", "RustTargetResolution"),
];

/// The Go core spellings no source outside the Go adapter may name.
pub const GO_CORE_SPELLINGS: &[&str] = &[
    "GoResolutionSnapshot",
    "GoProjectResolution",
    "GoResolutionUnit",
    "GoSnapshotModuleId",
    "GoSnapshotUnitId",
    "GoSnapshotEdge",
    "GoUnitBinding",
    "go-resolution",
];

/// The Rust core spellings no Go adapter source may name.
pub const RUST_CORE_SPELLINGS: &[&str] = &[
    "RustResolutionSnapshot",
    "RustTargetResolution",
    "RustSnapshotUnitId",
    "RustSnapshotEdge",
    "RustUnitBinding",
    "RustResolutionUnit",
    "GraphCache",
];

/// The one source that owns the Go entry points.
pub const GO_ENTRY_OWNER: &str = "src/go/entry.rs";

/// The one source that owns the Rust entry points.
pub const RUST_ENTRY_OWNER: &str = "src/rust/entry.rs";

/// The one source that owns the Go vocabulary.
pub const GO_VOCABULARY_OWNER: &str = "src/go/mapping.rs";

/// The one source that owns the Go planner.
pub const GO_PLANNER: &str = "src/go/projection.rs";

/// The sole neutral assembler, and the passes it must allocate through.
pub const ASSEMBLY_OWNER: &str = "src/projection/assembly.rs";

/// Every pass the sole assembler runs after its state exists, in order.
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

/// The three record insertions every draft reaches the graph through.
///
/// Each is a method of the one checked store, and each admits an identity
/// before it touches a collection. An adapter that named one of them directly
/// would allocate a record outside the assembler's own ordering.
pub const RECORD_INSERTIONS: &[&str] = &["insert_node", "insert_reference", "insert_edge"];
