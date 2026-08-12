//! The clause each owner document owes after this plan amends it.
//!
//! A completion claim that no document records is a claim with no reader. Each
//! row names a specific phrase a later maintainer would search for, so a
//! document that still describes the tree before the seam fails rather than
//! reads plausibly. Identifiers are paired across the rows that own their
//! behavior; lifecycle, count, and policy clauses use distinctive prose rather
//! than a bare number that arithmetic elsewhere could satisfy.
//!
//! The specs and guides are local tooling this repository does not publish, so
//! the module carries `resolution-test-support`. [`read_text`] panics on an
//! absent one; the feature decides where the check runs, never whether a
//! missing document reads as a satisfied clause.

use crate::resolution::authority_scan::read_text;

/// One document and the clauses its effective contract must state.
pub struct DocumentClauses {
    /// The document, repository-relative.
    pub path: &'static str,
    /// Text the document must carry after this plan amends it.
    pub clauses: &'static [&'static str],
}

/// The two guides, the active spec, and all eight implemented relation owners.
///
/// A completion claim that no document records is a claim with no reader; each
/// row is the specific contract phrase a later maintainer would need to find.
///
/// The graph rows name the final CI key names and proof modes rather than a
/// paraphrase, so a mode renamed in `.manifest.toml` and left stale in prose
/// fails here.
pub const DOCUMENT_CLAUSES: &[DocumentClauses] = &[
    DocumentClauses {
        path: "docs/specs/implemented/rust-symbol-resolution.md",
        clauses: &[
            "RustTargetResolution",
            "RustResolutionSnapshot",
            "RustSnapshotFingerprint",
            "RustTargetResolution::snapshot_fingerprint()",
            "RustResolutionWarning::SharedSourceUnits",
            "SemanticSharedSourceMismatch",
            "ResolutionReport::deserialize_with_limits",
            "Public `Id<K>`",
            "Public `Handle<K>`",
            "CargoEdition",
            "valid Rust 2015 and 2018 bare",
            "language filter refuses Rust",
            "It never tells units from different packages to share one package's library",
        ],
    },
    DocumentClauses {
        path: "docs/testing.md",
        clauses: &[
            "run_resolution_proof.sh",
            "run_graph_proof.sh",
            "graph-dependency-closure",
            "graph-source-capabilities",
            "graph-owner-registration",
            "graph_release_and_verification_owners_are_exact",
            "ci_installs_every_proof_runner_tool_before_execution",
            "completion-proof-support",
            "pedant-graph/tests/graph.rs",
            "The Public Graph Boundary",
            "The workspace currently links **34** such executables",
            "pedant-process-guard",
            "CARGO_TARGET_DIR",
            "SemanticSharedSourceMismatch",
            "max_references",
            "CargoEdition",
            "bare callable trait aliases",
            "distinct physical sources for different packages",
        ],
    },
    DocumentClauses {
        path: "docs/design-rationale.md",
        clauses: &[
            "RustTargetSnapshot",
            "RustResolutionSnapshot",
            "ResolutionReportBuilder",
            "CompletionProofInputs",
            "selection_chain::Ancestry",
            "SharedSourceUnits",
            "resolution/path_normalization.rs",
            "pedant_process_guard::ContainedProcessTree",
            "type_aliases",
            "ResolutionReport::deserialize_with_limits",
            "CargoEdition",
            "ParseCompatibility",
            "`Id<K>` over `u32`",
            "`Handle<K>` over `Arc<BuilderBrand>`",
            "resolution/rust/fingerprint.rs",
            "| 19 | Code structure graph | Rust symbol resolution | **Implemented**",
            "Containment is logical ownership; location is a source artifact",
            "The graph depends on resolution, never the other way round",
            "| 18 | Rust symbol resolution | Syntax substrate and snippet tool | **Implemented**",
            "Conflicting units from different packages need distinct physical sources",
            "run_graph_proof.sh",
        ],
    },
    DocumentClauses {
        path: "docs/specs/implemented/code-structure-graph.md",
        clauses: &[
            "docs/scripts/run_graph_proof.sh",
            "[ci].graph_dependency_closure",
            "[ci].graph_source_capabilities",
            "[ci].graph_owner_registration",
            "exactly 34 top-level Cargo integration-test executables",
        ],
    },
    DocumentClauses {
        path: "docs/specs/implemented/analysis-surface-split.md",
        clauses: &[
            "resolution::rust",
            "effective closed set now also contains `toml` and `semver`",
            "effective ungated set is `hash.rs`, `pattern.rs`, and `substrate.rs`",
        ],
    },
    DocumentClauses {
        path: "docs/specs/implemented/ir-extraction.md",
        clauses: &["reference_sites", "module_scopes", "TypeAliasFact"],
    },
    DocumentClauses {
        path: "docs/specs/implemented/LSP-semantic-analysis.md",
        clauses: &[
            "RustSnapshotUnitId",
            "SemanticContextMismatch",
            "SemanticSharedSourceMismatch",
            "outer proof target's lock",
            "distinct physical source for each unit",
        ],
    },
    DocumentClauses {
        path: "docs/specs/implemented/semantic-file-analysis-cache.md",
        clauses: &[
            "resolve_semantic",
            "call_graph",
            "distinct physical sources",
        ],
    },
    DocumentClauses {
        path: "docs/specs/implemented/supply-chain-scope.md",
        clauses: &["RustTargetSnapshot", "RustProject"],
    },
    DocumentClauses {
        path: "docs/specs/implemented/syntax-substrate-and-snippet-tool.md",
        clauses: &["Language::Rust"],
    },
    DocumentClauses {
        path: "docs/specs/implemented/mcp-server.md",
        clauses: &[
            "RustProject",
            "refuses the shared `Language::Rust`",
            "completion-proof-support",
        ],
    },
    DocumentClauses {
        path: "docs/specs/implemented/multi-language-capability-detection.md",
        clauses: &["Language::Rust"],
    },
];

/// Every owner document states the clauses its effective contract owes.
pub fn assert_document_clauses() {
    for document in DOCUMENT_CLAUSES {
        let text = read_text(document.path);
        for clause in document.clauses {
            assert!(
                text.contains(clause),
                "{} must state {clause:?}",
                document.path
            );
        }
    }
}
