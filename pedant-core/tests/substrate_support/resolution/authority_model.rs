//! The written-down shape of the finished tree, as its tracked files carry it.
//!
//! Every expectation here is stated, never discovered. A count taken from the
//! repository agrees with whatever the repository happens to contain, so it
//! cannot reject a authority that moved, an old identifier that came back, or a
//! proof mode that quietly stopped running anything.
//!
//! Every subject below is committed, so this model and [`super::authority_scan`]
//! compile and run in every configuration.

/// One authority: what it is, where it lives, the text that proves it lives
/// there, and the complete set of first-party sources allowed to name that text.
pub struct Authority {
    /// What this authority decides.
    pub label: &'static str,
    /// The text only its owner may carry.
    pub marker: &'static str,
    /// Every first-party source permitted to name the marker, in path order.
    pub sites: &'static [&'static str],
}

/// One decision, one owner. A second site for any marker below means two
/// answers to a question the plan says has one.
pub const AUTHORITIES: &[Authority] = &[
    Authority {
        label: "the resolution report validator",
        marker: "pub(crate) fn validate(report: &ResolutionReport)",
        sites: &["pedant-types/src/resolution/validate.rs"],
    },
    Authority {
        label: "the import-site inventory",
        marker: "pub(super) fn use_tree_leaves(tree: &syn::UseTree)",
        sites: &["pedant-core/src/ir/extract/imports.rs"],
    },
    Authority {
        label: "the Cargo project loader",
        marker: "pub fn load(root: &Path, limits: ResolutionLimits)",
        sites: &["pedant-core/src/resolution/rust/project.rs"],
    },
    Authority {
        label: "the Rust module closure",
        marker: "pub(in crate::resolution::rust::snapshot) struct UnitClosure",
        sites: &["pedant-core/src/resolution/rust/snapshot/closure/state.rs"],
    },
    Authority {
        label: "repository-relative path normalization",
        marker: "pub(crate) fn relative_text(root: &Path, path: &Path)",
        sites: &["pedant-core/src/resolution/path_normalization.rs"],
    },
    Authority {
        label: "package-primary shared source storage",
        marker: "pub struct RustPackageSnapshot",
        sites: &["pedant-core/src/resolution/rust/snapshot/primary.rs"],
    },
    Authority {
        label: "persistent dependency ancestry",
        marker: "pub(super) struct Ancestry",
        sites: &["pedant-core/src/resolution/rust/snapshot/selection_chain.rs"],
    },
    Authority {
        label: "shared physical-source diagnostics",
        marker: "pub enum RustResolutionWarning",
        sites: &["pedant-core/src/resolution/rust/warning.rs"],
    },
    Authority {
        label: "the snapshot-bound semantic target owner",
        marker: "impl Promotion for SemanticPromotion",
        sites: &["pedant-core/src/resolution/rust/resolve/semantic.rs"],
    },
    Authority {
        label: "the sole core validation boundary for a report",
        marker: "impl RustTargetResolution",
        sites: &["pedant-core/src/resolution/rust/resolve/target.rs"],
    },
    Authority {
        label: "workspace-member discovery, one entry per consumer",
        marker: "RustProject::load(",
        sites: &[
            "pedant-mcp/src/index/workspace.rs",
            "pedant/src/supply_chain/discovery.rs",
        ],
    },
];

/// Identifiers the breaking seam removed. None may appear in any first-party
/// source, under any spelling that would let a consumer reach it again.
pub const FORBIDDEN_IDENTIFIERS: &[&str] = &[
    "resolve_workspace_members",
    "WorkspaceMemberError",
    "pub fn call_graph",
    "CargoManifest",
];

/// Paths the breaking seam removed. A file that reappeared here would restore
/// a private authority the shared one replaced.
pub const FORBIDDEN_PATHS: &[&str] = &[
    "pedant-core/src/workspace.rs",
    "pedant-core/tests/workspace_members.rs",
    "pedant-mcp/src/index/manifest.rs",
    "pedant/src/supply_chain/manifest.rs",
    "pedant/src/supply_chain/module_graph.rs",
];

/// The first-party source trees every forbidden-identifier scan covers.
pub const FIRST_PARTY_SOURCES: &[&str] = &[
    "pedant-core/src",
    "pedant-graph/src",
    "pedant-lang/src",
    "pedant-mcp/src",
    "pedant-snippet/src",
    "pedant-syntax/src",
    "pedant-types/src",
    "pedant/src",
];

/// Where the migrated workspace-member cases now run, and the predicate that
/// carries them.
pub const MIGRATED_PREDICATE_SITE: &str =
    "pedant-core/tests/substrate_support/resolution/project.rs";

/// Predicates the substrate root must own after the migration.
pub const MIGRATED_PREDICATES: &[&str] = &[
    "fn workspace_member_cases_run_from_substrate_root",
    "fn testing_contract_tracks_exact_34_root_transition",
];
