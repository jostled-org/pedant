//! Which test modules prove the Go surface, and the root each compiles into.
//!
//! The production half is [`super::surface`]. Stated apart because they are
//! answered apart: a production tree is claimed whole, while a support directory
//! a root shares with four other languages is claimed by prefix.

/// One integration root's Go test modules.
pub struct SupportTree {
    /// The cargo test executable they compile into.
    pub root: &'static str,
    /// The `#[path]` support directory beneath it.
    pub directory: &'static str,
    /// Whether every module in that directory is Go-owned. When false, the
    /// directory holds other languages' cases too, and only the `go_`-prefixed
    /// modules are claimed.
    pub whole: bool,
    /// Every Go module, relative to `directory`.
    pub modules: &'static [&'static str],
}

/// The prefix a Go module carries in a support directory it shares.
pub const GO_MODULE_PREFIX: &str = "go_";

/// Every Go test module in the workspace, by the root that compiles it.
pub const GO_SUPPORT: &[SupportTree] = &[
    SupportTree {
        root: "pedant-syntax/tests/enclosing_unit.rs",
        directory: "pedant-syntax/tests/enclosing_unit_support",
        whole: false,
        modules: &[
            "go_fact_limits.rs",
            "go_fact_source.rs",
            "go_facts.rs",
            "go_type_facts.rs",
            "ownership/go_facts.rs",
        ],
    },
    SupportTree {
        root: "pedant-lang/tests/capability.rs",
        directory: "pedant-lang/tests/capability_support",
        whole: false,
        modules: &["go_cases.rs", "go_fact_cases.rs", "go_ownership.rs"],
    },
    SupportTree {
        root: "pedant-core/tests/substrate.rs",
        directory: "pedant-core/tests/substrate_support/resolution/go",
        whole: true,
        modules: &[
            "boundary.rs",
            "conditions.rs",
            "discovery.rs",
            "fixture.rs",
            "host_state.rs",
            "limits.rs",
            "mod.rs",
            "observation.rs",
            "owners.rs",
            "ownership.rs",
            "policy.rs",
            "policy_errors.rs",
            "policy_model.rs",
            "policy_nesting.rs",
            "policy_routes.rs",
            "policy_scan.rs",
            "project.rs",
            "project_fixtures.rs",
            "recovery.rs",
            "refusal.rs",
            "registration.rs",
            "registration_model.rs",
            "resolution_calls.rs",
            "resolution_fixtures.rs",
            "resolution_imports.rs",
            "resolution_interface_dispatch.rs",
            "resolution_interface_fixtures.rs",
            "resolution_interface_gaps.rs",
            "resolution_interface_order.rs",
            "resolution_interface_ownership.rs",
            "resolution_interfaces.rs",
            "resolution_limits.rs",
            "resolution_method_facts.rs",
            "resolution_methods.rs",
            "resolution_ownership.rs",
            "resolution_refusal.rs",
            "resolution_scopes.rs",
            "resolution_views.rs",
            "resolution_wrapper.rs",
            "scan.rs",
            "snapshot.rs",
            "snapshot_claims.rs",
            "snapshot_fingerprint.rs",
            "snapshot_fixtures.rs",
            "snapshot_limits.rs",
            "snapshot_ownership.rs",
            "snapshot_views.rs",
            "support_trees.rs",
            "surface.rs",
            "views.rs",
        ],
    },
    SupportTree {
        root: "pedant-graph/tests/graph.rs",
        directory: "pedant-graph/tests/graph_support",
        whole: false,
        modules: &[
            "go_corpus.rs",
            "go_defensive.rs",
            "go_evidence.rs",
            "go_fixture.rs",
            "go_model.rs",
            "go_ownership.rs",
            "go_topology.rs",
            "go_wire.rs",
        ],
    },
];
