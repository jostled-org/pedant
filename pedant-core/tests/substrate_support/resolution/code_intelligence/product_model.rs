//! The completed code-intelligence product, written down.
//!
//! Four trees, one module list each. Stated rather than discovered for the
//! reason every inventory here is: a discovered set agrees with whatever the
//! crate happens to hold, so it could not reject a module that arrived beside
//! the modelled owners — and a capability claim over a set that quietly lost a
//! file is a claim about a product nobody ships.
//!
//! Read by two cases. The capability case asks what the tree is allowed to do;
//! the structure case asks how it is allowed to be written. One inventory,
//! because two could pass one claim while the other ranged over a smaller tree.

use crate::resolution::production_tree::ProductionTree;

/// The package that publishes the completed product.
pub(crate) const PRODUCT_PACKAGE: &str = "pedant-snippet";

/// The tree every claim below ranges over.
pub(crate) const PRODUCT_TREE: &str = "pedant-snippet/src";

/// The library boundary, the two transports, and the shared request vocabulary
/// between them.
const ROOT_MODULES: &[&str] = &[
    "cli.rs",
    "command.rs",
    "lib.rs",
    "main.rs",
    "operation.rs",
    "render.rs",
    "request.rs",
    "server.rs",
    "token.rs",
];

/// The immutable repository index: admission, retention, identity, and the
/// ceilings all three are held to.
const INDEX_MODULES: &[&str] = &[
    "analysis.rs",
    "authority.rs",
    "build.rs",
    "claim.rs",
    "count.rs",
    "coverage.rs",
    "digits.rs",
    "discovery.rs",
    "error.rs",
    "file_inventory.rs",
    "go_slices.rs",
    "graph_budget.rs",
    "health.rs",
    "hex.rs",
    "indexer.rs",
    "instance.rs",
    "issue.rs",
    "join.rs",
    "joined.rs",
    "limit_field.rs",
    "limit_inventory.rs",
    "limits.rs",
    "lines.rs",
    "membership.rs",
    "mod.rs",
    "observe.rs",
    "path.rs",
    "profile.rs",
    "project.rs",
    "provider.rs",
    "read.rs",
    "report.rs",
    "retained.rs",
    "reuse.rs",
    "revision.rs",
    "rust_slices.rs",
    "seal.rs",
    "serialize.rs",
    "slice.rs",
    "source.rs",
    "state.rs",
    "store.rs",
    "structure.rs",
    "syntax.rs",
];

/// The live state owner: what changed, what that made of it, and what a caller
/// reaches afterwards.
const LIVE_MODULES: &[&str] = &[
    "batch.rs",
    "change.rs",
    "core.rs",
    "error.rs",
    "fold.rs",
    "index.rs",
    "key.rs",
    "mod.rs",
    "rules.rs",
    "terminal.rs",
    "transaction.rs",
    "watcher.rs",
];

/// The navigation answers, and the graph-backed three beneath them.
///
/// One tree rather than two: `graph` is a subdirectory of `navigation`, and the
/// exactness walk claims a nested directory by prefix.
const NAVIGATION_MODULES: &[&str] = &[
    "cursor.rs",
    "describe.rs",
    "failure.rs",
    "graph/analysis.rs",
    "graph/analysis_request.rs",
    "graph/betweenness.rs",
    "graph/budget.rs",
    "graph/certainty.rs",
    "graph/component.rs",
    "graph/degree.rs",
    "graph/direction.rs",
    "graph/divergence.rs",
    "graph/edge_kind.rs",
    "graph/entity.rs",
    "graph/mod.rs",
    "graph/neighborhood.rs",
    "graph/path_record.rs",
    "graph/refusal.rs",
    "graph/relation_request.rs",
    "graph/relations.rs",
    "graph/route.rs",
    "graph/seed.rs",
    "graph/selection.rs",
    "mod.rs",
    "outline.rs",
    "page.rs",
    "page_request.rs",
    "paged_query.rs",
    "point.rs",
    "project_list.rs",
    "project_record.rs",
    "record.rs",
    "request.rs",
    "response.rs",
    "search.rs",
];

/// The MCP registry: one module per served tool, plus the entries that list
/// and dispatch them.
///
/// The eight per-tool names are a second spelling of the eight operations, so
/// the structure case derives them from that model and compares the two. Read
/// there rather than only here for the reason the tool-name scan is: a
/// hand-copied list drifts in the direction that keeps passing.
pub(crate) const REGISTRY_MODULES: &[&str] = &[
    "analyze_graph.rs",
    "entries.rs",
    "find_path.rs",
    "list_projects.rs",
    "mod.rs",
    "outline_file.rs",
    "params.rs",
    "query_relations.rs",
    "read_structure.rs",
    "schema.rs",
    "search_symbols.rs",
    "structure_at.rs",
];

/// Every tree the completed product is written in.
pub(crate) const PRODUCT_TREES: &[ProductionTree] = &[
    ProductionTree {
        package: PRODUCT_PACKAGE,
        directory: PRODUCT_TREE,
        families: &[ROOT_MODULES],
        subdirectories: &[],
        delegated: &["index", "live", "navigation", "registry"],
    },
    ProductionTree {
        package: PRODUCT_PACKAGE,
        directory: "pedant-snippet/src/index",
        families: &[INDEX_MODULES],
        subdirectories: &[],
        delegated: &[],
    },
    ProductionTree {
        package: PRODUCT_PACKAGE,
        directory: "pedant-snippet/src/live",
        families: &[LIVE_MODULES],
        subdirectories: &[],
        delegated: &[],
    },
    ProductionTree {
        package: PRODUCT_PACKAGE,
        directory: "pedant-snippet/src/navigation",
        families: &[NAVIGATION_MODULES],
        subdirectories: &["graph"],
        delegated: &[],
    },
    ProductionTree {
        package: PRODUCT_PACKAGE,
        directory: "pedant-snippet/src/registry",
        families: &[REGISTRY_MODULES],
        subdirectories: &[],
        delegated: &[],
    },
];

/// The module roots that may hold nothing but module declarations and
/// re-exports.
///
/// A root that grew a body is a body no `#[path]`-free reader would look for,
/// and it is the one place a second implementation of an exported operation
/// could sit beside the export that hides it.
pub(crate) const MODULE_ROOTS: &[&str] = &[
    "pedant-snippet/src/index/mod.rs",
    "pedant-snippet/src/live/mod.rs",
    "pedant-snippet/src/navigation/graph/mod.rs",
    "pedant-snippet/src/navigation/mod.rs",
    "pedant-snippet/src/registry/mod.rs",
];

/// How many modules the whole product states.
///
/// A literal, and that is the whole point of it. Summed from the five arrays it
/// is compared against, the claim was a derivation of the table set against a
/// second derivation of the same table: dropping a row from [`INDEX_MODULES`]
/// moved both sides by one and the count stayed green over a smaller product.
/// Written down, a tree that lost a family — and with it every claim over that
/// family — fails here.
pub(crate) const PRODUCT_MODULE_COUNT: usize = 112;
