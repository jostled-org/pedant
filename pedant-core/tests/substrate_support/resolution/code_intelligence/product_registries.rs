//! 9.T8 (Invariant 21): code intelligence registers in neither other product.
//!
//! Three products share this workspace and one repository walk. The lint CLI
//! reports style and gate verdicts; the security MCP server answers capability
//! and violation questions; the code-intelligence binary answers navigation
//! questions. A navigation command that appeared in the lint CLI, or a
//! navigation tool in the security registry, would put a third product's surface
//! inside a binary whose users never asked for it — and would do so silently,
//! because every one of them would still pass its own tests.
//!
//! So the claim is made twice, from opposite sides. The scan requires that no
//! navigation name is declared in either product's sources. The inventory
//! requires that each product's own retained predicates are still there to run,
//! which is what keeps the scan from being satisfied by a product that lost its
//! surface entirely.

use std::collections::BTreeSet;

use crate::resolution::authority_scan::{Source, first_party_sources};
use crate::resolution::code_intelligence::operation_model::OPERATIONS;
use crate::resolution::comment_scan::code_index;
use crate::resolution::manifest_reader::assert_requires_none;
use crate::resolution::test_identity::{declaration_sites, workspace_test_sources};

/// The two product trees that must not register a navigation surface.
///
/// Both are first-party source trees, so the process-wide scan has already
/// walked and read them. Filtering that reading is what keeps this claim over
/// the same set every other source claim is made about.
const NON_NAVIGATION_TREES: [&str; 2] = ["pedant/src", "pedant-mcp/src"];

/// How few sources under one tree mean the scan is not reading that product.
///
/// Both trees hold more than this. Without the floor a tree that yielded
/// nothing would pass every clause below: no file, no line, no offender, and a
/// green claim that a product registers no navigation surface.
const MINIMUM_TREE_SOURCES: usize = 20;

/// The crate that publishes the navigation surface.
const NAVIGATION_CRATE: &str = "pedant-snippet";

/// The navigation spellings this claim owns, which no operation names.
///
/// The command spelling of the one operation `clap` renames, and the three index
/// and response types a reader would reach the surface through.
const NAVIGATION_TYPES: [&str; 4] = [
    "list-projects",
    "CodeIntelligenceIndex",
    "LiveCodeIntelligenceIndex",
    "NavigationResponse",
];

/// Every public operation the code-intelligence product registers.
///
/// The MCP tool names and the CLI command names, because a registry entry and a
/// command tree are the two ways a product can grow a surface, and each of these
/// names is one of them.
///
/// The eight tool names come from [`OPERATIONS`], which is where the product's
/// operations are written down. Hand-copied into a sibling module they were a
/// second list: a ninth operation grew the first and not this one, and the scan
/// silently stopped covering the new name.
fn navigation_names() -> Box<[&'static str]> {
    OPERATIONS
        .iter()
        .map(|operation| operation.method)
        .chain(NAVIGATION_TYPES)
        .collect()
}

/// One retained predicate, and the root that still has to run it.
struct Retained {
    /// The predicate name.
    predicate: &'static str,
    /// The test root that declares it, repository-relative.
    root: &'static str,
}

/// Every byte control the cutover leaves untouched.
///
/// A predicate here is not re-run by this test — its own root runs it, and the
/// Step 9 route runs those roots whole. What this indexes is that the predicate
/// is still declared where the route expects it, so a cutover that deleted one
/// and left the route green is caught here rather than at a release.
static RETAINED: [Retained; 17] = [
    Retained {
        predicate: "test_cli_python_capabilities",
        root: "pedant/tests/integration.rs",
    },
    Retained {
        predicate: "test_cli_go_file_runs_source_and_manifest_analysis",
        root: "pedant/tests/integration.rs",
    },
    Retained {
        predicate: "test_capabilities_flag_unchanged",
        root: "pedant/tests/attestation.rs",
    },
    Retained {
        predicate: "test_single_file_mode_unchanged",
        root: "pedant/tests/attestation.rs",
    },
    Retained {
        predicate: "test_nonsemantic_attestation_tier_unchanged",
        root: "pedant/tests/attestation.rs",
    },
    Retained {
        predicate: "project_gate_input_modes_are_disjoint_and_legacy_modes_stay_graph_free",
        root: "pedant/tests/gate_cli.rs",
    },
    Retained {
        predicate: "project_gate_outputs_are_exact_and_actionable",
        root: "pedant/tests/gate_cli.rs",
    },
    Retained {
        predicate: "rust_language_token_is_refused_without_tool_surface_change",
        root: "pedant-mcp/tests/tools.rs",
    },
    Retained {
        predicate: "test_stdio_tools_list",
        root: "pedant-mcp/tests/integration.rs",
    },
    Retained {
        predicate: "test_stdio_tools_call_query_capabilities",
        root: "pedant-mcp/tests/integration.rs",
    },
    Retained {
        predicate: "test_index_gate_verdicts",
        root: "pedant-mcp/tests/index.rs",
    },
    Retained {
        predicate: "mcp_watcher_cutover_preserves_incremental_reindex_and_removal",
        root: "pedant-mcp/tests/watcher.rs",
    },
    Retained {
        predicate: "test_watcher_keeps_last_good_result_and_marks_file_degraded",
        root: "pedant-mcp/tests/watcher.rs",
    },
    Retained {
        predicate: "test_watcher_removes_stale_entry_after_rename",
        root: "pedant-mcp/tests/watcher.rs",
    },
    Retained {
        predicate: "go_graph_is_deterministic_and_rust_graph_bytes_stay_exact",
        root: "pedant-graph/tests/graph.rs",
    },
    Retained {
        predicate: "go_graph_uses_schema_v1_without_new_wire_branches",
        root: "pedant-graph/tests/graph.rs",
    },
    Retained {
        predicate: "go_graph_uses_existing_queries_and_rust_cache_answers_stay_exact",
        root: "pedant-graph/tests/graph.rs",
    },
];

/// 9.T8 (Invariant 21): neither non-navigation product registers a navigation
/// command, tool, or index, and every retained byte control is still declared.
#[test]
fn non_navigation_product_registries_exclude_code_intelligence() {
    assert_no_navigation_name_is_declared();
    assert_neither_product_depends_on_the_navigation_crate();
    assert_every_retained_control_is_still_declared();
}

/// No source in either non-navigation product declares a navigation name.
///
/// Comment lines are skipped: a module that explains why the navigation surface
/// lives elsewhere is documentation, and a scan that refused it would push the
/// reasoning out of the code that needs it.
fn assert_no_navigation_name_is_declared() {
    let names = navigation_names();
    let mut offenders: Vec<Box<str>> = Vec::new();
    for tree in NON_NAVIGATION_TREES {
        let held: Box<[&Source]> = first_party_sources()
            .iter()
            .filter(|source| source.path.starts_with(tree))
            .collect();
        assert!(
            held.len() >= MINIMUM_TREE_SOURCES,
            "the scan read {} sources under {tree}, so it is not reading that product",
            held.len()
        );
        offenders.extend(
            held.iter()
                .flat_map(|source| navigation_names_stated(source, &names).into_vec()),
        );
    }
    assert!(
        offenders.is_empty(),
        "the lint and security products must register no navigation surface: {offenders:?}"
    );
}

/// Every navigation name one source states outside its comments, with the line.
///
/// The comments are removed as the language defines them rather than by line
/// shape. A reading that dropped every line beginning with `*` dropped live
/// deref assignments with the continuation lines of a block comment, and this
/// scan was one of the three it left blind.
fn navigation_names_stated(source: &Source, names: &[&str]) -> Box<[Box<str>]> {
    code_index(&source.text)
        .iter()
        .flat_map(|(number, line)| {
            names
                .iter()
                .filter(move |name| line.contains(**name))
                .map(move |name| format!("{}:{number}: {name}", source.path).into_boxed_str())
        })
        .collect()
}

/// Neither product declares an edge on the navigation crate.
///
/// The name scan alone would pass a product that reached the whole surface
/// through one `use pedant_snippet::*`, and a dependency edge is what makes any
/// of those names reachable in the first place.
///
/// The reading belongs to `manifest_reader`, which parses rather than searches
/// — a `contains` over raw TOML failed on a mention in a comment or under
/// `[package.metadata]`, and it could not tell a real edge from a
/// dev-dependency — and which floors the answer before testing a name. The
/// provider case states the mirror claim about this crate's own consumers, and
/// the two used to be one walk written twice, neither of them floored.
fn assert_neither_product_depends_on_the_navigation_crate() {
    for product in ["pedant", "pedant-mcp"] {
        assert_requires_none(&format!("{product}/Cargo.toml"), &[NAVIGATION_CRATE]);
    }
}

/// Every retained byte control is declared exactly once in the whole workspace,
/// in the root that runs it.
///
/// Asked of the one cached reading of every member's `tests/` tree, which is
/// where "declared once" is decidable. A `contains` over the named root alone
/// could not see the same predicate declared twice, or a second copy in a root
/// the model never mentions — and it read the root once per row.
fn assert_every_retained_control_is_still_declared() {
    let sources = workspace_test_sources();
    let wrong: Box<[String]> = RETAINED
        .iter()
        .filter_map(|control| {
            let sites = declaration_sites(sources, control.predicate);
            match *sites == [control.root] {
                true => None,
                false => Some(format!(
                    "{} is declared at {sites:?}, and the model says {}",
                    control.predicate, control.root
                )),
            }
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "every retained byte control must still be declared where the route runs it: {wrong:?}"
    );

    let named: BTreeSet<&str> = RETAINED.iter().map(|control| control.predicate).collect();
    assert_eq!(
        named.len(),
        RETAINED.len(),
        "the retained inventory names each control once"
    );
}
