//! What the published package states about itself: one dependency closure, one
//! module inventory, one registered wrapper per predicate, and no function
//! declared twice.
//!
//! Every structural input is compiled in, so the whole reading surface of these
//! cases is the argument of a compile-time inclusion. Each argument is held
//! against the tracked roots this crate owns, and no production source may
//! state a file, process, or network site at all.

use super::analysis_source_boundary::{
    assert_every_registered_wrapper_is_modelled, assert_functions_are_declared_once,
    assert_manifest_states_no_delta, assert_no_test_lives_outside_the_root,
};
use super::cache_ownership::assert_cache_modules_are_discovered;
use super::inventory::{
    CACHE_SOURCES, PRODUCTION_SOURCES, SOURCES, TEST_ROOT, TEST_SUPPORT_SOURCES,
};
use super::scan::{code_only, compact};

/// Every predicate the cache family registers at the one root.
pub const CACHE_PREDICATES: &[&str] = &[
    "cached_graph_analysis_is_thread_shareable_and_deterministic",
    "cached_graph_analysis_matches_every_direct_operation",
    "cached_graph_analysis_rechecks_every_limit_before_hits",
    "cached_graph_analysis_retention_is_bounded_lru",
    "cached_graph_analysis_reuses_exact_arc_products_and_none",
    "graph_cache_clear_eviction_and_drop_keep_live_handles_valid",
    "graph_cache_counter_updates_are_saturating_and_single_owned",
    "graph_cache_exact_build_matches_direct_graph_and_json",
    "graph_cache_exact_hits_share_graph_and_short_circuit_work",
    "graph_cache_exact_identity_guards_the_complete_resolution_claim",
    "graph_cache_exact_retention_is_bounded_lru",
    "graph_cache_hits_reapply_graph_limits_in_direct_order",
    "graph_cache_poison_recovery_is_explicit_and_total",
    "graph_cache_projection_has_one_planner_and_assembler",
    "graph_cache_public_boundary_is_exact",
    "graph_cache_rejects_invalid_pairs_before_observation",
    "graph_cache_reuses_only_exact_source_unit_claims",
    "graph_cache_revision_matrix_matches_direct_graph_and_json",
    "graph_cache_source_boundary_is_exact",
    "graph_cache_source_projection_retention_is_bounded_lru",
    "graph_cache_tied_definition_identities_survive_dense_remapping",
];

/// The only roots a compiled-in structural input may be read from, as the whole
/// argument it is written with.
///
/// This crate's own sources, its one registered root, and its own manifest. A
/// plan, a specification, or a lifecycle manifest is outside every one of them.
const TRACKED_INPUTS: &[&str] = &["\"../../src/", "\"../graph.rs\"", "\"../../Cargo.toml\""];

/// The only pieces an assembled argument may be built from.
///
/// One macro builds a sibling support module's path out of the module name it
/// was handed and the extension every one of them carries. An assembled
/// argument that names anything else — a manifest directory, a plan, a
/// lifecycle file — fails on the piece that names it, so admitting assembly
/// does not admit whatever assembly can reach.
const TRACKED_FRAGMENTS: &[&str] = &["$name", "\".rs\""];

/// The one registered root, under the path a failure reports it at.
const TEST_ROOT_PATH: &str = "tests/graph.rs";

/// Every cache-family module, beside the one entry point built on them.
///
/// Named so the duplicate scan states a floor this family carries: eight cache
/// modules and the adapter's cache declare two free functions between them, so a
/// floor over the whole crate is met by families this claim is not about.
const CACHE_FAMILY_SOURCES: &[&str] = &["src/rust/cache.rs", "src/rust/reuse.rs"];

/// The spellings a file, process, or network site would be written with.
const CAPABILITY_SPELLINGS: &[&str] = &[
    "std::fs",
    "std::net",
    "std::process",
    "File::open",
    "File::create",
    "TcpStream",
    "UdpSocket",
    "Command::new",
    "read_to_string",
    "read_dir",
    "include!",
    "include_str!",
    "include_bytes!",
];

/// The published package still states one dependency closure, one module
/// inventory, one registered wrapper per predicate, and no function twice.
pub fn assert_cache_source_boundary_is_exact() {
    assert_manifest_states_no_delta();
    assert_no_test_lives_outside_the_root();
    assert_cache_modules_are_discovered();
    assert_every_cache_predicate_is_registered_once();
    assert_every_registered_wrapper_is_modelled();
    assert_reads_no_lifecycle_file();
    assert_states_no_capability();
    assert_functions_are_declared_once(PRODUCTION_SOURCES, 200, "this crate");
    assert_functions_are_declared_once(&cache_family(), 18, "the cache family");
}

/// Every module the cache claim is about, in inventory order.
fn cache_family() -> Vec<&'static str> {
    CACHE_SOURCES
        .iter()
        .chain(CACHE_FAMILY_SOURCES.iter())
        .copied()
        .collect()
}

/// Every predicate this family registers is a bare wrapper, registered once.
fn assert_every_cache_predicate_is_registered_once() {
    for predicate in CACHE_PREDICATES {
        assert_eq!(
            TEST_ROOT
                .matches(&format!("#[test]\nfn {predicate}()"))
                .count(),
            1,
            "{predicate} is registered exactly once, with its bare identity"
        );
    }
}

/// No test reads a lifecycle document, a plan, or a repository script.
///
/// Every structural input is compiled in, so the whole reading surface is the
/// argument of a compile-time inclusion. Each one is held against the tracked
/// roots this crate owns: its own sources, its own registered root, its own
/// manifest, and its sibling support modules. Anything else — a plan, a
/// specification, a lifecycle manifest, a script — fails, whether or not this
/// case has heard of it.
///
/// Every compiled file is scanned, the registered root included: the file every
/// predicate is declared in reads no more than the modules beneath it. And every
/// spelling of the inclusion family is matched, so a byte inclusion or a
/// path-qualified one cannot slip a plan in past a scan that knew one macro.
fn assert_reads_no_lifecycle_file() {
    let offenders: Vec<String> = TEST_SUPPORT_SOURCES
        .iter()
        .chain(SOURCES.iter())
        .map(|entry| (entry.path, entry.text))
        .chain(std::iter::once((TEST_ROOT_PATH, TEST_ROOT)))
        .flat_map(|(path, text)| {
            included_arguments(text)
                .into_iter()
                .filter(|argument| !is_tracked(argument))
                .map(move |argument| format!("{path} reads {argument}"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "every compiled-in input is a tracked root of this crate: {offenders:?}"
    );
}

/// Whether one inclusion argument names a tracked root.
///
/// An assembled argument is resolved rather than admitted: every piece it is
/// built from is held against the fragments the one assembling macro states, so
/// assembling a plan's path fails on the piece that spells it.
fn is_tracked(argument: &str) -> bool {
    match argument.strip_prefix(&assembly()) {
        Some(listed) => listed.strip_suffix(')').is_some_and(|pieces| {
            pieces
                .split(',')
                .all(|piece| TRACKED_FRAGMENTS.contains(&piece))
        }),
        None => TRACKED_INPUTS.iter().any(|root| argument.starts_with(root)),
    }
}

/// Every argument one source states a compile-time inclusion with.
///
/// Read from the compacted text, so an argument the formatter wrapped is one
/// argument, and taken to the parenthesis that closes it, so an assembled
/// argument arrives whole rather than truncated at its first nested call.
fn included_arguments(text: &str) -> Vec<String> {
    let code = compact(text);
    inclusions()
        .iter()
        .flat_map(|needle| {
            code.match_indices(needle.as_str())
                .map(|(at, opening)| enclosed(&code, at + opening.len()))
                .collect::<Vec<String>>()
        })
        .collect()
}

/// The text one already-opened parenthesis encloses.
fn enclosed(code: &str, from: usize) -> String {
    let mut depth = 1_usize;
    let mut taken = String::new();
    for character in code[from..].chars() {
        match character {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => (),
        }
        if depth == 0 {
            return taken;
        }
        taken.push(character);
    }
    panic!("an inclusion at {from} states no closing parenthesis: {taken}")
}

/// Every macro spelling a compiled-in input is read through.
///
/// Assembled rather than written whole, for the reason comments are stripped
/// before every structural scan: a case looking for a spelling must not read as
/// the thing it is looking for. A path-qualified spelling ends in one of these,
/// so `std::include_str!` is matched by the same needle the bare one is.
fn inclusions() -> Vec<String> {
    ["include", "include_bytes", "include_str"]
        .into_iter()
        .map(|spelling| format!("{spelling}{}(", '!'))
        .collect()
}

/// The macro spelling an argument is assembled with.
fn assembly() -> String {
    format!("concat{}(", '!')
}

/// No production source states a file, process, or network site.
fn assert_states_no_capability() {
    let offenders: Vec<String> = SOURCES
        .iter()
        .flat_map(|entry| {
            let code = code_only(entry.text);
            CAPABILITY_SPELLINGS
                .iter()
                .filter(move |spelling| code.contains(**spelling))
                .map(move |spelling| format!("{} names {spelling}", entry.path))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "graph production sources state no file, process, or network site: {offenders:?}"
    );
}
