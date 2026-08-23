//! Which owner every graph a caller reuses passes through.
//!
//! Direct and cached construction must reach one planner and one checked
//! assembler, a hit must return before either runs, every identity must come
//! from the one checked insertion owner, and neither building owner may reach a
//! call that returns to it.
//!
//! Every input is a compile-time source read through [`super::scan`].

use super::call_graph::{declared_call_graph, recursive_functions};
use super::projection_ownership::assert_identities_are_minted_by_one_owner;
use super::scan::{code_only, declaring_sources, method_body, position_of, source};

/// Direct and cached construction reach one planner and one checked assembler,
/// a hit returns before either runs, and no graph-building call returns to
/// itself.
///
/// That the direct entry validates, then plans, then assembles is the same
/// claim for every adapter and is read by [`super::ownership`], once per
/// adapter, rather than a second time here.
pub fn assert_projection_has_one_planner_and_assembler() {
    assert_one_planner_and_one_assembler();
    assert_hits_return_before_planning();
    assert_identities_are_minted_by_one_owner();
    assert_no_graph_building_call_cycle();
}

/// Exactly one source declares the planner, and exactly one declares the
/// assembler.
fn assert_one_planner_and_one_assembler() {
    for (owner, declaration) in [
        ("src/rust/projection.rs", "pub(crate) fn plan("),
        ("src/projection/assembly.rs", "pub(crate) fn assemble("),
    ] {
        assert_eq!(
            declaring_sources(declaration),
            vec![owner],
            "{declaration} is declared by exactly its owning source"
        );
        assert_eq!(
            code_only(source(owner)).matches(declaration).count(),
            1,
            "{owner} declares {declaration} exactly once"
        );
    }
}

/// A cached lookup validates before it observes, and a hit returns before the
/// planner or the assembler is reached.
fn assert_hits_return_before_planning() {
    let entry = method_body("src/rust/cache.rs", "build_rust_graph");
    let validated = position_of(&entry, "projection :: validate", "the cached entry");
    let examined = position_of(&entry, "self . graphs", "the cached entry");
    assert!(
        validated < examined,
        "the cached entry validates before it examines retained state"
    );
    for forbidden in ["plan", "assemble"] {
        assert!(
            !entry.contains(forbidden),
            "the cached entry must not reach {forbidden} itself"
        );
        assert!(
            !method_body("src/rust/cache.rs", "reuse").contains(forbidden),
            "a retained graph must be returned without reaching {forbidden}"
        );
    }
    let miss = method_body("src/rust/cache.rs", "build_missing");
    let planned = position_of(&miss, "projection :: plan", "the cached miss");
    let assembled = position_of(&miss, "assembly :: assemble", "the cached miss");
    assert!(
        planned < assembled,
        "a cached miss plans before it assembles"
    );
}

/// Neither graph-building owner can reach a call that returns to it.
///
/// The planner and the assembler are the two owners a reused projection passes
/// through, and both walk their inputs once. A cycle between their passes would
/// be a second traversal no ceiling bounds.
fn assert_no_graph_building_call_cycle() {
    for path in ["src/projection/assembly.rs", "src/rust/projection.rs"] {
        let recursive = recursive_functions(&declared_call_graph(path));
        assert!(
            recursive.is_empty(),
            "{path} must state no graph-building call cycle: {recursive:?}"
        );
    }
}
