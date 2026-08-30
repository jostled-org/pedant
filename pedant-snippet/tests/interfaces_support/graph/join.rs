//! The join between one graph node and the declaration it states.
//!
//! Two things could stand in for the join and must not: the declared name and
//! the declaration extent. This source states `run` twice — once in a trait,
//! once in the impl that satisfies it — so a name join merges them; and every
//! declaration's own extent strictly contains the identifier a report points
//! at, so an extent comparison between the two finds nothing at all.
//!
//! The mutation rows below make both failures observable from outside the
//! crate: they hold what a broken join would produce and assert the index does
//! not produce it.

use std::collections::BTreeSet;

use pedant_snippet::{CodeIntelligenceState, StructureCoverage, StructureDescriptor};

use super::fixture::{
    BINARIES, LIBRARY_SOURCE, assert_ascending, declaration, indexed_graph, matching,
};

/// Every Rust instance joins by exact definition site, never by name or span.
#[test]
fn rust_definition_instances_join_by_exact_site_identity() {
    let (_repository, state) = indexed_graph();

    equal_names_at_two_sites_state_two_declarations(&state);
    every_instance_names_a_node_the_graph_holds(&state);
    one_source_states_one_instance_per_target(&state);
    an_impl_block_states_no_definition_and_joins_nothing(&state);
    a_declaration_extent_never_matches_an_identifier_extent(&state);
}

/// The trait method and the impl method are two declarations with two
/// instance sets, and neither carries the other's nodes.
fn equal_names_at_two_sites_state_two_declarations(state: &CodeIntelligenceState) {
    let named: Vec<StructureDescriptor> = matching(state, "run")
        .into_vec()
        .into_iter()
        .filter(|structure| structure.path() == LIBRARY_SOURCE)
        .collect();
    assert_eq!(
        named.len(),
        2,
        "the library declares `run` at two sites: {:?}",
        named
            .iter()
            .map(|structure| structure.span())
            .collect::<Vec<_>>()
    );
    let index = state.index();
    let sites: Vec<BTreeSet<(u32, u32)>> = named
        .iter()
        .map(|structure| {
            index
                .structure(structure.handle())
                .expect("the handle is this revision's")
                .instances()
                .iter()
                .map(|instance| (instance.project().position(), instance.node().index()))
                .collect()
        })
        .collect();
    assert!(
        sites.iter().all(|held| !held.is_empty()),
        "each site states its own graph nodes: {sites:?}"
    );
    assert!(
        sites[0].is_disjoint(&sites[1]),
        "and no node is claimed by both sites: {sites:?}"
    );
}

/// Every instance names a node the issuing project's graph actually holds, and
/// that node's own name is this declaration's.
fn every_instance_names_a_node_the_graph_holds(state: &CodeIntelligenceState) {
    let index = state.index();
    let mut checked = 0_usize;
    for structure in index.structures() {
        for instance in structure.instances() {
            let slice = index
                .projects()
                .get(instance.project().position() as usize)
                .expect("an instance names a project this index retained");
            let node = slice
                .graph()
                .node(instance.node())
                .expect("an instance names a node the graph retained");
            assert_eq!(
                Some(node.name()),
                structure.name(),
                "the joined node states this declaration's own name at {}",
                structure.path()
            );
            checked += 1;
        }
    }
    assert!(
        checked > 8,
        "the fixture states enough instances to be worth checking: {checked}"
    );
}

/// One physical library source reached by every target states one instance of
/// its declaration per project graph, and no fewer.
fn one_source_states_one_instance_per_target(state: &CodeIntelligenceState) {
    let made = declaration(state, LIBRARY_SOURCE, "make");
    let index = state.index();
    let instances = index
        .structure(made.handle())
        .expect("the handle is this revision's")
        .instances();
    let projects: BTreeSet<u32> = instances
        .iter()
        .map(|instance| instance.project().position())
        .collect();
    assert_eq!(
        projects.len(),
        1 + BINARIES.len(),
        "the library and every binary reach this source: {projects:?}"
    );
    assert_eq!(
        made.coverage(),
        StructureCoverage::Resolved,
        "and each of them resolved it"
    );
    let ordered: Vec<(u32, u32)> = instances
        .iter()
        .map(|instance| (instance.project().position(), instance.node().index()))
        .collect();
    assert_ascending(&ordered, "instances state one deterministic order");
}

/// A Rust `impl` block declares no name and states no definition, so it joins
/// no graph node.
fn an_impl_block_states_no_definition_and_joins_nothing(state: &CodeIntelligenceState) {
    let index = state.index();
    let blocks: Vec<&pedant_snippet::CodeStructure> = index
        .structures()
        .iter()
        .filter(|structure| structure.kind() == pedant_types::StructureKind::Impl)
        .collect();
    assert!(
        !blocks.is_empty(),
        "the library states an impl block, or this row proves nothing"
    );
    for block in blocks {
        assert!(
            block.instances().is_empty(),
            "an impl block names no definition, so it joins no node at {}",
            block.path()
        );
    }
}

/// No joined node's location extent equals the declaration extent the outline
/// states, so a join written against declaration extents would find nothing.
fn a_declaration_extent_never_matches_an_identifier_extent(state: &CodeIntelligenceState) {
    let index = state.index();
    let made = declaration(state, LIBRARY_SOURCE, "make");
    let structure = index
        .structure(made.handle())
        .expect("the handle is this revision's");
    let instance = structure
        .instances()
        .first()
        .copied()
        .expect("the declaration joined at least one node");
    let slice = index
        .projects()
        .get(instance.project().position() as usize)
        .expect("the instance names a retained project");
    let node = slice
        .graph()
        .node(instance.node())
        .expect("the instance names a retained node");
    let Some(pedant_snippet::GraphNodeLocation::Span { span, .. }) = node.location() else {
        panic!("a joined definition node states a span location");
    };
    let text = index
        .file(structure.path())
        .expect("the source is admitted")
        .text();
    let identifier = slice_of(text, span);
    assert_eq!(
        identifier, "make",
        "the graph points at the declared name, not the declaration"
    );
    let declaration_text = text
        .get(structure.span().byte_range())
        .expect("the declaration span slices its own source");
    assert!(
        declaration_text.len() > identifier.len(),
        "and the declaration is the wider extent: {declaration_text:?}"
    );
}

/// The exact bytes one report span covers in `text`.
///
/// Borrowed from `text` rather than copied out of it. The one caller compares
/// the bytes and reads their length, and neither needs an allocation the source
/// already holds.
fn slice_of<'source>(text: &'source str, span: &pedant_types::SourceSpan) -> &'source str {
    let line = text
        .split_inclusive('\n')
        .nth(span.start().line() as usize)
        .expect("the span names a line of this source");
    let start = span.start().column() as usize;
    let end = span.end().column() as usize;
    line.get(start..end)
        .expect("the span names bytes of that line")
}
