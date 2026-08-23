//! Go node inventory, source association, and the containment forest.
//!
//! Every case builds through the production path — load, snapshot, resolve,
//! project — and then reads the report and the graph side by side. Nothing is
//! written down that the report already states: the expected node set is
//! derived from the claims, so a corpus that grows a declaration grows both
//! sides at once.

use std::collections::{BTreeMap, BTreeSet};

use pedant_graph::{CodeGraph, GraphNode, GraphNodeId, GraphNodeKind, GraphNodeLocation};
use pedant_types::{ResolutionReport, SymbolDefinition, SymbolKind};

use super::go_corpus::{GO_CORPUS, GO_SHARED_SOURCE_CORPUS};
use super::go_fixture::{GoResolved, project_go};
use super::go_model::{MODULE_LEVEL, PACKAGE_LEVEL};

/// One graph node's container level, when it is a container at all.
pub fn container_level(node: &GraphNode) -> Option<&str> {
    match node.kind() {
        GraphNodeKind::Container { level } => Some(level),
        _ => None,
    }
}

/// Every node of one container level, in dense order.
pub fn containers<'graph>(graph: &'graph CodeGraph, level: &str) -> Vec<&'graph GraphNode> {
    graph
        .nodes()
        .iter()
        .filter(|node| container_level(node) == Some(level))
        .collect()
}

/// Every file node, in dense order.
pub fn files(graph: &CodeGraph) -> Vec<&GraphNode> {
    graph
        .nodes()
        .iter()
        .filter(|node| *node.kind() == GraphNodeKind::File)
        .collect()
}

/// The parent every contained node states.
pub fn parents(graph: &CodeGraph) -> BTreeMap<u32, u32> {
    graph
        .containment()
        .iter()
        .map(|edge| (edge.child().index(), edge.parent().index()))
        .collect()
}

/// One module container node per admitted module, one package node per report
/// unit, one file node per unit-qualified source, and one node per definition.
///
/// Every claim family is answered, rendered as its own row, and the whole table
/// is compared once. A chain of assertions would abort on the first family that
/// moved, so a build that got the modules wrong could never be seen agreeing
/// about the files, and no receipt could bound more than one family at a time.
pub fn assert_one_package_and_definition_node_per_claim() {
    let (resolved, graph) = project_go(GO_CORPUS);
    let report = resolved.resolution.report();
    assert_eq!(
        stated_inventory(&graph),
        claimed_inventory(&resolved, report),
        "the graph states one node per module, source, and definition claim, and no other"
    );
}

/// Every row of the inventory, read out of the built graph alone.
fn stated_inventory(graph: &CodeGraph) -> Vec<String> {
    let parents = parents(graph);
    let mut rows = vec![
        format!("packages|{}", named(&containers(graph, PACKAGE_LEVEL))),
        format!("modules|{}", containers(graph, MODULE_LEVEL).len()),
        format!("files|{}", files(graph).len()),
        format!("nodes|{}", graph.nodes().len()),
        format!("claims|{}", rendered(&declared_nodes(graph))),
        format!("vocabulary|{}", stated_vocabulary(graph)),
    ];
    rows.extend(NAMED_DECLARATIONS.iter().map(|(name, holder, _)| {
        declared_row(
            (name, holder),
            declared_inside(graph, &parents, (name, holder)),
        )
    }));
    rows
}

/// The same rows, derived from the report and the snapshot that produced it.
fn claimed_inventory(resolved: &GoResolved, report: &ResolutionReport) -> Vec<String> {
    let modules = resolved.snapshot.modules().len();
    let sources = instantiated_sources(resolved);
    let mut rows = vec![
        format!("packages|{}", package_names(report).join(", ")),
        format!("modules|{modules}"),
        format!("files|{sources}"),
        format!(
            "nodes|{}",
            modules
                .saturating_add(sources)
                .saturating_add(report.definitions().len())
        ),
        format!("claims|{}", rendered(&declared_claims(report))),
        format!("vocabulary|{}", modelled_vocabulary()),
    ];
    rows.extend(
        NAMED_DECLARATIONS
            .iter()
            .map(|(name, holder, token)| declared_row((name, holder), (*token).to_owned())),
    );
    rows
}

/// One named declaration's row, whichever side answered it.
fn declared_row(declared: (&str, &str), token: String) -> String {
    let (name, holder) = declared;
    format!("{name} in {holder}|{token}")
}

/// Every container node's name, in dense order.
fn named(nodes: &[&GraphNode]) -> String {
    nodes
        .iter()
        .map(|node| node.name())
        .collect::<Vec<&str>>()
        .join(", ")
}

/// One line per stated tuple, so a whole set compares as one row.
fn rendered(stated: &[(String, String, String)]) -> String {
    stated
        .iter()
        .map(|(name, file, span)| format!("{name}@{file}{span}"))
        .collect::<Vec<String>>()
        .join(" ")
}

/// Every declaration token a Go graph may state, beside the node category it
/// belongs to.
///
/// Written down rather than derived: deriving it from the projection's own
/// vocabulary would be that mapping restated, and would agree with whatever the
/// adapter happened to emit.
const GO_DECLARATIONS: &[(&str, &str)] = &[
    ("container", "module"),
    ("container", "package"),
    ("function", "function"),
    ("function", "method"),
    ("function", "interface_method"),
    ("type", "struct"),
    ("type", "interface"),
    ("type", "defined_type"),
    ("type", "type_alias"),
    ("value", "constant"),
    ("value", "variable"),
    ("value", "field"),
];

/// The declaration token four named nodes of the corpus take.
///
/// A method and an interface method share a report kind and are told apart by
/// the definition that holds them, so both spellings are named here beside a
/// type and a value that could not be confused for either.
const NAMED_DECLARATIONS: &[(&str, &str, &str)] = &[
    ("Widget", "app", "struct"),
    ("Shape", "shapes", "interface"),
    ("Area", "Widget", "method"),
    ("Area", "Shape", "interface_method"),
];

/// Every declaration token the built graph states, in one sorted line.
fn stated_vocabulary(graph: &CodeGraph) -> String {
    let stated: BTreeSet<(&str, &str)> = graph.nodes().iter().filter_map(declared_token).collect();
    tokens(stated.into_iter())
}

/// The written-down vocabulary, in the same line shape.
fn modelled_vocabulary() -> String {
    tokens(GO_DECLARATIONS.iter().copied())
}

/// One sorted line of category-and-token pairs.
fn tokens<'a>(stated: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    let mut rendered: Vec<String> = stated
        .map(|(category, token)| format!("{category}:{token}"))
        .collect();
    rendered.sort();
    rendered.join(" ")
}

/// The token every node of one name declared inside one holder states.
///
/// A name the corpus does not declare inside that holder answers `absent`
/// rather than nothing, so a missing declaration and a mistyped one are two
/// different rows instead of one silent pass.
fn declared_inside(
    graph: &CodeGraph,
    parents: &BTreeMap<u32, u32>,
    declared: (&str, &str),
) -> String {
    let (name, holder) = declared;
    let found: BTreeSet<&str> = graph
        .nodes()
        .iter()
        .filter(|node| node.name() == name)
        .filter(|node| holds(graph, parents, node.id().index()) == Some(holder))
        .filter_map(|node| declared_token(node).map(|(_, stated)| stated))
        .collect();
    match found.is_empty() {
        true => "absent".to_owned(),
        false => found.into_iter().collect::<Vec<&str>>().join(", "),
    }
}

/// The category and declaration token one node states, when it states one.
fn declared_token(node: &GraphNode) -> Option<(&str, &str)> {
    match node.kind() {
        GraphNodeKind::File => None,
        GraphNodeKind::Container { level } => Some(("container", level)),
        GraphNodeKind::Function { declaration } => Some(("function", declaration)),
        GraphNodeKind::Type { declaration } => Some(("type", declaration)),
        GraphNodeKind::Value { declaration } => Some(("value", declaration)),
    }
}

/// The name of the node one contained node sits inside.
fn holds<'graph>(
    graph: &'graph CodeGraph,
    parents: &BTreeMap<u32, u32>,
    node: u32,
) -> Option<&'graph str> {
    let parent = parents.get(&node)?;
    graph.nodes().get(*parent as usize).map(|held| held.name())
}

/// The package clause each report unit declares, in report unit order.
fn package_names(report: &ResolutionReport) -> Vec<String> {
    let mut named: Vec<(u32, String)> = report
        .definitions()
        .iter()
        .filter(|definition| definition.kind() == SymbolKind::Package)
        .map(|definition| (definition.unit().index(), definition.name().to_owned()))
        .collect();
    named.sort_by_key(|(unit, _)| *unit);
    named.into_iter().map(|(_, name)| name).collect()
}

/// How many unit-qualified sources the snapshot's package contexts instantiate.
fn instantiated_sources(resolved: &GoResolved) -> usize {
    resolved
        .snapshot
        .units()
        .iter()
        .map(|unit| unit.sources().len())
        .sum()
}

/// Every declaration node, as the claim it should have come from.
fn declared_nodes(graph: &CodeGraph) -> Vec<(String, String, String)> {
    let mut stated: Vec<(String, String, String)> = graph
        .nodes()
        .iter()
        .filter_map(|node| match node.location() {
            Some(GraphNodeLocation::Span { file, span }) => Some((
                node.name().to_owned(),
                located(graph, *file),
                format!("{span:?}"),
            )),
            _ => None,
        })
        .collect();
    stated.sort();
    stated
}

/// Every definition the report claims, in the same shape a node states.
fn declared_claims(report: &ResolutionReport) -> Vec<(String, String, String)> {
    let mut claimed: Vec<(String, String, String)> = report
        .definitions()
        .iter()
        .map(|definition| {
            let span = SymbolDefinition::span(definition);
            (
                definition.name().to_owned(),
                span.file().to_owned(),
                format!("{span:?}"),
            )
        })
        .collect();
    claimed.sort();
    claimed
}

/// The normalized path one file node names.
fn located(graph: &CodeGraph, file: GraphNodeId) -> String {
    graph
        .node(file)
        .map(|node| node.name().to_owned())
        .unwrap_or_else(|| panic!("a span names file node {} the graph holds", file.index()))
}

/// Containment is total, acyclic, exactly module over package over file over
/// definition, and stated nowhere else.
pub fn assert_containment_is_total_acyclic_and_relation_free() {
    let (_resolved, graph) = project_go(GO_CORPUS);
    let parents = parents(&graph);
    assert_eq!(
        parents.len(),
        graph.containment().len(),
        "no node is contained twice"
    );

    let modules: BTreeSet<u32> = containers(&graph, MODULE_LEVEL)
        .iter()
        .map(|node| node.id().index())
        .collect();
    let packages: BTreeSet<u32> = containers(&graph, PACKAGE_LEVEL)
        .iter()
        .map(|node| node.id().index())
        .collect();

    for node in graph.nodes() {
        let held = parents.get(&node.id().index()).copied();
        assert_parent_is_exact(&graph, (node, held), (&modules, &packages));
    }
    assert_no_chain_returns_to_itself(&graph, &parents);
    assert_containment_is_not_an_edge(&graph, &parents);
}

/// Every node states the one parent its level allows, and a module states none.
fn assert_parent_is_exact(
    graph: &CodeGraph,
    stated: (&GraphNode, Option<u32>),
    levels: (&BTreeSet<u32>, &BTreeSet<u32>),
) {
    let (node, held) = stated;
    let (modules, packages) = levels;
    let at = node.id().index();
    let parent = match (modules.contains(&at), held) {
        (true, parent) => {
            assert_eq!(parent, None, "module node {at} is contained by nothing");
            return;
        }
        (false, None) => panic!("node {at} is contained by nothing and is not a module"),
        (false, Some(parent)) => parent,
    };
    let allowed = match (packages.contains(&at), *node.kind() == GraphNodeKind::File) {
        (true, _) => modules.contains(&parent),
        (_, true) => packages.contains(&parent),
        _ => packages.contains(&parent) || is_declaration(graph, parent),
    };
    assert!(
        allowed,
        "node {at} ({:?}) states parent {parent}, which its level does not allow",
        node.kind()
    );
}

/// Whether one node is a declaration rather than a module, package, or file.
fn is_declaration(graph: &CodeGraph, node: u32) -> bool {
    graph
        .nodes()
        .get(node as usize)
        .is_some_and(|held| match held.kind() {
            GraphNodeKind::File => false,
            GraphNodeKind::Container { level } => {
                &**level != MODULE_LEVEL && &**level != PACKAGE_LEVEL
            }
            _ => true,
        })
}

/// No containment chain returns to a node it already visited.
fn assert_no_chain_returns_to_itself(graph: &CodeGraph, parents: &BTreeMap<u32, u32>) {
    for node in graph.nodes() {
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        let mut current = Some(node.id().index());
        while let Some(at) = current {
            assert!(
                seen.insert(at),
                "the containment chain above node {} returns to {at}",
                node.id().index()
            );
            current = parents.get(&at).copied();
        }
    }
}

/// No containment pair is restated as a reference edge or a dependency edge.
fn assert_containment_is_not_an_edge(graph: &CodeGraph, parents: &BTreeMap<u32, u32>) {
    let restated: Vec<u32> = graph
        .edges()
        .iter()
        .filter(|edge| parents.get(&edge.target().index()) == Some(&edge.source().index()))
        .map(|edge| edge.id().index())
        .collect();
    assert!(
        restated.is_empty(),
        "containment is its own relation; these edges restate it: {restated:?}"
    );
}

/// One snapshot source read once, and one file node per package context that
/// instantiates it.
pub fn assert_shared_source_has_two_unit_file_nodes() {
    let (resolved, graph) = project_go(GO_SHARED_SOURCE_CORPUS);
    let shared = "value.go";
    assert_eq!(
        resolved
            .snapshot
            .sources()
            .iter()
            .filter(|source| source.path() == shared)
            .count(),
        1,
        "the snapshot stores the shared source exactly once"
    );
    let instantiating: Vec<&str> = resolved
        .snapshot
        .units()
        .iter()
        .filter(|unit| unit.sources().iter().any(|path| &**path == shared))
        .map(|unit| unit.package_name())
        .collect();
    assert_eq!(
        instantiating.len(),
        2,
        "two package contexts instantiate the shared source: {instantiating:?}"
    );

    let nodes: Vec<&GraphNode> = files(&graph)
        .into_iter()
        .filter(|node| node.name() == shared)
        .collect();
    assert_eq!(
        nodes.len(),
        2,
        "the shared source takes one file node per package context"
    );
    let owners: BTreeSet<u32> = nodes
        .iter()
        .map(|node| {
            parents(&graph)
                .get(&node.id().index())
                .copied()
                .unwrap_or_else(|| panic!("file node {} states a parent", node.id().index()))
        })
        .collect();
    assert_eq!(
        owners.len(),
        2,
        "the two file nodes are qualified by two different package contexts"
    );
    assert!(
        owners.iter().all(
            |owner| graph.nodes().get(*owner as usize).map(container_level)
                == Some(Some(PACKAGE_LEVEL))
        ),
        "each shared file node sits beneath a package node"
    );
}
