//! Tied definition identities, and what a retained projection may join
//! through.
//!
//! The report contract sorts definitions by unit, span, kind, and name and
//! permits equal keys, so two declarations can agree on every column a fragment
//! joins by. The occurrence among them is what keeps them apart, and a record
//! inserted before them moves every dense identity around them without moving
//! either.

use std::collections::{BTreeMap, BTreeSet};

use pedant_graph::{CodeGraph, GraphCache, GraphEdgeOrigin, GraphNode, GraphNodeId};

use super::cache_counting::{Classification, assert_build_classifies};
use super::cache_fixture::{assert_matches_direct, pair, projection_only, restated};
use super::corpus_revision::{REVISION_CORPUS, REVISION_FRAGMENTS};
use super::fixture::{self, CORPUS_LIBRARY};
use super::inventory::SOURCES;
use super::promotion::Restatement;
use super::scan::{parsed, token_text};
use super::surface::declared_items;

/// The types a retained projection is reached through, beside their declaring
/// module.
///
/// The roots only. Every type their fields name is followed, so an identity
/// introduced one level down is read by the same scan rather than escaping a
/// list that names only the outermost records.
const RETAINED_PROJECTION_ROOTS: &[(&str, &str)] = &[
    ("src/rust/claim.rs", "SourceKey"),
    ("src/projection/draft.rs", "SourceFragment"),
];

/// Every type the walk from those roots must reach.
///
/// Written down as well as walked: a scan that stopped following fields would
/// otherwise report a clean projection because it read almost none of it.
const REACHED_PROJECTION_TYPES: &[&str] = &[
    "SourceKey",
    "SourceFragment",
    "SourceIdentity",
    "DefinitionProjection",
    "DefinitionIdentity",
    "ReferenceProjection",
    "CandidateProjection",
];

/// The dense identities a retained projection may never hold.
///
/// Each is a position in one complete graph, so an inserted record renumbers
/// every later one. A projection that stored one would answer a later build
/// with an identity that graph never minted.
const DENSE_IDENTITIES: &[&str] = &["GraphNodeId", "GraphReferenceId", "GraphEdgeId"];

/// One declared record, and the type text of every column it holds.
///
/// Variants are columns too: an identity stored in one arm of an enum is stored
/// by every value of that type.
///
/// The declared name is not a column here. Every record is read out of the map
/// that keys it by name, so the key is the one place the name is written.
pub struct DeclaredRecord {
    path: &'static str,
    columns: Vec<(String, String)>,
}

/// No type a retained projection is made of holds a dense graph, reference, or
/// edge identity, at any depth.
///
/// The declared columns are read rather than the module text: the drafts a
/// fragment produces take minted identities as arguments, and a module scan
/// could not tell an argument from a stored column.
pub fn assert_retained_projections_hold_no_dense_identity() {
    let declared = declared_records();
    assert_roots_are_declared_where_modelled(&declared);
    let reached = reached_from_roots(&declared);
    let names: BTreeSet<&str> = reached.iter().map(|(name, _)| *name).collect();
    for expected in REACHED_PROJECTION_TYPES {
        assert!(
            names.contains(expected),
            "the projection walk must reach {expected}, reaching {names:?}"
        );
    }
    let offenders: Vec<String> = reached
        .iter()
        .flat_map(|(name, record)| dense_columns(name, record))
        .collect();
    assert!(
        offenders.is_empty(),
        "a retained projection holds a dense identity: {offenders:?}"
    );
}

/// Every column every record declared under one name holds.
///
/// One name may be several declarations, so every one of them answers. A map
/// resolving a name to whichever source was walked last would silently drop the
/// other declaration's columns from every claim read through here.
pub fn declared_columns(name: &str) -> Vec<String> {
    let declared = declared_records();
    let held = declared
        .get(name)
        .unwrap_or_else(|| panic!("no production source declares {name}"));
    held.iter()
        .flat_map(|record| &record.columns)
        .map(|(column, _)| column.clone())
        .collect()
}

/// Every root of the retained projection is declared by exactly the source the
/// model names, and by no other.
///
/// The model carries the declaring path beside each name, and a walk keyed by
/// name alone would answer for a type of that name wherever it came from. The
/// path is what binds a root to the declaration this case is actually about.
fn assert_roots_are_declared_where_modelled(declared: &BTreeMap<String, Vec<DeclaredRecord>>) {
    for (path, name) in RETAINED_PROJECTION_ROOTS {
        let sites: Vec<&str> = declared
            .get(*name)
            .map(|held| held.iter().map(|record| record.path).collect())
            .unwrap_or_default();
        assert_eq!(
            sites,
            vec![*path],
            "{name} is declared by exactly the source the retained model names"
        );
    }
}

/// Every record this crate's production sources declare, keyed by name.
///
/// A name answers with every declaration that carries it. Two adapters each
/// state their own `Inputs`, their own `Vocabulary`, and their own planned
/// units, so a map of one record per name would resolve an ambiguous name to
/// whichever source came last in the inventory and read the other adapter's
/// columns for nothing — which is exactly how a dense identity stored one side
/// of a collision would escape the scan below.
fn declared_records() -> BTreeMap<String, Vec<DeclaredRecord>> {
    let mut found: BTreeMap<String, Vec<DeclaredRecord>> = BTreeMap::new();
    for entry in SOURCES {
        for (name, record) in declared_in(entry.path) {
            found.entry(name).or_default().push(record);
        }
    }
    found
}

/// Every record one production source declares, beside the name it is declared
/// under.
fn declared_in(path: &'static str) -> Vec<(String, DeclaredRecord)> {
    let file = parsed(path);
    declared_items(&file.items)
        .into_iter()
        .filter_map(|item| match item {
            syn::Item::Struct(found) => Some((
                found.ident.to_string(),
                DeclaredRecord {
                    path,
                    columns: stated_columns(found.fields.iter()),
                },
            )),
            syn::Item::Enum(found) => Some((
                found.ident.to_string(),
                DeclaredRecord {
                    path,
                    columns: stated_columns(
                        found.variants.iter().flat_map(|variant| &variant.fields),
                    ),
                },
            )),
            _ => None,
        })
        .collect()
}

/// Each field's own name beside the type it is declared with.
fn stated_columns<'a>(fields: impl Iterator<Item = &'a syn::Field>) -> Vec<(String, String)> {
    fields
        .map(|field| {
            let column = field
                .ident
                .as_ref()
                .map_or_else(|| "a field".to_owned(), ToString::to_string);
            (column, token_text(&field.ty))
        })
        .collect()
}

/// Every declared record reachable from the retained projection roots.
///
/// A name reaches every declaration that states it. Following one of them would
/// make the walk depend on inventory order, and the columns it never read would
/// be exactly the ones nothing else examines.
fn reached_from_roots(
    declared: &BTreeMap<String, Vec<DeclaredRecord>>,
) -> Vec<(&str, &DeclaredRecord)> {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut pending: Vec<String> = RETAINED_PROJECTION_ROOTS
        .iter()
        .map(|(_, name)| (*name).to_owned())
        .collect();
    let mut reached: Vec<(&str, &DeclaredRecord)> = Vec::new();
    while let Some(name) = pending.pop() {
        let Some((declared_name, found)) = declared.get_key_value(&name) else {
            continue;
        };
        if !visited.insert(name) {
            continue;
        }
        reached.extend(found.iter().map(|record| (declared_name.as_str(), record)));
        pending.extend(
            found
                .iter()
                .flat_map(|record| &record.columns)
                .flat_map(|(_, stated)| named_types(stated)),
        );
    }
    reached
}

/// Every identifier one stated type names.
///
/// A column reaches whatever its type names, however it is wrapped: the types
/// inside `Option<Box<[T]>>` are followed exactly as `T` alone would be.
fn named_types(stated: &str) -> Vec<String> {
    stated
        .split(|character: char| !character.is_alphanumeric() && character != '_')
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Every column of one declared record whose stated type names a dense
/// identity.
fn dense_columns(name: &str, record: &DeclaredRecord) -> Vec<String> {
    record
        .columns
        .iter()
        .filter(|(_, stated)| {
            DENSE_IDENTITIES
                .iter()
                .any(|identity| stated.contains(identity))
        })
        .map(|(column, stated)| format!("{}::{name}::{column} holds {stated}", record.path))
        .collect()
}

/// Definitions tied on every sorted column keep distinct identities through
/// dense assembly, and an inserted or removed earlier record cannot move them.
pub fn assert_tied_definitions_survive_remapping() {
    let (_repository, base) = fixture::resolve_target(REVISION_CORPUS, CORPUS_LIBRARY);
    let mut cache = GraphCache::new(projection_only(64));
    let plain = assert_build_classifies(
        &mut cache,
        pair(&base),
        Classification::retained(0, REVISION_FRAGMENTS),
        "the untied report",
    );

    let tied = restated(&base, Restatement::Tied);
    let doubled = assert_build_classifies(
        &mut cache,
        (&base.snapshot, &tied),
        Classification::retained(REVISION_FRAGMENTS - 1, 1),
        Restatement::Tied.label(),
    );
    assert_matches_direct(
        doubled.graph(),
        (&base.snapshot, &tied),
        Restatement::Tied.label(),
    );
    assert_tied_pair_is_distinct(plain.graph(), doubled.graph(), 1, Restatement::Tied.label());

    let probed = restated(&base, Restatement::TiedProbe);
    let inserted = assert_build_classifies(
        &mut cache,
        (&base.snapshot, &probed),
        Classification::retained(REVISION_FRAGMENTS - 1, 1),
        Restatement::TiedProbe.label(),
    );
    assert_matches_direct(
        inserted.graph(),
        (&base.snapshot, &probed),
        Restatement::TiedProbe.label(),
    );
    assert_tied_pair_is_distinct(
        plain.graph(),
        inserted.graph(),
        2,
        Restatement::TiedProbe.label(),
    );

    let subject = "the tied report after the earlier record is withdrawn";
    let withdrawn = assert_build_classifies(
        &mut cache,
        (&base.snapshot, &tied),
        Classification::retained(REVISION_FRAGMENTS - 1, 1),
        subject,
    );
    assert_matches_direct(withdrawn.graph(), (&base.snapshot, &tied), subject);
    assert_tied_pair_is_distinct(plain.graph(), withdrawn.graph(), 1, subject);
}

/// The tied pair is two nodes over one declaration, contained by one parent,
/// and named by exactly the sites the untied report named.
///
/// The twin is stated after the record it doubles, so the earlier occurrence
/// keeps every candidate edge and the later one is reached by none.
fn assert_tied_pair_is_distinct(
    plain: &CodeGraph,
    restated: &CodeGraph,
    added: usize,
    subject: &str,
) {
    assert_eq!(
        restated.nodes().len(),
        plain.nodes().len() + added,
        "{subject}: the restated report states its further definitions"
    );
    let held = named(plain, "first");
    let twins = named(restated, "first");
    assert_eq!(
        (held.len(), twins.len()),
        (1, 2),
        "{subject}: one declaration is stated twice"
    );
    let (earlier, later) = (twins[0], twins[1]);
    let (held, earlier, later) = (
        node(plain, held[0], subject),
        node(restated, earlier, subject),
        node(restated, later, subject),
    );
    assert_ne!(
        earlier.id(),
        later.id(),
        "{subject}: tied definitions take distinct identities"
    );
    for twin in [earlier, later] {
        assert_eq!(
            (twin.kind(), twin.location()),
            (held.kind(), held.location()),
            "{subject}: both tied nodes state the declaration they were copied from"
        );
    }
    assert_eq!(
        parent_of(restated, earlier.id(), subject),
        parent_of(restated, later.id(), subject),
        "{subject}: both tied nodes are contained by one parent"
    );
    assert_eq!(
        (
            candidate_edges_into(restated, earlier.id()),
            candidate_edges_into(restated, later.id())
        ),
        (candidate_edges_into(plain, held.id()), 0),
        "{subject}: every stated candidate names the occurrence it was stated for"
    );
}

/// Every node of one graph carrying `name`, in mint order.
fn named(graph: &CodeGraph, name: &str) -> Box<[GraphNodeId]> {
    graph
        .nodes()
        .iter()
        .filter(|node| node.name() == name)
        .map(GraphNode::id)
        .collect()
}

/// The node one identity names.
fn node<'graph>(graph: &'graph CodeGraph, id: GraphNodeId, subject: &str) -> &'graph GraphNode {
    graph
        .nodes()
        .iter()
        .find(|node| node.id() == id)
        .unwrap_or_else(|| panic!("{subject}: the graph holds node {}", id.index()))
}

/// The containment parent one node states.
fn parent_of(graph: &CodeGraph, child: GraphNodeId, subject: &str) -> GraphNodeId {
    graph
        .containment()
        .iter()
        .find(|edge| edge.child() == child)
        .map(|edge| edge.parent())
        .unwrap_or_else(|| panic!("{subject}: node {} states a parent", child.index()))
}

/// How many reference-borne edges name one node as their target.
fn candidate_edges_into(graph: &CodeGraph, target: GraphNodeId) -> usize {
    graph
        .edges()
        .iter()
        .filter(|edge| edge.target() == target)
        .filter(|edge| matches!(edge.origin(), GraphEdgeOrigin::Reference { .. }))
        .count()
}
