//! Comparable text taken from the public graph reading surface.
//!
//! Every case asserts against ordered `String` lines rather than nested
//! structures, so each borrowed view is rendered exactly once here and no case
//! reimplements a reader.

use pedant_graph::{
    CodeGraph, GraphEdgeOrigin, GraphNode, GraphNodeKind, GraphNodeLocation, GraphReference,
};
use pedant_types::SourceSpan;

/// Every node as `id|language|name|kind|location`.
pub fn nodes(graph: &CodeGraph) -> Vec<String> {
    graph.nodes().iter().map(node).collect()
}

/// One node as comparable text.
pub fn node(node: &GraphNode) -> String {
    format!(
        "{}|{:?}|{}|{}|{}",
        node.id().index(),
        node.language(),
        node.name(),
        node_kind(node.kind()),
        location(node.location()),
    )
}

/// One node kind as `category:attribute`.
pub fn node_kind(kind: &GraphNodeKind) -> String {
    match kind {
        GraphNodeKind::File => "file".to_owned(),
        GraphNodeKind::Container { level } => format!("container:{level}"),
        GraphNodeKind::Function { declaration } => format!("function:{declaration}"),
        GraphNodeKind::Type { declaration } => format!("type:{declaration}"),
        GraphNodeKind::Value { declaration } => format!("value:{declaration}"),
    }
}

/// The normalized path one file node reads, or `None` for any other node.
///
/// The one place a file node is recognized, so no case spells that predicate a
/// second way.
pub fn file_path(node: &GraphNode) -> Option<&str> {
    match node.location() {
        Some(GraphNodeLocation::File { path }) => Some(path),
        _ => None,
    }
}

/// Whether one node is a unit-qualified file node.
pub fn is_file(node: &GraphNode) -> bool {
    file_path(node).is_some()
}

/// Whether one node is a definition. Definitions are the only span-located
/// nodes, and a file node is located by its path instead.
pub fn is_definition(node: &GraphNode) -> bool {
    matches!(node.location(), Some(GraphNodeLocation::Span { .. }))
}

/// One optional node location as comparable text.
pub fn location(location: Option<&GraphNodeLocation>) -> String {
    match location {
        None => "-".to_owned(),
        Some(GraphNodeLocation::File { path }) => format!("file:{path}"),
        Some(GraphNodeLocation::Span { file, span }) => {
            format!("span:{}@{}", file.index(), coordinates(span))
        }
    }
}

/// One span as `file:startLine:startColumn-endLine:endColumn`.
pub fn coordinates(span: &SourceSpan) -> String {
    format!(
        "{}:{}:{}-{}:{}",
        span.file(),
        span.start().line(),
        span.start().column(),
        span.end().line(),
        span.end().column(),
    )
}

/// Every containment edge as `parent>child`.
pub fn containment(graph: &CodeGraph) -> Vec<String> {
    graph
        .containment()
        .iter()
        .map(|edge| format!("{}>{}", edge.parent().index(), edge.child().index()))
        .collect()
}

/// One reference record as its site, its gaps, and the edges it produced.
///
/// The site is rendered by [`reference_site`] rather than restated here, so the
/// two views cannot disagree about which fields a record carries.
pub fn reference(reference: &GraphReference) -> String {
    format!(
        "{}|{}|{}",
        reference_site(reference),
        joined(reference.gaps().iter().map(|gap| format!("{gap:?}"))),
        joined(
            reference
                .edges()
                .iter()
                .map(|edge| edge.index().to_string())
        ),
    )
}

/// One edge origin as comparable text.
pub fn origin(origin: &GraphEdgeOrigin) -> String {
    match origin {
        GraphEdgeOrigin::Reference { reference } => format!("reference:{}", reference.index()),
        GraphEdgeOrigin::Dependency { evidence } => format!(
            "dependency:{}:{:?}:{}",
            evidence.alias(),
            evidence.kind(),
            evidence.predicate().unwrap_or("-"),
        ),
    }
}

/// The stable site fields of every reference, which no tier may change.
pub fn reference_sites(graph: &CodeGraph) -> Vec<String> {
    graph.references().iter().map(reference_site).collect()
}

/// One reference's site as `id|source|language|kind|text|span`.
pub fn reference_site(reference: &GraphReference) -> String {
    format!(
        "{}|{}|{:?}|{:?}|{}|{}",
        reference.id().index(),
        reference.source().index(),
        reference.language(),
        reference.kind(),
        reference.text(),
        coordinates(reference.span()),
    )
}

fn joined(values: impl Iterator<Item = String>) -> String {
    let collected: Vec<String> = values.collect();
    match collected.is_empty() {
        true => "-".to_owned(),
        false => collected.join(","),
    }
}
