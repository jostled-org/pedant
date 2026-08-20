//! Every reference site of every module instance, stated once in the report.

use std::sync::Arc;

use pedant_types::{ReferenceHandle, ResolutionReportBuilder, ResolutionUnitHandle, SourceSpan};

use crate::ir::sites::ReferenceSite;
use crate::resolution::rust::snapshot::RustResolutionSnapshot;

use crate::resolution::line_index::LineIndex;

use super::coordinates;
use super::error::RustResolutionError;
use super::graph::Graph;
use super::index::Index;
use super::units::Units;

/// One stated reference and where it came from.
pub(super) struct ReferenceEntry {
    pub(super) node: usize,
    pub(super) site: usize,
    pub(super) handle: ReferenceHandle,
    /// The report coordinates of the reference, which a later tier joins on.
    pub(super) span: SourceSpan,
}

/// State every reference the snapshot's module instances hold.
pub(super) fn add_references(
    builder: &mut ResolutionReportBuilder,
    snapshot: &RustResolutionSnapshot,
    graph: &Graph,
    parts: (&Index, &Units, &[LineIndex]),
) -> Result<Box<[ReferenceEntry]>, RustResolutionError> {
    let mut entries = Vec::new();
    for node in 0..graph.nodes.len() {
        add_node(builder, snapshot, (graph, parts), (&mut entries, node))?;
    }
    Ok(entries.into_boxed_slice())
}

fn add_node(
    builder: &mut ResolutionReportBuilder,
    snapshot: &RustResolutionSnapshot,
    corpus: (&Graph, (&Index, &Units, &[LineIndex])),
    target: (&mut Vec<ReferenceEntry>, usize),
) -> Result<(), RustResolutionError> {
    let (graph, (index, units, indexed)) = corpus;
    let (entries, node) = target;
    let Some(entry) = graph.nodes.get(node) else {
        return Ok(());
    };
    let (Some(source), Some(unit), Some(lines)) = (
        graph.source(snapshot, node),
        units.handles.get(entry.unit),
        indexed.get(entry.file),
    ) else {
        return Ok(());
    };
    let stated = source
        .ir()
        .reference_sites
        .iter()
        .enumerate()
        .filter(|(_, reference)| reference.scope == entry.scope);
    for (site, reference) in stated {
        let context = SiteContext {
            graph,
            index,
            unit,
            node,
            site,
        };
        let span = coordinates::span(lines, source.text(), source.shared_path(), reference.range);
        entries.extend(add_site(builder, snapshot, &context, (reference, span))?);
    }
    Ok(())
}

/// What one reference site is stated against.
struct SiteContext<'a> {
    graph: &'a Graph,
    index: &'a Index,
    unit: &'a ResolutionUnitHandle,
    node: usize,
    site: usize,
}

/// State one reference, when its range exists in the exact snapshotted text.
fn add_site(
    builder: &mut ResolutionReportBuilder,
    snapshot: &RustResolutionSnapshot,
    context: &SiteContext<'_>,
    stated: (&ReferenceSite, Option<SourceSpan>),
) -> Result<Option<ReferenceEntry>, RustResolutionError> {
    let (reference, span) = stated;
    let Some(span) = span else {
        return Ok(None);
    };
    let enclosing = enclosing_slot(
        context.graph,
        (snapshot, context.index),
        context.node,
        reference,
    );
    let handle = builder.add_reference(
        context.unit,
        reference.kind,
        Arc::from(&*reference.text),
        span.clone(),
        enclosing
            .and_then(|slot| context.index.slot(slot))
            .map(|slot| &slot.handle),
    )?;
    Ok(Some(ReferenceEntry {
        node: context.node,
        site: context.site,
        handle,
        span,
    }))
}

/// The definition one reference sits inside, resolved to the module instance
/// that holds it.
fn enclosing_slot(
    graph: &Graph,
    corpus: (&RustResolutionSnapshot, &Index),
    node: usize,
    reference: &ReferenceSite,
) -> Option<usize> {
    let (snapshot, index) = corpus;
    let enclosing = reference.enclosing?;
    let file = graph.nodes.get(node)?.file;
    let scope = graph
        .file_ir(snapshot, node)?
        .definition_sites
        .get(enclosing)?
        .scope;
    let owner = graph.node_for_scope(node, file, scope)?;
    index.at(owner, enclosing)
}
