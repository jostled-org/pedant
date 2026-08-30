//! The text projection of one answer.
//!
//! A projection, not a second answer. Every field it prints is read out of the
//! same [`Answered`] the JSON renderer serializes, so the two cannot state
//! different facts — the text one states fewer of them, for a reader rather
//! than a program.
//!
//! Two shapes only: a table of tab-separated rows, or the exact source bytes a
//! structure covers. A structure's source is printed alone and unterminated,
//! because it is the file's own bytes and anything appended would no longer be
//! the extract a caller asked for.
//!
//! The refusal rendering lives here too, because it is the other thing both
//! transports write and neither of them may spell on its own.

use std::collections::BTreeMap;
use std::fmt::Write;

use pedant_snippet::{CodeIntelligenceError, FileOutline, ProjectRecord, StructureDescriptor};

use crate::operation::Answered;

/// What one indent level of an outline costs.
const INDENT: &str = "  ";

/// What a text row prints where the record states no value.
///
/// Gated with its one reader. Every other cell a text row prints is read off an
/// accessor that always answers, so the marker exists for the graph rows alone
/// — a graph member this index retained no declaration for.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
const ABSENT: &str = "-";

/// One answer, projected for a reader.
///
/// A free function rather than a method: this is one renderer's reading of an
/// answer, not something the answer knows about itself. `Answered`'s own API is
/// the JSON both transports send, and it lives beside the type.
///
/// The rendering is returned as the `String` its rows were pushed into. Nothing
/// outlives it — the one caller writes the bytes to standard output and drops
/// them — and `into_boxed_str` would reallocate and copy the whole projection to
/// shed a capacity that dies on the next line.
///
/// Every row is written straight into that one buffer. A row built as its own
/// `String` and then copied in is one throwaway allocation per rendered item,
/// and `write!` to a `String` cannot fail, so there is nothing the copy bought.
pub(crate) fn text(answer: &Answered) -> String {
    let mut rendered = String::new();
    match answer {
        Answered::Projects(response) => rows(&mut rendered, response.result(), project_row),
        Answered::Symbols(response) => rows(&mut rendered, response.result(), structure_row),
        Answered::Outline(response) => outline(&mut rendered, response.result()),
        // The one projection that is not a table: a structure's source is the
        // file's own bytes, so it is printed exactly and alone.
        Answered::Source(response) => rendered.push_str(response.result().text()),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        Answered::Relations(response) => rows(&mut rendered, response.result(), neighborhood_row),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        Answered::Path(response) => path(&mut rendered, response.result()),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        Answered::Analysis(response) => analysis(&mut rendered, response.result()),
    }
    rendered
}

/// One terminated line per item.
///
/// An empty result prints nothing at all, which is what a successful empty
/// answer looks like to a reader and to every line-oriented tool downstream.
///
/// Takes the items and a callable rather than a response and a `fn` pointer.
/// Typed to the response, this could only serve the three paged answers; typed
/// to the slice, every table in this module is one call — including the analysis
/// arms, each of which closes over the answer it is measuring.
fn rows<T>(out: &mut String, items: &[T], row: impl Fn(&mut String, &T)) {
    for item in items {
        row(out, item);
        out.push('\n');
    }
}

/// One project: its position, language, authority, unit, coverage, and health.
fn project_row(out: &mut String, record: &ProjectRecord) {
    write!(
        out,
        "{}\t{}\t{}\t{}\t{}\t{}",
        record.handle().id().position(),
        record.language().token(),
        record.authority(),
        record.unit(),
        record.coverage().token(),
        record.health().status().token(),
    )
    .ok();
}

/// One structure: where it is, what it declares, and how to read it back.
fn structure_row(out: &mut String, record: &StructureDescriptor) {
    let span = record.span();
    write!(
        out,
        "{}\t{}-{}\t{}\t{}\t{}",
        record.path(),
        span.start_line(),
        span.end_line(),
        record.kind().token(),
        record.qualified_name(),
        record.handle().id().position(),
    )
    .ok();
}

/// One file's forest: a header, then one indented line per structure.
///
/// The indent is the depth of the owner chain, which is what makes the printed
/// shape the forest rather than a flat list in source order.
fn outline(out: &mut String, outline: &FileOutline) {
    writeln!(out, "{}\t{}", outline.path(), outline.language().token()).ok();
    let depths = owner_depths(outline.structures());
    for (record, depth) in outline.structures().iter().zip(depths.iter().copied()) {
        for _ in 0..depth {
            out.push_str(INDENT);
        }
        structure_row(out, record);
        out.push('\n');
    }
}

/// How deep each structure sits in its file's owner forest, in structure order.
///
/// Built in one pass because an owner is always earlier in source order than
/// what it owns: by the time a record is reached, its owner's depth is already
/// known. A record whose owner is missing is a root, which is what an outline
/// of a file the owner links never leave already guarantees.
///
/// The position-keyed map stays inside the builder, which is the only place a
/// position is ever looked up. Returning it would make the renderer search for
/// a depth it is standing next to, and carry a fallback for the missing-owner
/// case this pass has already resolved.
fn owner_depths(structures: &[StructureDescriptor]) -> Box<[usize]> {
    let mut by_position = BTreeMap::new();
    let mut depths = Vec::with_capacity(structures.len());
    for record in structures {
        let depth = record
            .owner()
            .and_then(|owner| by_position.get(&owner.id().position()).copied())
            .map_or(0, |owner: usize| owner.saturating_add(1));
        by_position.insert(record.handle().id().position(), depth);
        depths.push(depth);
    }
    depths.into_boxed_slice()
}

/// One neighborhood: which graph it was walked in, and what it retained.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn neighborhood_row(out: &mut String, held: &pedant_snippet::RelationNeighborhood) {
    write!(
        out,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        held.project().id().position(),
        held.seed().index(),
        held.coverage().token(),
        held.neighbors().len(),
        held.nodes().len(),
        held.edges().len(),
        held.containment().len(),
        held.unresolved().len(),
    )
    .ok();
}

/// The selected route's stops, or nothing where no eligible pair is connected.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn path(out: &mut String, answer: &pedant_snippet::PathAnswer) {
    let Some(route) = answer.selected() else {
        return;
    };
    rows(out, route.nodes(), |out, node| {
        write!(
            out,
            "{}\t{}\t{}",
            route.project().id().position(),
            node.node().index(),
            entity(node),
        )
        .ok();
    });
}

/// One line per measured record, in the mode's own vocabulary.
///
/// Five arms, five row shapes, one loop. Each arm states only what its own
/// record measures; the iteration and the terminator belong to [`rows`], which
/// is why the arms take a closure rather than restating the walk five times.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn analysis(out: &mut String, answer: &pedant_snippet::AnalysisAnswer) {
    use pedant_snippet::AnalysisAnswer;

    match answer {
        AnalysisAnswer::DegreeCentrality(records) => rows(out, records, |out, record| {
            write!(
                out,
                "{}\t{}\t{}",
                entity(record.entity()),
                record.incoming(),
                record.outgoing()
            )
            .ok();
        }),
        AnalysisAnswer::BetweennessCentrality(records) => rows(out, records, |out, record| {
            write!(
                out,
                "{}\t{}\t{}",
                entity(record.entity()),
                record.raw(),
                record.normalized()
            )
            .ok();
        }),
        AnalysisAnswer::Components(records) => rows(out, records, |out, record| {
            write!(
                out,
                "{}\t{}\t{}",
                record.id().index(),
                record.members().len(),
                record.cyclic()
            )
            .ok();
        }),
        AnalysisAnswer::Condensation(held) => {
            let leaving = outgoing(held);
            rows(out, held.topological_order(), |out, component| {
                write!(
                    out,
                    "{}\t{}",
                    component.index(),
                    leaving.get(component).copied().unwrap_or_default()
                )
                .ok();
            });
        }
        AnalysisAnswer::ModuleDivergence(held) => rows(out, held.cohesion(), |out, record| {
            write!(
                out,
                "{}\t{}\t{}",
                entity(record.root()),
                record.internal_edges(),
                record.boundary_edges()
            )
            .ok();
        }),
    }
}

/// How many condensation edges leave each component.
///
/// The value the row's own component states. Printing the answer's whole edge
/// total put one number on every line and said nothing about the component the
/// line names, which is the column every other analysis row uses for a
/// per-record measurement.
///
/// Counted in one fold over the edge list rather than per row. A filter per
/// component walked the whole list once for every component, which is the edge
/// count times the component count for a table that states each edge once. A
/// component no edge leaves states no entry, and the row reads that absence as
/// the zero it is.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn outgoing(
    held: &pedant_snippet::CondensationAnswer,
) -> BTreeMap<pedant_snippet::GraphComponentId, usize> {
    held.edges()
        .iter()
        .fold(BTreeMap::new(), |mut counted, edge| {
            *counted.entry(edge.source()).or_default() += 1;
            counted
        })
}

/// How one graph member is named in a text row.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn entity(member: &pedant_snippet::NavigationEntity) -> &str {
    member
        .structure()
        .map_or(ABSENT, StructureDescriptor::qualified_name)
}

/// One typed refusal as both transports state it.
///
/// The serialized envelope, or — where that envelope will not serialize — the
/// sentence the refusal itself carries. The sentence is the fallback rather than
/// the serializer's complaint, because the operator and the client are both
/// asking about the refusal and not about the document it failed to become.
///
/// Written once because the CLI writes it to stderr and the MCP server sends it
/// as tool-error content: a refusal spelled two ways is one product stating one
/// failure twice.
pub(crate) fn refusal(report: &impl serde::Serialize, refused: &CodeIntelligenceError) -> String {
    serde_json::to_string(report).unwrap_or_else(|_| refused.to_string())
}
