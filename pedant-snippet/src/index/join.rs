//! The join between one project graph's nodes and the physical declarations
//! this index retained.
//!
//! A graph node states a definition: its language, its declared name, and the
//! extent of that name inside one file of one resolution unit. A retained
//! structure states a declaration: the whole of what a reader asks to read. The
//! two are different extents over the same source, so the join is neither a
//! name comparison nor a comparison between those two extents — a name is
//! shared by every `run` in a repository, and an `impl` block and the type it
//! names can open at the same byte.
//!
//! What the join follows is the definition site each language owner already
//! recorded beside its structure. `RustFileInventory::definition_span` answers
//! where the declared name sits; `GoFileInventory::definition_span` answers the
//! same question for a report that points at the whole declaration. Both come
//! from the walk that produced the structure, so the extent keyed here is the
//! one the report was built from rather than one measured again.

use std::collections::BTreeMap;

use pedant_graph::{CodeGraph, GraphNode, GraphNodeLocation};
use pedant_types::{SourcePosition, StructureSpan};

use super::count::narrowed;
use super::instance::StructureInstance;
use super::lines::LineTable;
use super::membership::NodeMembership;
use super::project::ProjectSlice;
use super::slice::directory_of;
use super::state::FileRecord;
use super::structure::StructureId;

/// The extent one definition occupies, in report coordinates.
type DefinitionExtent = (SourcePosition, SourcePosition);

/// Every structure one admitted source states, keyed by its definition extent.
struct FileSites {
    keyed: BTreeMap<DefinitionExtent, u32>,
}

/// Every retained structure, keyed by its source and its definition extent.
///
/// Built once per index revision rather than once per project, because one
/// physical source belongs to as many project graphs as reach it and rebuilding
/// the table per graph would re-measure every line of it.
///
/// The keys are borrowed from the file records, which outlive this table, and
/// only a source that stated a definition site gets an entry. Owning a copy of
/// every repository path bought nothing, and a Python, JavaScript, or Bash file
/// — which can state no definition site at all — bought an empty map beside it.
struct DefinitionSites<'files> {
    files: BTreeMap<&'files str, FileSites>,
}

impl<'files> DefinitionSites<'files> {
    /// Key every structure whose language owner stated a definition site.
    fn of(files: &'files [FileRecord], definitions: &[Option<StructureSpan>]) -> Self {
        Self {
            files: files
                .iter()
                .filter_map(|file| Some((file.path(), sites_of(file, definitions)?)))
                .collect(),
        }
    }

    /// The structures one repository path states, if this index keyed any.
    fn of_path(&self, path: &str) -> Option<&FileSites> {
        self.files.get(path)
    }
}

/// Every structure one file states, keyed by definition extent, or nothing.
///
/// First-wins in source order, so two declarations sharing one extent resolve
/// to the earlier one rather than to whichever the map saw last.
///
/// The line table is built on the first stated definition site rather than up
/// front. Only a source a language owner resolved states any, so in a mixed
/// repository every Python, JavaScript, and Bash file — and every Rust or Go
/// file no slice reached — would pay a scan of its whole text for a table
/// nothing then reads.
fn sites_of(file: &FileRecord, definitions: &[Option<StructureSpan>]) -> Option<FileSites> {
    let mut lines: Option<LineTable> = None;
    let mut keyed = BTreeMap::new();
    for position in file.structures() {
        if let Some(span) = definitions.get(position).copied().flatten() {
            let measured = lines.get_or_insert_with(|| LineTable::of(file.text()));
            let extent = (measured.at(span.start_byte()), measured.at(span.end_byte()));
            keyed.entry(extent).or_insert(narrowed(position));
        }
    }
    match keyed.is_empty() {
        true => None,
        false => Some(FileSites { keyed }),
    }
}

/// Which admitted source each of one graph's file nodes names.
///
/// Resolved in one pass before any declaration is joined, so a graph whose
/// hundred nodes sit in one file states that path once rather than once per
/// node.
///
/// One buffer carries every join, because the joined spelling is a map key and
/// nothing outlives the lookup: a fresh `String` and a fresh `Arc<str>` per file
/// node were two allocations spent to ask a question and then dropped.
///
/// Every location is named so adding a new upstream variant is a compile error.
fn sources_of<'sites>(
    sites: &'sites DefinitionSites<'_>,
    prefix: &str,
    graph: &CodeGraph,
) -> Box<[Option<&'sites FileSites>]> {
    let mut joined = String::new();
    graph
        .nodes()
        .iter()
        .map(|node| match node.location() {
            Some(GraphNodeLocation::File { path }) => {
                beneath_into(&mut joined, prefix, path);
                sites.of_path(&joined)
            }
            None | Some(GraphNodeLocation::Span { .. }) => None,
        })
        .collect()
}

/// One path beneath `directory`, in repository spelling, into `buffer`.
///
/// The one owner of the join. [`beneath`](super::slice::beneath) reads it
/// through a buffer of its own for the answer it has to hand back shared, and
/// this walk reuses one buffer across every graph node — but both spell a
/// project path the same way, which is what makes a lookup here find the record
/// a producer keyed there.
pub(super) fn beneath_into(buffer: &mut String, directory: &str, relative: &str) {
    buffer.clear();
    match directory.is_empty() {
        true => buffer.push_str(relative),
        false => {
            buffer.push_str(directory);
            buffer.push('/');
            buffer.push_str(relative);
        }
    }
}

/// The structure one graph node declares, if this index retained it.
fn structure_of(sources: &[Option<&FileSites>], node: &GraphNode) -> Option<u32> {
    match node.location() {
        Some(GraphNodeLocation::Span { file, span }) => {
            let held = sources.get(file.index() as usize).copied().flatten()?;
            held.keyed.get(&(span.start(), span.end())).copied()
        }
        None | Some(GraphNodeLocation::File { .. }) => None,
    }
}

/// Both directions of every membership one join states.
pub(super) struct Memberships {
    /// One entry per retained structure, in that structure's own position.
    pub(super) of_structure: Box<[Box<[StructureInstance]>]>,
    /// Every membership keyed by the node that states it, in key order.
    pub(super) of_node: Box<[NodeMembership]>,
}

/// Every membership one project's graph states, recorded in both directions.
fn admit(found: &mut Found, sites: &DefinitionSites<'_>, project: &ProjectSlice) {
    let graph = project.graph();
    let sources = sources_of(sites, directory_of(project.key().authority()), graph);
    let stated = graph
        .nodes()
        .iter()
        .filter_map(|node| Some((structure_of(&sources, node)?, node.id())));
    for (position, node) in stated {
        // The position came from a table keyed over the same file records the
        // seal pass counted, so a position outside the list is the two passes
        // disagreeing about how many structures this index holds. Dropped
        // rather than panicking at a library boundary: production source here
        // states no assertion of any kind, because an owner refuses through its
        // typed error and this walk has no error to refuse through. The cost is
        // that a dropped membership is a declaration silently stating no graph
        // node it is in fact a node of, which only the seal pass can prevent.
        let Some(held) = found.of_structure.get_mut(position as usize) else {
            continue;
        };
        held.push(StructureInstance::stated(project.id(), node));
        found.of_node.push(NodeMembership::stated(
            project.id(),
            node,
            StructureId::at(position),
        ));
    }
}

/// Both directions, while they are still growing.
struct Found {
    of_structure: Vec<Vec<StructureInstance>>,
    of_node: Vec<NodeMembership>,
}

/// Every structure's graph memberships, in project then node order.
///
/// One entry per retained structure, so a caller seals each structure with the
/// instances at its own position and a structure no graph reached seals with an
/// empty list rather than with an absence a reader has to interpret.
pub(super) fn memberships(
    files: &[FileRecord],
    definitions: &[Option<StructureSpan>],
    projects: &[ProjectSlice],
) -> Memberships {
    let sites = DefinitionSites::of(files, definitions);
    let mut found = Found {
        of_structure: vec![Vec::new(); definitions.len()],
        of_node: Vec::new(),
    };
    for project in projects {
        admit(&mut found, &sites, project);
    }
    found.of_node.sort_unstable();
    Memberships {
        of_structure: found
            .of_structure
            .into_iter()
            .map(|mut stated| {
                stated.sort_unstable();
                stated.into_boxed_slice()
            })
            .collect(),
        of_node: found.of_node.into_boxed_slice(),
    }
}
