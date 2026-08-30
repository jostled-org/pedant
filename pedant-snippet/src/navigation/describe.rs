//! Turning one retained structure into what a caller is told about it.
//!
//! Three of the facts a descriptor carries are not on the structure record: the
//! qualified name, the projects that reached its source, and the coverage those
//! projects state. Two of the three are properties of the file rather than of
//! the structure, so they are computed once per file and held — which is what
//! the memo below is for, and why every page this crate describes is ordered by
//! path before it is described.

use std::sync::Arc;

use crate::index::{
    CodeIntelligenceIndex, CodeStructure, ProjectHandle, ProjectSlice, StructureCoverage,
    StructureHandle, StructureId,
};

use super::record::StructureDescriptor;

/// What one file's structures share, held while a page describes them.
///
/// The project list is an `Arc` because that is what the memo is for: every
/// structure in the file is handed the same list, and a copy per structure made
/// a page of two hundred items pay two hundred allocations for one answer this
/// describer computed once.
struct FileFacts {
    path: Box<str>,
    projects: Arc<[ProjectHandle]>,
    coverage: StructureCoverage,
}

impl FileFacts {
    /// The facts no admitted file can match.
    ///
    /// The empty path is not a normalized repository path — admission refuses
    /// it — so the held value starts as one nothing can be mistaken for, and
    /// the memo needs no separate "nothing held yet" state to check.
    fn none() -> Self {
        Self {
            path: Box::from(""),
            projects: Arc::from([]),
            coverage: StructureCoverage::SyntaxOnly,
        }
    }
}

/// A describer that recomputes a file's shared facts only when the file
/// changes.
pub(super) struct Describer<'index> {
    index: &'index CodeIntelligenceIndex,
    held: FileFacts,
}

impl<'index> Describer<'index> {
    /// A describer over one immutable index.
    pub(super) fn new(index: &'index CodeIntelligenceIndex) -> Self {
        Self {
            index,
            held: FileFacts::none(),
        }
    }

    /// What a caller is told about one retained structure.
    pub(super) fn describe(&mut self, structure: &CodeStructure) -> StructureDescriptor {
        let facts = self.facts(structure.path());
        let projects = Arc::clone(&facts.projects);
        let coverage = facts.coverage;
        StructureDescriptor {
            handle: self.handle(structure.id()),
            owner: structure.owner().map(|owner| self.handle(owner)),
            language: structure.language(),
            kind: structure.kind(),
            name: structure.name().map(Box::from),
            qualified_name: qualified_name(self.index, structure),
            path: Box::from(structure.path()),
            span: structure.span(),
            coverage,
            projects,
        }
    }

    /// The shared facts of the file `path` names, computed once per file.
    fn facts(&mut self, path: &str) -> &FileFacts {
        if &*self.held.path != path {
            let (projects, coverage) = reaching(self.index, path);
            self.held = FileFacts {
                path: Box::from(path),
                projects,
                coverage,
            };
        }
        &self.held
    }

    /// One dense identity, carried out under the revision that issued it.
    fn handle(&self, id: StructureId) -> StructureHandle {
        StructureHandle::new(self.index.revision(), id.position())
    }
}

/// The strongest evidence any project slice states about one source.
///
/// Only a graph query asks it of a file rather than of a page. A build that
/// links no graph producer describes coverage through [`Describer`] alone, and
/// compiling a second entry for a question nobody can ask would be a route
/// whose absence no test could state.
///
/// It folds the coverage alone rather than reading it off [`reaching`]. That
/// call grows one `Vec<ProjectHandle>` per reaching slice and copies it into an
/// `Arc<[ProjectHandle]>`, and a caller asking only what the evidence is
/// allocated both to drop both.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(super) fn file_coverage(index: &CodeIntelligenceIndex, path: &str) -> StructureCoverage {
    strongest(reached(index, path).map(ProjectSlice::coverage))
}

/// Every project slice whose corpus reached `path`, in project-key order, and
/// the strongest evidence any of them states.
///
/// Both readings come off the same selection: the handles are which slices
/// reached the file, and the coverage is what those same slices say about it.
/// Read off the handles instead, the second would have to turn each one back
/// into the slice the first already held — a lookup that can refuse, and a
/// refusal that would silently downgrade a resolved file to syntax-only.
///
/// The selection is walked twice rather than folded once. Each walk is one
/// binary search per slice over a sorted source list, which is cheaper than the
/// handle list a coverage-only caller would otherwise allocate and drop — and
/// the memo above means one walk per file rather than one per structure.
fn reaching(
    index: &CodeIntelligenceIndex,
    path: &str,
) -> (Arc<[ProjectHandle]>, StructureCoverage) {
    let handles: Vec<ProjectHandle> = reached(index, path)
        .map(|project| ProjectHandle::new(index.revision(), project.id().position()))
        .collect();
    (
        Arc::from(handles),
        strongest(reached(index, path).map(ProjectSlice::coverage)),
    )
}

/// Every project slice whose corpus reached `path`, in project-key order.
///
/// The one selection both readings share. A slice's sources are sorted, so
/// reaching is one binary search per slice rather than a scan of its corpus.
fn reached<'index>(
    index: &'index CodeIntelligenceIndex,
    path: &'index str,
) -> impl Iterator<Item = &'index ProjectSlice> {
    index.projects().iter().filter(move |project| {
        project
            .sources()
            .binary_search_by(|source| (**source).cmp(path))
            .is_ok()
    })
}

/// The strongest evidence any reaching slice states.
///
/// Strongest rather than weakest: a structure a resolved slice reached has
/// resolved evidence, and a second slice that can say less about it does not
/// take that away. `StructureCoverage` is ordered from most evidence to least,
/// so the strongest is the smallest.
///
/// Syntax-only where no slice reached the source at all, which is the honest
/// answer for a language this build resolves no project for: the outline is
/// complete and there is no graph behind it.
fn strongest(stated: impl Iterator<Item = StructureCoverage>) -> StructureCoverage {
    stated
        .reduce(StructureCoverage::min)
        .unwrap_or(StructureCoverage::SyntaxOnly)
}

/// The normalized path, the named owner chain, and the structure's own name,
/// joined by `::`.
///
/// Unnamed owners are skipped rather than spelled: a Rust `impl` block declares
/// no name, and a qualified name carrying an empty segment for it would state a
/// namespace no language has.
fn qualified_name(index: &CodeIntelligenceIndex, structure: &CodeStructure) -> Box<str> {
    let mut segments: Vec<&str> = structure.name().into_iter().collect();
    segments.extend(named_owners(index, structure));
    segments.push(structure.path());
    segments.reverse();
    segments.join("::").into_boxed_str()
}

/// Every owner that declares a name, nearest first.
///
/// The one owner walk this crate takes. A qualified name reads the whole chain
/// and an owner filter reads its first entry, and two walks over the same links
/// are two chances for them to disagree about what owns what.
///
/// It terminates on any retained forest: an owner is declared before what it
/// owns, so each step strictly decreases the position.
pub(super) fn named_owners<'index>(
    index: &'index CodeIntelligenceIndex,
    structure: &CodeStructure,
) -> impl Iterator<Item = &'index str> {
    let held = |owner: Option<StructureId>| {
        owner.and_then(|id| index.structures().get(id.position() as usize))
    };
    std::iter::successors(held(structure.owner()), move |owner| held(owner.owner()))
        .filter_map(CodeStructure::name)
}
