//! Which graph instances one structure handle selects, and how a query with
//! none refuses.
//!
//! A structure with no instance is not an empty answer. A Python function that
//! calls nothing and a Python function this build has no resolver for produce
//! the same empty neighborhood and state opposite facts, so the absence is
//! returned as a typed refusal that names the evidence the entity does have.
//!
//! The two absences are told apart. A source no project slice reached is
//! syntax-only: its outline is complete and there is no graph behind it. A
//! source a slice did reach, whose declaration no graph node states, is
//! unavailable: there is a graph, and this declaration is not in it.

use crate::index::{
    CodeIntelligenceError, CodeIntelligenceIndex, CodeStructure, ProjectHandle, StructureCoverage,
    StructureHandle, StructureInstance,
};

use super::super::describe::file_coverage;

/// The instances one handle selects, in project then node order, or why it
/// selects none.
///
/// The handle is proved against this revision before any position is read, and
/// a stated project is proved the same way, so a stale identity refuses before
/// a graph is touched.
///
/// # Errors
///
/// [`CodeIntelligenceError::StaleRevision`] for an identity from another
/// revision, [`CodeIntelligenceError::UnknownStructure`] or
/// [`CodeIntelligenceError::UnknownProject`] for one this revision does not
/// hold, and [`CodeIntelligenceError::UnavailableCoverage`] where the selection
/// is empty.
pub(super) fn seeded(
    index: &CodeIntelligenceIndex,
    handle: StructureHandle,
    project: Option<ProjectHandle>,
) -> Result<Box<[StructureInstance]>, CodeIntelligenceError> {
    let structure = index.structure(handle)?;
    let selected = match project {
        None => structure.instances().to_vec(),
        Some(named) => {
            let slice = index.project(named)?;
            structure
                .instances()
                .iter()
                .filter(|instance| instance.project() == slice.id())
                .copied()
                .collect()
        }
    };
    match selected.is_empty() {
        false => Ok(selected.into_boxed_slice()),
        true => Err(absent(index, structure, project)),
    }
}

/// Why one structure states no graph instance a query can walk.
///
/// The coverage is the query's, not the file's. A source no slice reached is
/// syntax-only, and that is what its declarations state. A source a slice did
/// reach states resolved evidence about the declarations it mapped — and about
/// this one it states none, which is what unavailable means.
fn absent(
    index: &CodeIntelligenceIndex,
    structure: &CodeStructure,
    project: Option<ProjectHandle>,
) -> CodeIntelligenceError {
    let stated = file_coverage(index, structure.path());
    let (coverage, reason) = match (stated, project) {
        (StructureCoverage::SyntaxOnly, _) => (
            StructureCoverage::SyntaxOnly,
            format!(
                "no project slice resolved {}, so its declarations state no graph node",
                structure.path()
            ),
        ),
        (_, None) => (
            StructureCoverage::Unavailable,
            format!(
                "no project graph states a node for the declaration at {}",
                structure.path()
            ),
        ),
        (_, Some(_)) => (
            StructureCoverage::Unavailable,
            format!(
                "the requested project states no node for the declaration at {}",
                structure.path()
            ),
        ),
    };
    CodeIntelligenceError::UnavailableCoverage {
        coverage,
        reason: reason.into_boxed_str(),
    }
}
