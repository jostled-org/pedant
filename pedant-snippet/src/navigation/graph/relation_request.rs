//! What one relation query selects, and what its cursor is bound to.
//!
//! Every parameter here is part of the cursor binding, for the reason a search
//! filter is: a continuation is only the rest of the same result when every one
//! of them is unchanged. A page taken under one direction and resumed under
//! another would present one neighborhood as the tail of a different walk.

use serde::{Deserialize, Serialize};

use crate::index::{
    PagedQuery, ProjectHandle, QueryField, RevisionClaim, RevisionClaimInput, StructureHandle,
};

use super::super::paged_query::PagedRequest;
use super::direction::RelationDirection;
use super::selection::EdgeSelection;

/// Which neighborhoods one relation query states.
///
/// An omitted project expands every graph the seed appears in, in project then
/// node order. Naming one selects that graph alone, which is the only way to
/// ask about a library target apart from the binary that links it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationQuery {
    /// The revision-bound declaration to walk from.
    pub structure: StructureHandle,
    /// The one project graph to walk, or every graph the seed appears in.
    #[serde(default)]
    pub project: Option<ProjectHandle>,
    /// Which way to follow a selected edge.
    pub direction: RelationDirection,
    /// Which edges to admit.
    pub edges: EdgeSelection,
    /// How many selected steps the walk may take.
    pub max_depth: u32,
}

impl PagedRequest for RelationQuery {
    fn kind(&self) -> PagedQuery {
        PagedQuery::Relations
    }

    fn claim(&self, claim: &mut RevisionClaim) {
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::Seed,
            value: Some(&seed_token(self.structure)),
        });
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::Project,
            value: self.project.map(project_token).as_deref(),
        });
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::Direction,
            value: Some(self.direction.token()),
        });
        self.edges.claim(claim);
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::MaxDepth,
            value: Some(&self.max_depth.to_string()),
        });
    }
}

/// The token one seed handle is claimed under.
///
/// The revision is already claimed by the binding, so the position is the whole
/// of what the seed adds: two handles that differ only by revision cannot both
/// reach a cursor this state minted.
fn seed_token(handle: StructureHandle) -> String {
    handle.id().position().to_string()
}

/// The token one project handle is claimed under, on the same terms.
fn project_token(handle: ProjectHandle) -> String {
    handle.id().position().to_string()
}
