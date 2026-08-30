//! Every project one index resolved, one page at a time.

use crate::index::{
    CodeIntelligenceError, CodeIntelligenceState, IndexHealth, IssueScope, ProjectHandle,
};

use super::page::Window;
use super::page_request::PageRequest;
use super::paged_query::ProjectListing;
use super::project_record::ProjectRecord;
use super::response::NavigationResponse;

/// Answer [`CodeIntelligenceState::list_projects`].
pub(crate) fn projects_listed(
    state: &CodeIntelligenceState,
    request: &PageRequest,
) -> Result<NavigationResponse<Box<[ProjectRecord]>>, CodeIntelligenceError> {
    let listing = ProjectListing;
    let window = Window::opened(state, &listing, request)?;
    let total = state.index().projects().len();
    let selected = window.page(state.index().projects())?;
    let mut health = AuthorityHealth::new(state);
    let records: Box<[ProjectRecord]> = selected
        .iter()
        .map(|project| {
            ProjectRecord::stated(
                ProjectHandle::new(state.index().revision(), project.id().position()),
                project.key().language(),
                Box::from(project.key().authority()),
                Box::from(project.key().unit()),
                project.coverage(),
                health.of(project.key().authority()),
            )
        })
        .collect();
    Ok(NavigationResponse::paged(
        state,
        records,
        window.next(state, &listing, total),
    ))
}

/// A health that is recomputed only when the authority changes.
///
/// Every target of one Cargo manifest is one row, and a project key orders by
/// language, authority, then unit — so a workspace's targets are adjacent rows
/// sharing one authority. Computing the health per row would scan the whole
/// issue list once per target for one answer.
struct AuthorityHealth<'state> {
    state: &'state CodeIntelligenceState,
    authority: Box<str>,
    held: IndexHealth,
}

impl<'state> AuthorityHealth<'state> {
    /// A memo over one published state, holding an authority no project has.
    ///
    /// The empty spelling is not a normalized authority path — discovery states
    /// none — so the first row cannot match what is held, and the memo needs no
    /// separate "nothing held yet" state to check.
    fn new(state: &'state CodeIntelligenceState) -> Self {
        Self {
            state,
            authority: Box::from(""),
            held: IndexHealth::over(std::iter::empty()),
        }
    }

    /// What one authority refused, if anything.
    ///
    /// Scoped by the issue's own kind rather than by its name: a source and an
    /// authority can be spelled alike, and a project that inherited a file's
    /// refusal would report a health that is not its own.
    fn of(&mut self, authority: &str) -> IndexHealth {
        if &*self.authority != authority {
            self.authority = Box::from(authority);
            self.held = IndexHealth::over(self.state.issues().iter().filter(|issue| {
                matches!(
                    issue.scope(),
                    IssueScope::Project { authority: named } if &**named == authority
                )
            }));
        }
        self.held
    }
}
