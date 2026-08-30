//! What a caller is told about the state one answer came from.
//!
//! Beside [`issue`](super::issue) rather than inside it. An issue is one thing
//! that did not happen; health is the arithmetic over a selection of them, and
//! the two are read by different callers — every response carries the summary,
//! and only a caller that asked for the list reads the issues themselves.

use serde::{Deserialize, Serialize};

use super::issue::IndexIssue;
use super::serialize::serialize_token;

/// What every response says about the state it was answered from.
///
/// Derived from the state rather than assembled by a transport, so a CLI answer
/// and an MCP answer cannot disagree about whether an index is complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexHealth {
    status: HealthStatus,
    issues: u32,
    stale_scopes: u32,
}

/// Whether an index is complete, incomplete, or serving an older answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Every scope the build reached succeeded.
    Complete,
    /// At least one scope refused, and none is serving an older answer.
    Degraded,
    /// At least one scope is serving the last good answer it had.
    Stale,
}

impl HealthStatus {
    /// The stable token this status is named by.
    ///
    /// Published for the reason every sibling vocabulary publishes one: a text
    /// row prints the spelling the JSON carries, and the renderer that had no
    /// accessor to read reached it by serializing the value to a JSON string
    /// and stripping the quotes — two allocations, a fallible route, and a
    /// second spelling to keep in step.
    pub fn token(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Degraded => "degraded",
            Self::Stale => "stale",
        }
    }
}

serialize_token!(HealthStatus);

impl IndexHealth {
    /// The health one sorted issue list states.
    pub(crate) fn of(issues: &[IndexIssue]) -> Self {
        Self::over(issues.iter())
    }

    /// The health one selection of issues states.
    ///
    /// A project record answers for the issues its own authority carries, and a
    /// response answers for all of them. Both are the same arithmetic over a
    /// different selection, so the selection is the caller's and the arithmetic
    /// is here.
    pub(crate) fn over<'issue>(issues: impl Iterator<Item = &'issue IndexIssue>) -> Self {
        let (held, stale) = issues.fold((0_usize, 0_usize), |(held, stale), issue| {
            (
                held.saturating_add(1),
                stale.saturating_add(usize::from(issue.stale())),
            )
        });
        let status = match (held, stale) {
            (0, _) => HealthStatus::Complete,
            (_, 0) => HealthStatus::Degraded,
            _ => HealthStatus::Stale,
        };
        Self {
            status,
            issues: super::count::narrowed(held),
            stale_scopes: super::count::narrowed(stale),
        }
    }

    /// Whether this index is complete, incomplete, or serving an older answer.
    pub fn status(self) -> HealthStatus {
        self.status
    }

    /// How many issues the state carries.
    pub fn issues(self) -> u32 {
        self.issues
    }

    /// How many of them are scopes serving an older good answer.
    pub fn stale_scopes(self) -> u32 {
        self.stale_scopes
    }
}
