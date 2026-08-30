//! Which edges a graph query admits.
//!
//! The selection is the caller's to state. `pedant-graph` publishes no default,
//! because which relations answer a question is policy rather than topology,
//! and a library that picked one would make that policy invisible.
//!
//! It widens nothing. A selection admits the intersection of the kinds and the
//! certainties it names, so naming a kind twice changes nothing and either
//! empty side is a question about no edge at all.

use pedant_graph::GraphEdgeSelection;
use serde::{Deserialize, Serialize};

use crate::index::{CodeIntelligenceError, QueryField, RevisionClaim, RevisionClaimInput};

use super::certainty::EdgeCertainty;
use super::edge_kind::EdgeKind;

/// Which edges one graph query admits.
///
/// Both lists are explicit and neither has a default. An empty list on either
/// side admits no edge at all, which is a question about nothing rather than a
/// question about everything, so it is refused instead of answered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeSelection {
    /// The relations to follow.
    pub kinds: Box<[EdgeKind]>,
    /// The certainties to admit.
    pub certainties: Box<[EdgeCertainty]>,
}

impl EdgeSelection {
    /// The graph selection this request states.
    ///
    /// # Errors
    ///
    /// [`CodeIntelligenceError::InvalidQuerySelection`] when either list is
    /// empty.
    pub(super) fn admitted(&self) -> Result<GraphEdgeSelection, CodeIntelligenceError> {
        let refusal = match (self.kinds.is_empty(), self.certainties.is_empty()) {
            (true, _) => "an edge selection names at least one edge kind",
            (_, true) => "an edge selection names at least one certainty",
            (false, false) => {
                let kinds: Box<[_]> = self.kinds.iter().map(|kind| kind.admitted()).collect();
                let certainties: Box<[_]> = self
                    .certainties
                    .iter()
                    .map(|certainty| certainty.admitted())
                    .collect();
                return Ok(GraphEdgeSelection::new(&kinds, &certainties));
            }
        };
        Err(CodeIntelligenceError::InvalidQuerySelection {
            reason: Box::from(refusal),
        })
    }

    /// Write this selection into one cursor claim.
    ///
    /// Normalized before it is written, so two spellings of one selection —
    /// a kind named twice, or two lists in different orders — cannot mint two
    /// cursors over one result.
    pub(super) fn claim(&self, claim: &mut RevisionClaim) {
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::EdgeKinds,
            value: Some(&normalized(&self.kinds, EdgeKind::token)),
        });
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::Certainties,
            value: Some(&normalized(&self.certainties, EdgeCertainty::token)),
        });
    }
}

/// One list of tokens, sorted and deduplicated, joined by commas.
fn normalized<T: Copy>(stated: &[T], token: fn(T) -> &'static str) -> String {
    let mut tokens: Vec<&'static str> = stated.iter().copied().map(token).collect();
    tokens.sort_unstable();
    tokens.dedup();
    tokens.join(",")
}
