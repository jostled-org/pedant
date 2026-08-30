//! How far one analysis request may lower a host ceiling.
//!
//! A stated ceiling may only be at or below the host's own: a request that
//! asked for more work than the index was configured to do would be a caller
//! raising its own budget. An omitted field is the host field, so the effective
//! ceiling is always one the index already allowed.
//!
//! Every field is proved before an analysis is constructed, which is what puts
//! the request-versus-host refusal ahead of the node count, the selected-edge
//! count, the depth, and the betweenness work in the one refusal order this
//! product states.

use pedant_graph::GraphAnalysisLimits;
use serde::{Deserialize, Serialize};

use crate::index::CodeIntelligenceError;

/// How far one analysis request lowers the host's own ceilings.
///
/// An omitted field is the host field. A stated field replaces it, and may only
/// be at or below it: the effective ceiling is therefore always one the index
/// was configured to allow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisLimitRequest {
    /// The admitted node ceiling.
    #[serde(default)]
    pub max_nodes: Option<u32>,
    /// The admitted selected-edge ceiling.
    #[serde(default)]
    pub max_selected_edges: Option<u32>,
    /// The depth ceiling a walk refuses above.
    #[serde(default)]
    pub max_depth: Option<u32>,
    /// The work bound betweenness centrality refuses above.
    #[serde(default)]
    pub max_betweenness_work: Option<u64>,
}

impl AnalysisLimitRequest {
    /// The ceilings this request states, refusing any that raises the host's.
    ///
    /// # Errors
    ///
    /// [`CodeIntelligenceError::InvalidQuerySelection`] for the first field
    /// above its host field, named, and before any analysis is constructed.
    pub(super) fn lowered(
        &self,
        host: GraphAnalysisLimits,
    ) -> Result<GraphAnalysisLimits, CodeIntelligenceError> {
        Ok(GraphAnalysisLimits::new(
            admitted("max_nodes", self.max_nodes, host.max_nodes())?,
            admitted(
                "max_selected_edges",
                self.max_selected_edges,
                host.max_selected_edges(),
            )?,
            admitted("max_depth", self.max_depth, host.max_depth())?,
            admitted(
                "max_betweenness_work",
                self.max_betweenness_work,
                host.max_betweenness_work(),
            )?,
        ))
    }
}

/// One stated ceiling, or the host's where the request omits it.
fn admitted<T: Copy + Ord + std::fmt::Display>(
    field: &str,
    stated: Option<T>,
    host: T,
) -> Result<T, CodeIntelligenceError> {
    match stated {
        None => Ok(host),
        Some(value) if value <= host => Ok(value),
        Some(value) => Err(CodeIntelligenceError::InvalidQuerySelection {
            reason: format!(
                "{field} may only lower the host ceiling of {host}, not raise it to {value}"
            )
            .into_boxed_str(),
        }),
    }
}
