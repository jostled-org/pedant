//! The repository code-intelligence index: what this crate holds about one
//! repository, and the identities every answer about it carries.

#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod analysis;
mod authority;
mod build;
mod claim;
mod count;
mod coverage;
mod digits;
mod discovery;
mod error;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod file_inventory;
#[cfg(feature = "graph-go")]
mod go_slices;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod graph_budget;
mod health;
mod hex;
mod indexer;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod instance;
mod issue;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod join;
mod joined;
mod limit_field;
#[cfg(feature = "test-support")]
mod limit_inventory;
mod limits;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod lines;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod membership;
mod observe;
mod path;
mod profile;
mod project;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod provider;
mod read;
mod report;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod retained;
mod reuse;
mod revision;
#[cfg(feature = "graph-rust")]
mod rust_slices;
mod seal;
mod serialize;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod slice;
mod source;
mod state;
mod store;
mod structure;
mod syntax;

pub use authority::ProjectAuthority;
#[cfg(feature = "test-support")]
pub use claim::{AdmittedPathKind, PagedQuery, QueryField, RevisionClaim, RevisionClaimInput};
pub use coverage::StructureCoverage;
pub use error::{CapacityCollection, CapacityOwner, CodeIntelligenceError};
pub use health::{HealthStatus, IndexHealth};
pub use indexer::CodeIntelligenceIndexer;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub use instance::StructureInstance;
pub use issue::{IndexIssue, IssueCode, IssueScope, IssueStage};
#[cfg(feature = "test-support")]
pub use limit_field::LimitField;
#[cfg(feature = "test-support")]
pub use limit_inventory::stated_ceilings;
pub use limits::{CodeIntelligenceLimits, RepositoryLimits};
#[cfg(feature = "test-support")]
pub use observe::{PhaseEntry, SourceStep, SourceTallies, SourceWork, WorkEvent, WorkPhase};
pub use project::{ProjectHandle, ProjectId, ProjectKey, ProjectSlice};
#[cfg(feature = "test-support")]
pub use read::bounded_reader_for_test;
pub use report::{ErrorCode, ErrorReport, FatalReport};
pub use revision::{IndexRevision, StateRevision};
pub use state::{CodeIntelligenceIndex, CodeIntelligenceState, FileRecord};
pub use structure::{CodeStructure, StructureHandle, StructureId};

#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) use analysis::SliceAnalysis;
pub(crate) use claim::CursorBinding;
#[cfg(not(feature = "test-support"))]
pub(crate) use claim::{PagedQuery, QueryField, RevisionClaim, RevisionClaimInput};
pub(crate) use discovery::{
    EXCLUDED_DIRECTORIES, IGNORE_FILES, authority_language, ignore_matcher, recognized,
};
pub(crate) use error::capacity;
pub(crate) use hex::Hex;
pub(crate) use path::{CanonicalRoot, normalize};
pub(crate) use state::stalled;
