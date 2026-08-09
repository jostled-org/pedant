//! Adapter module for `ra_ap_ide` semantic analysis.
//!
//! All `ra_ap_*` types are contained within this module. Nothing leaks to the
//! rest of pedant-core. The `SemanticContext` struct exposes a stable internal
//! API that absorbs upstream API churn from rust-analyzer's weekly releases.
//!
//! When the `semantic` feature is disabled, `SemanticContext` and
//! `SemanticFileAnalysis` exist as unconstructable types so that `analyze()`
//! can always accept `Option<&SemanticContext>` without feature gates on the
//! signature.

#[cfg(feature = "semantic")]
mod common;
#[cfg(feature = "semantic")]
mod concurrency;
mod context;
/// The definition edges a verified snapshot may consume.
#[cfg(feature = "semantic")]
mod edges;
#[cfg(feature = "semantic")]
mod file_analysis;
#[cfg(feature = "semantic")]
mod function_summary;
#[cfg(feature = "semantic")]
mod perf;
#[cfg(feature = "semantic")]
mod quality;
#[cfg(feature = "semantic")]
mod reachability;
/// What a resolution snapshot claims, and the verification it must survive.
#[cfg(feature = "semantic")]
mod snapshot;
#[cfg(feature = "semantic")]
mod taint;
/// The definition edges one parsed file states.
#[cfg(feature = "semantic")]
mod targets;

pub use context::SemanticContext;
#[cfg(not(feature = "semantic"))]
pub use context::SemanticFileAnalysis;
#[cfg(feature = "semantic")]
pub(crate) use edges::{SemanticDefinitionEdge, SemanticDefinitionTargets, SemanticSite};
#[cfg(feature = "semantic")]
pub use file_analysis::SemanticFileAnalysis;
#[cfg(feature = "semantic")]
pub use function_summary::FunctionAnalysisSummary;
#[cfg(feature = "semantic")]
pub(crate) use snapshot::{
    SemanticEdgeClaim, SemanticSnapshotClaim, SemanticSourceClaim, SemanticUnitClaim,
};
