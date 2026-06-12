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
#[cfg(feature = "semantic")]
mod taint;

pub use context::SemanticContext;
#[cfg(not(feature = "semantic"))]
pub use context::SemanticFileAnalysis;
#[cfg(feature = "semantic")]
pub use file_analysis::SemanticFileAnalysis;
#[cfg(feature = "semantic")]
pub use function_summary::FunctionAnalysisSummary;
