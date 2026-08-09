//! CLI analysis orchestration.

mod accumulator;
mod context;
mod files;
mod project;
mod request;
mod run;
mod semantic;

pub(crate) use accumulator::AnalysisAccumulator;
pub(crate) use context::AnalysisContext;
pub(crate) use project::run_project_checks;
pub(crate) use request::AnalysisRequest;
pub(crate) use run::run_analysis;
pub(crate) use semantic::load_semantic_if_requested;
