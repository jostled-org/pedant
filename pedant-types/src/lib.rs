//! Shared types for pedant capability analysis output.

mod attestation;
mod capability;
mod capability_analysis;
mod diff;
mod error;
mod execution_context;
mod finding;
mod finding_origin;
mod language;
mod profile;
pub mod resolution;
mod source;
mod structure;

pub use attestation::{AnalysisCompleteness, AnalysisTier, AttestationContent, SkippedAnalysis};
pub use capability::Capability;
pub use capability_analysis::{
    CapabilityAnalysis, CapabilitySymbol, CapabilitySymbolKind, SymbolAttributionStatus,
    SymbolCapabilityProfile,
};
pub use diff::CapabilityDiff;
pub use error::ParseCapabilityError;
pub use execution_context::ExecutionContext;
pub use finding::{CapabilityFinding, SourceLocation};
pub use finding_origin::FindingOrigin;
pub use language::Language;
pub use profile::CapabilityProfile;
pub use resolution::{
    CandidateInput, DefinitionHandle, DefinitionId, ReferenceHandle, ReferenceId, ReferenceKind,
    ReportCollection, ResolutionCandidate, ResolutionCertainty, ResolutionGap, ResolutionRecord,
    ResolutionReport, ResolutionReportBuilder, ResolutionReportError, ResolutionReportLimits,
    ResolutionTier, ResolutionUnit, ResolutionUnitHandle, ResolutionUnitId, SourcePosition,
    SourceSpan, SymbolDefinition, SymbolKind, SymbolReference,
};
pub use source::{SourcePath, SourceProvider, SourceRecord};
pub use structure::{StructureKind, StructureRecord, StructureSpan};
