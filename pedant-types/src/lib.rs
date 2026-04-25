//! Shared types for pedant capability analysis output.

mod attestation;
mod capability;
mod diff;
mod error;
mod execution_context;
mod finding;
mod finding_origin;
mod language;
mod profile;

pub use attestation::{AnalysisCompleteness, AnalysisTier, AttestationContent};
pub use capability::Capability;
pub use diff::CapabilityDiff;
pub use error::ParseCapabilityError;
pub use execution_context::ExecutionContext;
pub use finding::{CapabilityFinding, SourceLocation};
pub use finding_origin::FindingOrigin;
pub use language::Language;
pub use profile::CapabilityProfile;
