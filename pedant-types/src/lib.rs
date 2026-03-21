//! Shared types for pedant capability analysis output.

mod attestation;
mod capability;
mod diff;
mod finding;
mod profile;

pub use attestation::{AnalysisTier, AttestationContent};
pub use capability::Capability;
pub use diff::CapabilityDiff;
pub use finding::{CapabilityFinding, SourceLocation};
pub use profile::CapabilityProfile;
