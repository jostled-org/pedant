//! Shared types for pedant capability analysis output.

mod attestation;
mod capability;
mod diff;
mod error;
mod finding;
mod profile;

pub use attestation::{AnalysisTier, AttestationContent};
pub use capability::Capability;
pub use diff::CapabilityDiff;
pub use error::TypeError;
pub use finding::{CapabilityFinding, SourceLocation};
pub use profile::CapabilityProfile;
