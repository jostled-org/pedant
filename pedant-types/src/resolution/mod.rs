//! The language-neutral symbol-resolution result schema.
//!
//! A resolution report says which source definition each reference in a
//! repository denotes, and how certain that answer is. It contains no parser
//! and no filesystem behavior: a producer states facts through
//! [`ResolutionReportBuilder`], and every report — built in process or decoded
//! from JSON — passes one shared validator before it exists.
//!
//! Identifiers are dense positions in sorted slices, so a consumer indexes the
//! report directly, and reordering the filesystem walk that produced it cannot
//! change a single identifier.

mod builder;
mod definition;
mod error;
mod finish;
mod handle;
mod id;
mod record;
mod reference;
mod report;
mod span;
mod unit;
mod validate;
mod wire;
mod wire_field;
mod wire_reject;
mod wire_sequence;

pub use builder::{ResolutionReportBuilder, ResolutionReportLimits};
pub use definition::{SymbolDefinition, SymbolKind};
pub use error::{ReportCollection, ResolutionReportError};
pub use handle::{CandidateInput, DefinitionHandle, ReferenceHandle, ResolutionUnitHandle};
pub use id::{DefinitionId, ReferenceId, ResolutionUnitId};
pub use record::{ResolutionCandidate, ResolutionCertainty, ResolutionGap, ResolutionRecord};
pub use reference::{ReferenceKind, SymbolReference};
pub use report::{ResolutionReport, ResolutionTier};
pub use span::{SourcePosition, SourceSpan};
pub use unit::ResolutionUnit;
