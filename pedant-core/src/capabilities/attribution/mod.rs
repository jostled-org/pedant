//! Lexical attribution of Rust capability evidence to the callables that
//! contain it.
//!
//! This closure reads one already-extracted [`FileIr`](crate::ir::FileIr) and
//! the findings detection drafted from it. It parses nothing, reads no file,
//! loads no project, runs no process, asks no semantic question, and reaches no
//! judgment surface: every input it needs is already a fact.

mod draft;
mod projection;
mod source;

pub(crate) use draft::CapabilityDraft;
pub(crate) use projection::project_analysis;
pub(crate) use source::CapabilitySourceFact;

#[cfg(all(feature = "checks", feature = "semantic"))]
pub(crate) use draft::DraftedFinding;
