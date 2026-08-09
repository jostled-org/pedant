//! Observation hooks over the production loaders and the one-pass extractor.
//!
//! With `resolution-test-support` these calls reach the probe installed on the
//! current thread. In an ordinary build the event is consumed and nothing is
//! recorded, so no instrumentation reaches a released binary.

/// The observable production events and the one hook that records them.
mod event;
/// Proof-only observation state, compiled by the proof feature alone.
#[cfg(feature = "resolution-test-support")]
mod probe;

pub(crate) use event::{Observation, record};

#[cfg(feature = "resolution-test-support")]
pub use probe::ResolutionProbe;
