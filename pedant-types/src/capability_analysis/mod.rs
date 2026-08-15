//! The language-neutral capability analysis envelope.
//!
//! A capability finding names a file and a position. This envelope adds the
//! named function or method that contains it, so a consumer can cite the
//! callable responsible for a capability rather than the file alone.
//!
//! The flat `CapabilityProfile` inside the envelope is unchanged and remains
//! the persisted and policy authority. Symbol evidence is a separate projection
//! over the same findings, which keeps lexical attribution out of attestation
//! and baseline identity.

mod analysis;
mod status;
mod symbol;

pub use analysis::CapabilityAnalysis;
pub use status::SymbolAttributionStatus;
pub use symbol::{CapabilitySymbol, CapabilitySymbolKind, SymbolCapabilityProfile};
