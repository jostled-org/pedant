//! The one place a non-Rust analysis envelope is assembled.
//!
//! Every status this crate can report goes out through [`seal_with`], so the
//! flat profile and the symbol projection are filled together and no backend
//! can build half an envelope of its own.

use pedant_types::{
    CapabilityAnalysis, CapabilityFinding, CapabilityProfile, SymbolAttributionStatus,
    SymbolCapabilityProfile,
};

/// Seal `findings` beside whatever symbol projection the producer proved.
pub(super) fn seal_with(
    findings: Box<[CapabilityFinding]>,
    symbol_attribution: SymbolAttributionStatus,
    symbols: Box<[SymbolCapabilityProfile]>,
) -> CapabilityAnalysis {
    CapabilityAnalysis {
        profile: CapabilityProfile { findings },
        symbol_attribution,
        symbols,
    }
}

/// A source analysis with no complete structural parse behind it.
///
/// The flat findings are the text tier's, the structured tier's, or a recovery
/// tree's, and they remain authoritative. No symbol is claimed, because no
/// complete callable inventory was available to classify against.
pub(crate) fn unavailable(findings: Box<[CapabilityFinding]>) -> CapabilityAnalysis {
    seal_with(findings, SymbolAttributionStatus::Unavailable, Box::new([]))
}

/// An analysis of an input with no source-callable model at all.
///
/// A manifest states hooks rather than callables, and a direct `Language::Rust`
/// request belongs to `pedant-core`. Neither has a callable inventory to be
/// complete or incomplete about.
pub(crate) fn not_applicable(findings: Box<[CapabilityFinding]>) -> CapabilityAnalysis {
    seal_with(
        findings,
        SymbolAttributionStatus::NotApplicable,
        Box::new([]),
    )
}
