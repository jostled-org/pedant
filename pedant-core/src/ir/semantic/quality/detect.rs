//! Quality detector orchestration.

use super::dead_store::detect_dead_stores;
use super::discarded::detect_discarded_results;
use super::immutable::detect_immutable_growable;
use super::partial::detect_partial_error_handling;
use super::prelude::*;
use super::swallowed::detect_swallowed_ok;

pub(in crate::ir::semantic) fn detect(ctx: &FnContext<'_, '_>) -> Box<[DataFlowFact]> {
    let mut facts = Vec::new();
    detect_dead_stores(ctx, &mut facts);
    detect_discarded_results(ctx, &mut facts);
    detect_partial_error_handling(ctx, &mut facts);
    detect_swallowed_ok(ctx, &mut facts);
    detect_immutable_growable(ctx, &mut facts);
    facts.into_boxed_slice()
}

// --- Dead store detection ---
