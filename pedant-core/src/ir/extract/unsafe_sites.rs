//! Recording of the three `unsafe` constructs, each stamped with its callable.
//!
//! A block and an `unsafe impl` belong to the body under traversal. An
//! `unsafe fn` belongs to the function it declares, which the caller records
//! before walking it, so the index that declaration will take is the current
//! length of the function list.

use proc_macro2::LineColumn;
use syn::Signature;

use crate::ir::facts::{UnsafeFact, UnsafeKind};

use super::extractor::IrExtractor;
use super::syn_helpers::span_from;

/// Record an `unsafe { … }` block.
pub(super) fn record_unsafe_block(extractor: &mut IrExtractor, start: LineColumn) {
    let containing_fn = extractor.fn_scope.current();
    push(extractor, UnsafeKind::Block, start, containing_fn);
}

/// Record an `unsafe impl` block, when the `impl` states one.
pub(super) fn record_unsafe_impl(
    extractor: &mut IrExtractor,
    unsafety: Option<syn::token::Unsafe>,
) {
    if let Some(token) = unsafety {
        let containing_fn = extractor.fn_scope.current();
        push(
            extractor,
            UnsafeKind::Impl,
            token.span.start(),
            containing_fn,
        );
    }
}

/// Record an `unsafe fn` declaration, when the signature states one.
pub(super) fn record_unsafe_fn(extractor: &mut IrExtractor, sig: &Signature) {
    if let Some(token) = sig.unsafety {
        let declared = extractor.next_fn_index();
        push(
            extractor,
            UnsafeKind::Fn,
            token.span.start(),
            Some(declared),
        );
    }
}

fn push(
    extractor: &mut IrExtractor,
    kind: UnsafeKind,
    start: LineColumn,
    containing_fn: Option<usize>,
) {
    extractor.unsafe_sites.push(UnsafeFact {
        kind,
        span: span_from(start),
        evidence: evidence(kind).into(),
        containing_fn,
    });
}

/// The evidence string one unsafe construct reports.
fn evidence(kind: UnsafeKind) -> &'static str {
    match kind {
        UnsafeKind::Block => "unsafe block",
        UnsafeKind::Fn => "unsafe fn",
        UnsafeKind::Impl => "unsafe impl",
    }
}
