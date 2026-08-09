//! Facts one `let` binding contributes.

use super::extractor::IrExtractor;
use super::site_visitor::record_local_receiver;
use super::syn_helpers::{for_each_pat_ident_span, span_from};

/// Record one `let` binding: the type a receiver may be inferred from, its
/// string and reference-count classification, and the names the naming check
/// reads.
pub(super) fn record_binding(extractor: &mut IrExtractor, node: &syn::Local) {
    record_local_receiver(extractor, node);
    extractor.fn_scope.record_string_binding(&node.pat);
    extractor.fn_scope.record_refcounted_from_pat(&node.pat);
    record_wildcard(extractor, node);
    for_each_pat_ident_span(&node.pat, None, &mut |name, span, annotation| {
        if !name.starts_with('_') {
            extractor.push_binding_fact(name, Some(span), false, false, false, annotation);
        }
    });
}

fn record_wildcard(extractor: &mut IrExtractor, node: &syn::Local) {
    let syn::Pat::Wild(wildcard) = &node.pat else {
        return;
    };
    let init_is_write = node
        .init
        .as_ref()
        .map(|init| extractor.fn_scope.is_write_macro_to_string(&init.expr))
        .unwrap_or(false);
    let span = span_from(wildcard.underscore_token.span.start());
    extractor.push_binding_fact(
        "_".into(),
        Some(span),
        true,
        node.init.is_some(),
        init_is_write,
        None,
    );
}
