//! Second-pass enrichment of syntactic facts with resolved type information.
//!
//! The syntactic extractor can only see what a type annotation spells; this
//! pass asks rust-analyzer what it resolves to, which is what the alias,
//! dispatch, and `Copy`-receiver checks actually need.

use crate::ir::facts::{BindingFact, FileIr, MethodCallFact};
use crate::ir::semantic::SemanticContext;

/// Enrich IR facts with resolved type information from semantic analysis.
///
/// Calls `analyze_file` once to get the cached `SemanticFileAnalysis`, then
/// reads data flows (shared via `Arc`) and resolved types (from the eagerly
/// populated cache) without reparsing the file.
pub(super) fn enrich_ir(ir: &mut FileIr, ctx: &SemanticContext) {
    let file_path: &str = &ir.file_path;

    let Some(analysis) = ctx.analyze_file(file_path) else {
        enrich_method_calls(&mut ir.method_calls, &ir.bindings);
        return;
    };

    // Share data flows via Arc — no deep copy.
    ir.data_flows = std::sync::Arc::clone(analysis.data_flows());

    // Resolve binding types from the cached analysis.
    for i in 0..ir.bindings.len() {
        let Some(span) = ir.bindings[i].type_annotation_span else {
            continue;
        };
        let Some(resolved_type) = analysis.resolve_type(span.line, span.column) else {
            continue;
        };
        let owned: Box<str> = Box::from(resolved_type);
        if owned.contains("Arc<") || owned.contains("Rc<") {
            ir.bindings[i].is_refcounted = true;
        }
        ir.bindings[i].resolved_type = Some(owned);
    }

    // Resolve type ref classification flags from the cached analysis.
    for tr in ir.type_refs.iter_mut() {
        let Some(resolved_type) = analysis.resolve_type(tr.span.line, tr.span.column) else {
            continue;
        };
        if resolved_type.contains("dyn ") {
            tr.involves_dyn = true;
        }
        if resolved_type.contains("HashMap") && !resolved_type.contains("BuildHasher") {
            tr.is_default_hasher = true;
        }
        if resolved_type.contains("Vec")
            && resolved_type.contains("Box")
            && resolved_type.contains("dyn ")
        {
            tr.is_vec_box_dyn = true;
        }
    }

    enrich_method_calls(&mut ir.method_calls, &ir.bindings);
}

/// Resolve method call receiver types using enriched binding data.
///
/// Looks up the receiver identifier's resolved type from the binding facts
/// already enriched by `enrich_ir`.
fn enrich_method_calls(method_calls: &mut [MethodCallFact], bindings: &[BindingFact]) {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    let mut binding_types: BTreeMap<(Option<usize>, &str), Arc<str>> = BTreeMap::new();
    for b in bindings {
        let Some(resolved) = b.resolved_type.as_deref() else {
            continue;
        };
        binding_types
            .entry((b.containing_fn, &b.name))
            .or_insert_with(|| Arc::from(resolved));
    }

    for mc in method_calls.iter_mut() {
        let Some(recv_ident) = mc.receiver_ident.as_deref() else {
            continue;
        };
        let Some(resolved) = binding_types.get(&(mc.containing_fn, recv_ident)) else {
            continue;
        };
        mc.is_copy_receiver = SemanticContext::is_copy(resolved);
        mc.receiver_type = Some(Arc::clone(resolved));
    }
}
