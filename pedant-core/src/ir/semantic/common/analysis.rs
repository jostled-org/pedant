//! Derivation of per-function semantic indices.

use super::context::{BindingMethodIndex, CallSite, LockAcquisition};
use super::file::{
    ParsedFile, direct_path_name, extract_binding_name, is_mutation_method,
    resolve_call_to_function, span_from_node,
};
use super::prelude::*;
use super::sinks::{classify_function_as_sink, classify_qualified_call_by_type};

/// A precomputed capability sink classified during the body walk.
pub(in crate::ir::semantic) struct CapabilitySink {
    pub(in crate::ir::semantic) capability: Capability,
    pub(in crate::ir::semantic) span: IrSpan,
    pub(in crate::ir::semantic) referenced_names: Box<[Box<str>]>,
}

/// Derived state from the single body descendants walk.
pub(super) struct BodyDerivedState {
    pub(super) mutated_bindings: BTreeSet<Box<str>>,
    pub(super) returned_bindings: BTreeSet<Box<str>>,
    pub(super) mut_ref_bindings: BTreeSet<Box<str>>,
    pub(super) call_sites: Box<[CallSite]>,
    pub(super) alloc_in_loop_spans: Box<[IrSpan]>,
    pub(super) capability_sinks: Box<[CapabilitySink]>,
}

/// Build per-binding → sorted statement indices where NAME_REF appears.
pub(super) fn build_binding_stmt_refs(stmts: &[ast::Stmt]) -> BTreeMap<Box<str>, Box<[usize]>> {
    let mut refs: BTreeMap<Box<str>, Vec<usize>> = BTreeMap::new();
    for (i, stmt) in stmts.iter().enumerate() {
        let name_refs = stmt
            .syntax()
            .descendants()
            .filter(|node| node.kind() == SyntaxKind::NAME_REF);
        for node in name_refs {
            refs.entry(node.text().to_string().into_boxed_str())
                .or_default()
                .push(i);
        }
    }
    refs.into_iter()
        .map(|(k, mut v)| {
            v.dedup();
            (k, v.into_boxed_slice())
        })
        .collect()
}

/// Collect binding names referenced in an expression subtree.
pub(super) fn build_binding_refs_in_expr(expr: Option<&ast::Expr>) -> BTreeSet<Box<str>> {
    expr.map(|e| {
        e.syntax()
            .descendants()
            .filter(|n| n.kind() == SyntaxKind::NAME_REF)
            .map(|n| n.text().to_string().into_boxed_str())
            .collect()
    })
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Merged body walk — binding flags, call sites, alloc-in-loop
// ---------------------------------------------------------------------------

/// Single walk over `body.syntax().descendants()` that computes:
/// - Binding mutation/return/&mut-pass flags
/// - Resolved call sites (for repeated-call detection and call graph)
/// - Allocation-in-loop spans (for performance detection)
///
/// Replaces three separate `descendants()` traversals with one.
pub(super) fn build_body_derived_state(
    pf: &ParsedFile<'_>,
    body: &ast::BlockExpr,
    tail: Option<&ast::Expr>,
) -> BodyDerivedState {
    let mut mutated = BTreeSet::new();
    let mut returned = BTreeSet::new();
    let mut mut_ref = BTreeSet::new();
    let mut call_sites = Vec::new();
    let mut alloc_in_loop_spans = Vec::new();
    let mut sinks = Vec::new();

    let body_syntax = body.syntax();

    for node in body_syntax.descendants() {
        match node.kind() {
            SyntaxKind::METHOD_CALL_EXPR => {
                process_method_call(&node, pf, &mut mutated, &mut call_sites, &mut sinks);
            }
            SyntaxKind::CALL_EXPR => {
                process_call_expr(
                    &node,
                    pf,
                    body_syntax,
                    &mut call_sites,
                    &mut alloc_in_loop_spans,
                    &mut sinks,
                );
            }
            SyntaxKind::BIN_EXPR => {
                process_bin_expr(&node, &mut mutated);
            }
            SyntaxKind::REF_EXPR => {
                process_ref_expr(&node, &mut mut_ref);
            }
            SyntaxKind::RETURN_EXPR => {
                process_return_expr(&node, &mut returned);
            }
            _ => {}
        }
    }

    // Check tail expression for direct return.
    let tail_name = tail.and_then(direct_path_name);
    if let Some(name) = tail_name {
        returned.insert(name);
    }

    BodyDerivedState {
        mutated_bindings: mutated,
        returned_bindings: returned,
        mut_ref_bindings: mut_ref,
        call_sites: call_sites.into_boxed_slice(),
        alloc_in_loop_spans: alloc_in_loop_spans.into_boxed_slice(),
        capability_sinks: sinks.into_boxed_slice(),
    }
}

/// Handle a METHOD_CALL_EXPR: check mutation, resolve as call site, classify as sink.
pub(super) fn process_method_call(
    node: &SyntaxNode,
    pf: &ParsedFile<'_>,
    mutated: &mut BTreeSet<Box<str>>,
    call_sites: &mut Vec<CallSite>,
    sinks: &mut Vec<CapabilitySink>,
) {
    let Some(mc) = ast::MethodCallExpr::cast(node.clone()) else {
        return;
    };
    // Mutation check.
    let is_mut = mc
        .receiver()
        .zip(mc.name_ref())
        .filter(|(_, method)| is_mutation_method(method.text().as_str()));
    if let Some((recv, _)) = is_mut {
        mutated.insert(recv.syntax().text().to_string().into_boxed_str());
    }
    // Call site resolution + sink classification.
    let Some(func) = pf.sema.resolve_method_call(&mc) else {
        return;
    };
    let name = Box::from(func.name(pf.db).as_str());
    let hash = mc.arg_list().map(|al| hash_arg_text(&al)).unwrap_or(0);
    let span = span_from_node(mc.syntax(), pf.line_index);
    call_sites.push(CallSite {
        callee: name,
        args_hash: hash,
        span,
    });
    let sink_cap = classify_function_as_sink(func, pf.db);
    if let Some(cap) = sink_cap {
        sinks.push(CapabilitySink {
            capability: cap,
            span,
            referenced_names: collect_name_refs(node),
        });
    }
}

/// Handle a CALL_EXPR: resolve as call site, check alloc-in-loop, classify as sink.
pub(super) fn process_call_expr(
    node: &SyntaxNode,
    pf: &ParsedFile<'_>,
    body_syntax: &SyntaxNode,
    call_sites: &mut Vec<CallSite>,
    alloc_in_loop_spans: &mut Vec<IrSpan>,
    sinks: &mut Vec<CapabilitySink>,
) {
    let Some(call) = ast::CallExpr::cast(node.clone()) else {
        return;
    };
    // Call site resolution + sink classification.
    let resolved = resolve_call_to_function(&pf.sema, &call);
    let sink_cap = match resolved {
        Some(func) => {
            let name = Box::from(func.name(pf.db).as_str());
            let hash = call.arg_list().map(|al| hash_arg_text(&al)).unwrap_or(0);
            let span = span_from_node(call.syntax(), pf.line_index);
            call_sites.push(CallSite {
                callee: name,
                args_hash: hash,
                span,
            });
            classify_function_as_sink(func, pf.db)
        }
        // Fallback: resolve qualifier type for associated function calls
        // (e.g., TcpStream::connect where full path resolution returns None).
        None => classify_qualified_call_by_type(&pf.sema, &call, pf.db),
    };
    if let Some(cap) = sink_cap {
        sinks.push(CapabilitySink {
            capability: cap,
            span: span_from_node(call.syntax(), pf.line_index),
            referenced_names: collect_name_refs(node),
        });
    }
    // Allocation-in-loop check.
    if is_allocation_call(&call) && is_inside_loop(node, body_syntax) {
        alloc_in_loop_spans.push(span_from_node(call.syntax(), pf.line_index));
    }
}

/// Handle a BIN_EXPR: check assignment mutation.
pub(super) fn process_bin_expr(node: &SyntaxNode, mutated: &mut BTreeSet<Box<str>>) {
    let Some(bin) = ast::BinExpr::cast(node.clone()) else {
        return;
    };
    let is_assign = bin.op_token().is_some_and(|t| {
        matches!(
            t.kind(),
            SyntaxKind::EQ | SyntaxKind::PLUSEQ | SyntaxKind::MINUSEQ
        )
    });
    if !is_assign {
        return;
    }
    let Some(lhs) = bin.lhs() else { return };
    let text = lhs.syntax().text().to_string();
    let name = text.split('[').next().unwrap_or(&text);
    mutated.insert(Box::from(name));
}

/// Handle a REF_EXPR: check &mut pass.
pub(super) fn process_ref_expr(node: &SyntaxNode, mut_ref: &mut BTreeSet<Box<str>>) {
    let Some(ref_expr) = ast::RefExpr::cast(node.clone()) else {
        return;
    };
    if ref_expr.mut_token().is_none() {
        return;
    }
    let Some(e) = ref_expr.expr() else { return };
    mut_ref.insert(e.syntax().text().to_string().into_boxed_str());
}

/// Handle a RETURN_EXPR: check direct binding return.
pub(super) fn process_return_expr(node: &SyntaxNode, returned: &mut BTreeSet<Box<str>>) {
    let name = ast::ReturnExpr::cast(node.clone())
        .and_then(|ret| ret.expr())
        .and_then(|expr| direct_path_name(&expr));
    let Some(n) = name else { return };
    returned.insert(n);
}

/// Hash the text content of an argument list.
pub(super) fn hash_arg_text(arg_list: &ast::ArgList) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for token in arg_list
        .syntax()
        .descendants_with_tokens()
        .filter_map(|it| it.into_token())
    {
        token.text().hash(&mut hasher);
    }
    hasher.finish()
}

/// Allocation constructor patterns that should be flagged inside loops.
pub(super) const ALLOC_CONSTRUCTORS: &[(&str, &str)] = &[
    ("new", "Vec"),
    ("new", "String"),
    ("with_capacity", "Vec"),
    ("with_capacity", "String"),
];

/// Check whether a call expression is a known allocation constructor.
pub(super) fn is_allocation_call(call: &ast::CallExpr) -> bool {
    let path = call
        .expr()
        .and_then(|e| ast::PathExpr::cast(e.syntax().clone()))
        .and_then(|pe| pe.path());
    let Some(path) = path else { return false };
    let Some(segment) = path.segment() else {
        return false;
    };
    let Some(name_ref) = segment.name_ref() else {
        return false;
    };
    let fn_name = name_ref.text();
    let qualifier_name = path
        .qualifier()
        .and_then(|q| q.segment())
        .and_then(|s| s.name_ref())
        .map(|n| n.text().to_smolstr());
    let Some(qual) = qualifier_name else {
        return false;
    };
    ALLOC_CONSTRUCTORS
        .iter()
        .any(|(f, t)| fn_name.as_str() == *f && *qual == **t)
}

/// Check whether a node is inside a loop body by walking ancestors.
pub(super) fn is_inside_loop(node: &SyntaxNode, root: &SyntaxNode) -> bool {
    node.ancestors().take_while(|a| a != root).any(|a| {
        matches!(
            a.kind(),
            SyntaxKind::FOR_EXPR | SyntaxKind::WHILE_EXPR | SyntaxKind::LOOP_EXPR
        )
    })
}

/// Collect all NAME_REF text values from a syntax subtree.
///
/// Used to eagerly capture references in capability sink nodes so that
/// taint detection can do a set intersection without per-sink subtree walks.
pub(super) fn collect_name_refs(node: &SyntaxNode) -> Box<[Box<str>]> {
    node.descendants()
        .filter(|n| n.kind() == SyntaxKind::NAME_REF)
        .map(|n| n.text().to_string().into_boxed_str())
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

// ---------------------------------------------------------------------------
// Binding method-call precomputation
// ---------------------------------------------------------------------------

/// Build per-binding `(stmt_index, method_name)` pairs for direct method calls.
///
/// A "direct method call" is `binding_name.method(...)` where the receiver
/// is a simple path expression matching the binding.
pub(super) fn build_binding_method_calls(stmts: &[ast::Stmt]) -> BindingMethodIndex {
    let mut map: BTreeMap<Box<str>, Vec<(usize, Box<str>)>> = BTreeMap::new();
    for (i, stmt) in stmts.iter().enumerate() {
        let entries = stmt
            .syntax()
            .descendants()
            .filter_map(ast::MethodCallExpr::cast)
            .filter_map(|mc| {
                mc.receiver()
                    .and_then(|recv| direct_path_name(&recv))
                    .zip(mc.name_ref().map(|n| Box::from(n.text().as_str())))
            });
        for (binding, method) in entries {
            map.entry(binding).or_default().push((i, method));
        }
    }
    map.into_iter()
        .map(|(k, v)| (k, v.into_boxed_slice()))
        .collect()
}

/// Find the first direct method call on any binding in the tail expression.
pub(super) fn build_binding_method_in_tail(
    tail: Option<&ast::Expr>,
) -> BTreeMap<Box<str>, Box<str>> {
    let Some(expr) = tail else {
        return BTreeMap::new();
    };
    let mut result = BTreeMap::new();
    for mc in expr
        .syntax()
        .descendants()
        .filter_map(ast::MethodCallExpr::cast)
    {
        let entry = mc
            .receiver()
            .and_then(|recv| direct_path_name(&recv))
            .zip(mc.name_ref().map(|n| Box::from(n.text().as_str())));
        if let Some((binding, method)) = entry {
            result.entry(binding).or_insert(method);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Match expression precomputation
// ---------------------------------------------------------------------------

/// Collect all match expressions from the statement list for use by
/// partial error handling detection.
pub(super) fn build_match_exprs(stmt_list: &ast::StmtList) -> Box<[ast::MatchExpr]> {
    stmt_list
        .syntax()
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::MATCH_EXPR)
        .filter_map(ast::MatchExpr::cast)
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

// ---------------------------------------------------------------------------
// Lock acquisition precomputation
// ---------------------------------------------------------------------------

/// Lock acquisition method names on `Mutex` and `RwLock`.
pub(super) const LOCK_METHODS: &[&str] = &["lock", "read", "write"];

/// Extract ordered lock acquisitions from the statement list.
pub(super) fn build_lock_acquisitions(
    line_index: &LineIndex,
    stmts: &[ast::Stmt],
) -> Box<[LockAcquisition]> {
    stmts
        .iter()
        .filter_map(|stmt| {
            let ast::Stmt::LetStmt(let_stmt) = stmt else {
                return None;
            };
            let init = let_stmt.initializer()?;
            let receiver_name = lock_receiver_name(&init)?;
            let guard_name = let_stmt.pat().and_then(|p| extract_binding_name(&p))?;
            let span = span_from_node(stmt.syntax(), line_index);
            Some(LockAcquisition {
                guard_name,
                receiver_name,
                span,
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Extract the receiver name from a lock acquisition within an expression.
///
/// For `m1.lock().unwrap()`, returns `"m1"`.
/// Returns `None` when the expression is a block (`{ let g = m.lock(); ... }`)
/// because locks inside block expressions are scoped.
pub(in crate::ir::semantic) fn lock_receiver_name(expr: &ast::Expr) -> Option<Box<str>> {
    if let ast::Expr::BlockExpr(_) = expr {
        return None;
    }
    let root = expr.syntax().clone();
    expr.syntax()
        .descendants()
        .filter_map(ast::MethodCallExpr::cast)
        .filter(|mc| {
            mc.name_ref()
                .is_some_and(|n| LOCK_METHODS.contains(&n.text().as_str()))
        })
        .filter(|mc| !is_inside_block_expr(mc.syntax(), &root))
        .find_map(|mc| extract_lock_receiver(&mc))
}

/// Returns `true` when `node` is nested inside a `BlockExpr` that is
/// a descendant of `root`.
pub(super) fn is_inside_block_expr(node: &SyntaxNode, root: &SyntaxNode) -> bool {
    node.ancestors()
        .skip(1)
        .take_while(|a| a != root)
        .any(|a| ast::BlockExpr::can_cast(a.kind()))
}

/// Extract a simple binding name from a method call's receiver.
pub(super) fn extract_lock_receiver(mc: &ast::MethodCallExpr) -> Option<Box<str>> {
    let recv = mc.receiver()?;
    let ast::Expr::PathExpr(pe) = &recv else {
        return None;
    };
    pe.path()?
        .segment()?
        .name_ref()
        .map(|n| Box::from(n.text().as_str()))
}
