//! Performance issue detection.
//!
//! Identifies repeated calls, unnecessary clones, allocations in loops,
//! and redundant collects within function bodies.

use ra_ap_syntax::{AstNode, ast};

use super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
use super::common::{FnContext, quality_fact};

/// Detect all performance issues within a function body.
///
/// Uses precomputed call sites and allocation-in-loop spans from `FnContext`.
pub(super) fn detect(ctx: &FnContext<'_>) -> Box<[DataFlowFact]> {
    let mut facts = Vec::new();
    detect_repeated_calls(ctx, &mut facts);
    detect_unnecessary_clones(ctx, &mut facts);
    detect_allocation_in_loops(ctx, &mut facts);
    detect_redundant_collects(ctx, &mut facts);
    facts.into_boxed_slice()
}

// --- Repeated call detection ---

/// Detect repeated calls from precomputed call sites.
fn detect_repeated_calls(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
    use std::collections::BTreeMap;

    let mut seen: BTreeMap<(&str, u64), IrSpan> = BTreeMap::new();

    for site in ctx.call_sites.iter() {
        let key = (&*site.callee, site.args_hash);
        match seen.get(&key) {
            Some(first_span) => {
                out.push(quality_fact(
                    DataFlowKind::RepeatedCall,
                    *first_span,
                    site.span,
                    format!("`{}` called with identical arguments", site.callee).into_boxed_str(),
                ));
            }
            None => {
                seen.insert(key, site.span);
            }
        }
    }
}

// --- Unnecessary clone detection ---

/// Detect unnecessary clones: `.clone()` called but the original binding is never used afterward.
///
/// Uses `FnContext` precomputed binding reference index for forward-use checks
/// instead of re-walking the statement list per clone site.
fn detect_unnecessary_clones(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
    for (idx, stmt) in ctx.stmts.iter().enumerate() {
        let ast::Stmt::LetStmt(let_stmt) = stmt else {
            continue;
        };
        let Some(init) = let_stmt.initializer() else {
            continue;
        };
        let Some(receiver_name) = extract_clone_receiver(&init) else {
            continue;
        };

        let used_after = ctx.binding_used_after(&receiver_name, idx);
        let used_in_tail = ctx.binding_used_in_tail(&receiver_name);

        if !used_after && !used_in_tail {
            let span = ctx.span(stmt.syntax());
            out.push(quality_fact(
                DataFlowKind::UnnecessaryClone,
                span,
                span,
                format!("`{receiver_name}` is never used after `.clone()` — move instead")
                    .into_boxed_str(),
            ));
        }
    }
}

/// Extract the receiver binding name from a `.clone()` method call expression.
fn extract_clone_receiver(expr: &ast::Expr) -> Option<Box<str>> {
    let ast::Expr::MethodCallExpr(mc) = expr else {
        return None;
    };
    let is_clone = mc
        .name_ref()
        .is_some_and(|name| name.text().as_str() == "clone");
    if !is_clone {
        return None;
    }
    let recv = mc.receiver()?;
    let ast::Expr::PathExpr(path_expr) = recv else {
        return None;
    };
    let path = path_expr.path()?;
    path.qualifier().is_none().then_some(())?;
    path.segment()
        .and_then(|seg| seg.name_ref())
        .map(|n| Box::from(n.text().as_str()))
}

// --- Allocation in loop detection ---

/// Emit findings for precomputed allocation-in-loop spans from `FnContext`.
fn detect_allocation_in_loops(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
    for &span in ctx.alloc_in_loop_spans.iter() {
        out.push(quality_fact(
            DataFlowKind::AllocationInLoop,
            span,
            span,
            Box::from("allocation inside loop body — consider hoisting"),
        ));
    }
}

// --- Redundant collect detection ---

/// Detect redundant collects: `.collect()` into a binding whose next use is `.iter()` or `.into_iter()`.
///
/// Uses precomputed `binding_method_calls` index from `FnContext` to check
/// whether the binding's next method call is an iterator re-entry.
fn detect_redundant_collects(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
    for (idx, stmt) in ctx.stmts.iter().enumerate() {
        let ast::Stmt::LetStmt(let_stmt) = stmt else {
            continue;
        };
        let Some(init) = let_stmt.initializer() else {
            continue;
        };
        if !ends_with_collect(&init) {
            continue;
        }
        let Some(pat) = let_stmt.pat() else {
            continue;
        };
        let Some(binding_name) = super::common::extract_binding_name(&pat) else {
            continue;
        };

        if ctx.next_use_is_iter(&binding_name, idx) {
            let span = ctx.span(stmt.syntax());
            out.push(quality_fact(
                DataFlowKind::RedundantCollect,
                span,
                span,
                format!(
                    "`{binding_name}` collected then immediately re-iterated — remove `.collect()`"
                )
                .into_boxed_str(),
            ));
        }
    }
}

/// Check whether an expression ends with a `.collect()` method call.
fn ends_with_collect(expr: &ast::Expr) -> bool {
    match expr {
        ast::Expr::MethodCallExpr(mc) => mc
            .name_ref()
            .is_some_and(|name| name.text().as_str() == "collect"),
        _ => false,
    }
}
