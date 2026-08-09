//! Discarded-result detection.

use super::dead_store::extract_assignment;
use super::prelude::*;

/// Detect discarded results: call expressions as statements where the callee returns Result.
pub(super) fn detect_discarded_results(ctx: &FnContext<'_, '_>, out: &mut Vec<DataFlowFact>) {
    for stmt in ctx.stmts.iter() {
        let ast::Stmt::ExprStmt(expr_stmt) = &stmt else {
            continue;
        };
        let Some(expr) = expr_stmt.expr() else {
            continue;
        };
        if extract_assignment(&expr).is_some() {
            continue;
        }
        if !expr_returns_result(ctx.sema, &expr, ctx.db) {
            continue;
        }
        let span = ctx.span(stmt.syntax());
        out.push(quality_fact(
            DataFlowKind::DiscardedResult,
            span,
            span,
            Box::from("Result-returning call used as statement without binding"),
        ));
    }
}

/// Check whether an expression returns a Result type using ADT structural check.
pub(super) fn expr_returns_result(
    sema: &Semantics<'_, RootDatabase>,
    expr: &ast::Expr,
    db: &RootDatabase,
) -> bool {
    let inferred = sema
        .type_of_expr(expr)
        .and_then(|ti| ti.original.as_adt())
        .map(|adt| adt.name(db).as_str() == "Result");

    match inferred {
        Some(result) => result,
        None => callee_returns_result(sema, expr, db),
    }
}

/// Resolve a call or method call expression's callee and check if it returns Result.
fn callee_returns_result(
    sema: &Semantics<'_, RootDatabase>,
    expr: &ast::Expr,
    db: &RootDatabase,
) -> bool {
    let func = match expr {
        ast::Expr::CallExpr(call) => resolve_call_to_function(sema, call),
        ast::Expr::MethodCallExpr(mc) => sema.resolve_method_call(mc),
        _ => None,
    };
    let Some(func) = func else { return false };
    let ret_ty = func.ret_type(db);
    let adt = match ret_ty.as_adt() {
        Some(a) => a,
        None => return false,
    };
    adt.name(db).as_str() == "Result"
}
