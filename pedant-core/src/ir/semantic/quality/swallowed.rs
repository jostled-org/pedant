//! Swallowed-`ok` detection.

use super::discarded::expr_returns_result;
use super::prelude::*;

/// Detect `.ok()` called on Result where the resulting Option is discarded.
///
/// Two forms: statement position (`expr.ok();`) and wildcard binding (`let _ = expr.ok();`).
/// Exempt `write!`/`writeln!` macro receivers per audit ledger convention.
pub(super) fn detect_swallowed_ok(ctx: &FnContext<'_, '_>, out: &mut Vec<DataFlowFact>) {
    for stmt in ctx.stmts.iter() {
        match &stmt {
            ast::Stmt::ExprStmt(expr_stmt) => {
                check_expr_stmt_swallowed_ok(ctx, expr_stmt, stmt, out);
            }
            ast::Stmt::LetStmt(let_stmt) => {
                check_let_stmt_swallowed_ok(ctx, let_stmt, stmt, out);
            }
            ast::Stmt::Item(_) => {}
        }
    }
}

/// Check an expression statement for swallowed `.ok()` on Result.
fn check_expr_stmt_swallowed_ok(
    ctx: &FnContext<'_, '_>,
    expr_stmt: &ast::ExprStmt,
    stmt: &ast::Stmt,
    out: &mut Vec<DataFlowFact>,
) {
    let Some(expr) = expr_stmt.expr() else {
        return;
    };
    let Some(mc) = as_ok_method_call(&expr) else {
        return;
    };
    emit_swallowed_ok_if_result(
        ctx,
        &mc,
        stmt,
        ".ok() on Result discards the error silently",
        out,
    );
}

/// Check a let statement with wildcard pattern for swallowed `.ok()` on Result.
fn check_let_stmt_swallowed_ok(
    ctx: &FnContext<'_, '_>,
    let_stmt: &ast::LetStmt,
    stmt: &ast::Stmt,
    out: &mut Vec<DataFlowFact>,
) {
    let Some(pat) = let_stmt.pat() else { return };
    if !matches!(pat, ast::Pat::WildcardPat(_)) {
        return;
    }
    let Some(init) = let_stmt.initializer() else {
        return;
    };
    let Some(mc) = as_ok_method_call(&init) else {
        return;
    };
    emit_swallowed_ok_if_result(
        ctx,
        &mc,
        stmt,
        "let _ = .ok() on Result discards the error silently",
        out,
    );
}

/// Validate the `.ok()` receiver is a non-write-macro Result and emit the finding.
fn emit_swallowed_ok_if_result(
    ctx: &FnContext<'_, '_>,
    mc: &ast::MethodCallExpr,
    stmt: &ast::Stmt,
    message: &str,
    out: &mut Vec<DataFlowFact>,
) {
    let Some(receiver) = mc.receiver() else {
        return;
    };
    if is_write_macro_expr(&receiver) {
        return;
    }
    if !expr_returns_result(ctx.sema, &receiver, ctx.db) {
        return;
    }
    let span = ctx.span(stmt.syntax());
    out.push(quality_fact(
        DataFlowKind::SwallowedOk,
        span,
        span,
        Box::from(message),
    ));
}

/// Extract a `.ok()` method call from an expression, if present.
fn as_ok_method_call(expr: &ast::Expr) -> Option<ast::MethodCallExpr> {
    let ast::Expr::MethodCallExpr(mc) = expr else {
        return None;
    };
    let name = mc.name_ref()?;
    match name.text() == "ok" {
        true => Some(mc.clone()),
        false => None,
    }
}

/// Check whether an expression is a `write!` or `writeln!` macro invocation.
fn is_write_macro_expr(expr: &ast::Expr) -> bool {
    let ast::Expr::MacroExpr(macro_expr) = expr else {
        return false;
    };
    let Some(macro_call) = macro_expr.macro_call() else {
        return false;
    };
    let Some(path) = macro_call.path() else {
        return false;
    };
    let text = path.syntax().text();
    text == "write" || text == "writeln"
}
