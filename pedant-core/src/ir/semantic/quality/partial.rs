//! Partial error-handling detection.

use super::discarded::expr_returns_result;
use super::prelude::*;

/// Detect partial error handling: Result-typed bindings handled in some match arms but not others.
///
/// Uses precomputed `ctx.match_exprs` instead of rescanning the statement
/// list per Result binding.
pub(super) fn detect_partial_error_handling(ctx: &FnContext<'_, '_>, out: &mut Vec<DataFlowFact>) {
    let result_bindings = collect_result_bindings(ctx);

    for (name, def_span) in &*result_bindings {
        check_partial_handling(name, def_span, &ctx.match_exprs, ctx.line_index, out);
    }
}

/// Collect all Result-typed let bindings from a statement list.
fn collect_result_bindings(ctx: &FnContext<'_, '_>) -> Box<[(Box<str>, IrSpan)]> {
    ctx.stmts
        .iter()
        .filter_map(|stmt| {
            let ast::Stmt::LetStmt(let_stmt) = &stmt else {
                return None;
            };
            let pat = let_stmt.pat()?;
            let init = let_stmt.initializer()?;
            match expr_returns_result(ctx.sema, &init, ctx.db) {
                true => {
                    let name = extract_binding_name(&pat)?;
                    let span = span_from_node(let_stmt.syntax(), ctx.line_index);
                    Some((name, span))
                }
                false => None,
            }
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Check precomputed match expressions for partial handling of a Result binding.
fn check_partial_handling(
    name: &str,
    def_span: &IrSpan,
    match_exprs: &[ast::MatchExpr],
    line_index: &line_index::LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    for match_expr in match_exprs {
        check_match_for_partial_handling(name, def_span, match_expr, line_index, out);
    }
}

/// Analyze a single match expression for partial error handling of a Result binding.
fn check_match_for_partial_handling(
    name: &str,
    def_span: &IrSpan,
    match_expr: &ast::MatchExpr,
    line_index: &line_index::LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    let Some(arm_list) = match_expr.match_arm_list() else {
        return;
    };

    let mut arm_count: usize = 0;
    let mut some_handle = false;
    let mut some_drop = false;
    for arm in arm_list.arms() {
        arm_count += 1;
        match classify_arm_handling(&arm, name) {
            (true, true) => some_handle = true,
            (true, false) => some_drop = true,
            (false, _) => {}
        }
    }

    if arm_count >= 2 && some_handle && some_drop {
        let span = span_from_node(match_expr.syntax(), line_index);
        out.push(quality_fact(
            DataFlowKind::PartialErrorHandling,
            *def_span,
            span,
            format!("Result `{name}` handled in some match arms but dropped in others")
                .into_boxed_str(),
        ));
    }
}

/// Classify whether a match arm references and handles a Result binding.
///
/// Returns (references_binding, handles_error).
fn classify_arm_handling(arm: &ast::MatchArm, binding_name: &str) -> (bool, bool) {
    let Some(arm_expr) = arm.expr() else {
        return (false, false);
    };
    let refs = expr_references_binding(arm_expr.syntax(), binding_name);
    match refs {
        true => (
            true,
            arm_uses_result_method(arm_expr.syntax(), binding_name),
        ),
        false => (false, false),
    }
}

/// Check if a subtree uses a Result binding in a way that handles the error.
fn arm_uses_result_method(node: &SyntaxNode, binding_name: &str) -> bool {
    node.descendants()
        .any(|desc| matches_result_handling(&desc, binding_name))
}

/// Check whether a single syntax node represents error handling of the named binding.
fn matches_result_handling(node: &SyntaxNode, binding_name: &str) -> bool {
    match node.kind() {
        SyntaxKind::METHOD_CALL_EXPR => ast::MethodCallExpr::cast(node.clone())
            .and_then(|mc| mc.receiver())
            .is_some_and(|recv| expr_references_binding(recv.syntax(), binding_name)),
        SyntaxKind::TRY_EXPR => expr_references_binding(node, binding_name),
        _ => false,
    }
}

// --- Swallowed .ok() detection ---
