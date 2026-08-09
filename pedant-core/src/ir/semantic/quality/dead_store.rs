//! Dead-store detection.

use super::prelude::*;

type BindingState = (bool, IrSpan);

/// Detect dead stores: a mutable binding reassigned without the previous value being read.
pub(super) fn detect_dead_stores(ctx: &FnContext<'_, '_>, out: &mut Vec<DataFlowFact>) {
    let mut bindings: BTreeMap<Box<str>, BindingState> = BTreeMap::new();

    for stmt in ctx.stmts.iter() {
        process_stmt_for_dead_stores(stmt, ctx, &mut bindings, out);
    }
    if let Some(tail) = &ctx.tail_expr {
        mark_reads_in_node(tail.syntax(), &mut bindings);
    }
}

/// Process a single statement for dead store tracking.
fn process_stmt_for_dead_stores(
    stmt: &ast::Stmt,
    ctx: &FnContext<'_, '_>,
    bindings: &mut BTreeMap<Box<str>, BindingState>,
    out: &mut Vec<DataFlowFact>,
) {
    match stmt {
        ast::Stmt::LetStmt(let_stmt) => {
            process_let_for_dead_stores(let_stmt, stmt, ctx, bindings);
        }
        ast::Stmt::ExprStmt(expr_stmt) => {
            process_expr_stmt_for_dead_stores(expr_stmt, stmt, ctx, bindings, out);
        }
        ast::Stmt::Item(_) => {}
    }
}

/// Handle a let statement for dead store tracking.
fn process_let_for_dead_stores(
    let_stmt: &ast::LetStmt,
    stmt: &ast::Stmt,
    ctx: &FnContext<'_, '_>,
    bindings: &mut BTreeMap<Box<str>, BindingState>,
) {
    let Some(pat) = let_stmt.pat() else { return };
    let is_mut = matches!(&pat, ast::Pat::IdentPat(ip) if ip.mut_token().is_some());
    match is_mut {
        true => {
            let Some(name) = extract_binding_name(&pat) else {
                return;
            };
            let span = ctx.span(stmt.syntax());
            bindings
                .entry(name)
                .and_modify(|state| *state = (false, span))
                .or_insert((false, span));
        }
        false => mark_reads_in_node(stmt.syntax(), bindings),
    }
}

/// Handle an expression statement for dead store tracking, detecting assignments.
fn process_expr_stmt_for_dead_stores(
    expr_stmt: &ast::ExprStmt,
    stmt: &ast::Stmt,
    ctx: &FnContext<'_, '_>,
    bindings: &mut BTreeMap<Box<str>, BindingState>,
    out: &mut Vec<DataFlowFact>,
) {
    let Some(expr) = expr_stmt.expr() else { return };
    let Some((lhs_name, rhs)) = extract_assignment(&expr) else {
        mark_reads_in_node(stmt.syntax(), bindings);
        return;
    };

    if let Some(rhs_node) = rhs {
        mark_reads_in_node(rhs_node.syntax(), bindings);
    }

    let Some(state) = bindings.get_mut(&*lhs_name) else {
        return;
    };

    if !state.0 {
        out.push(quality_fact(
            DataFlowKind::DeadStore,
            state.1,
            ctx.span(stmt.syntax()),
            format!("value of `{lhs_name}` overwritten before being read").into_boxed_str(),
        ));
    }

    *state = (false, ctx.span(stmt.syntax()));
}

/// Extract (lhs_name, rhs_expr) from an assignment expression, or None.
pub(super) fn extract_assignment(expr: &ast::Expr) -> Option<(Box<str>, Option<ast::Expr>)> {
    let ast::Expr::BinExpr(bin) = expr else {
        return None;
    };
    let is_eq = bin.op_token().is_some_and(|t| t.kind() == SyntaxKind::EQ);
    match is_eq {
        true => {
            let lhs = bin.lhs()?;
            let name = lhs.syntax().text().to_string().into_boxed_str();
            Some((name, bin.rhs()))
        }
        false => None,
    }
}

/// Mark all referenced bindings as "read" in the tracking map.
fn mark_reads_in_node(node: &SyntaxNode, bindings: &mut BTreeMap<Box<str>, BindingState>) {
    for desc in node.descendants() {
        let dominated = matches!(desc.kind(), SyntaxKind::NAME_REF | SyntaxKind::IDENT);
        match dominated {
            true => mark_if_tracked(&desc, bindings),
            false => mark_idents_in_macro(&desc, bindings),
        }
    }
}

/// Mark a single node as a read if its text matches a tracked binding.
fn mark_if_tracked(node: &SyntaxNode, bindings: &mut BTreeMap<Box<str>, BindingState>) {
    let Some(token) = node.first_token() else {
        return;
    };
    mark_token_if_tracked(token.text(), bindings);
}

/// Check macro call tokens for references to tracked bindings.
///
/// Handles both direct IDENT references and implicit format captures
/// in string literals (e.g., `println!("{x}")`).
fn mark_idents_in_macro(node: &SyntaxNode, bindings: &mut BTreeMap<Box<str>, BindingState>) {
    if node.kind() != SyntaxKind::MACRO_CALL || bindings.is_empty() {
        return;
    }
    for token in node
        .descendants_with_tokens()
        .filter_map(|it| it.into_token())
    {
        match token.kind() {
            SyntaxKind::IDENT => mark_token_if_tracked(token.text(), bindings),
            SyntaxKind::STRING => mark_format_captures(token.text(), bindings),
            _ => {}
        }
    }
}

/// Mark a single token as read if it exactly matches a tracked binding.
fn mark_token_if_tracked(text: &str, bindings: &mut BTreeMap<Box<str>, BindingState>) {
    if let Some(state) = bindings.get_mut(text) {
        state.0 = true;
    }
}

/// Mark bindings referenced via implicit format captures in string literals.
fn mark_format_captures(text: &str, bindings: &mut BTreeMap<Box<str>, BindingState>) {
    for (name, state) in bindings.iter_mut() {
        if text.contains(&**name) {
            state.0 = true;
        }
    }
}
