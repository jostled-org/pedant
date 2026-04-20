//! Quality issue detection.
//!
//! Identifies dead stores, discarded results, partial error handling,
//! swallowed `.ok()` calls, and immutable growable bindings within function bodies.

use std::collections::BTreeMap;

use ra_ap_hir::Semantics;
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, ast};

use super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
use super::common::{
    FnContext, expr_references_binding, extract_binding_name, quality_fact,
    resolve_call_to_function, span_from_node,
};

/// Detect all quality issues within a function body.
pub(super) fn detect(ctx: &FnContext<'_>) -> Box<[DataFlowFact]> {
    let mut facts = Vec::new();
    detect_dead_stores(ctx, &mut facts);
    detect_discarded_results(ctx, &mut facts);
    detect_partial_error_handling(ctx, &mut facts);
    detect_swallowed_ok(ctx, &mut facts);
    detect_immutable_growable(ctx, &mut facts);
    facts.into_boxed_slice()
}

// --- Dead store detection ---

/// Binding liveness state: (read_since_assignment, assignment_span).
type BindingState = (bool, IrSpan);

/// Detect dead stores: a mutable binding reassigned without the previous value being read.
fn detect_dead_stores(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
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
    ctx: &FnContext<'_>,
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
    ctx: &FnContext<'_>,
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
    ctx: &FnContext<'_>,
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
fn extract_assignment(expr: &ast::Expr) -> Option<(Box<str>, Option<ast::Expr>)> {
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

// --- Discarded result detection ---

/// Detect discarded results: call expressions as statements where the callee returns Result.
fn detect_discarded_results(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
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
fn expr_returns_result(
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

// --- Partial error handling detection ---

/// Detect partial error handling: Result-typed bindings handled in some match arms but not others.
///
/// Uses precomputed `ctx.match_exprs` instead of rescanning the statement
/// list per Result binding.
fn detect_partial_error_handling(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
    let result_bindings = collect_result_bindings(ctx);

    for (name, def_span) in &*result_bindings {
        check_partial_handling(name, def_span, &ctx.match_exprs, ctx.line_index, out);
    }
}

/// Collect all Result-typed let bindings from a statement list.
fn collect_result_bindings(ctx: &FnContext<'_>) -> Box<[(Box<str>, IrSpan)]> {
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

/// Detect `.ok()` called on Result where the resulting Option is discarded.
///
/// Two forms: statement position (`expr.ok();`) and wildcard binding (`let _ = expr.ok();`).
/// Exempt `write!`/`writeln!` macro receivers per audit ledger convention.
fn detect_swallowed_ok(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
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
    ctx: &FnContext<'_>,
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
    ctx: &FnContext<'_>,
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
    ctx: &FnContext<'_>,
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

// --- Immutable growable detection ---

/// Detect Vec/String bindings that are never mutated after construction.
///
/// Uses precomputed mutation, return, and `&mut` pass flags from `FnContext`
/// instead of rescanning the statement list per binding.
fn detect_immutable_growable(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
    for stmt in ctx.stmts.iter() {
        let ast::Stmt::LetStmt(let_stmt) = &stmt else {
            continue;
        };
        let Some(pat) = let_stmt.pat() else { continue };
        let Some(name) = extract_binding_name(&pat) else {
            continue;
        };
        let ann = classify_via_annotation(let_stmt);
        let sem = classify_via_semantics(ctx.sema, let_stmt, ctx.db);
        let Some(type_label) = ann.or(sem) else {
            continue;
        };

        if ctx.binding_is_mutated(&name)
            || ctx.binding_is_returned(&name)
            || ctx.binding_passed_as_mut_ref(&name)
        {
            continue;
        }

        let span = ctx.span(let_stmt.syntax());
        out.push(quality_fact(
            DataFlowKind::ImmutableGrowable,
            span,
            span,
            format!(
                "`{name}` is a {type_label} that is never mutated; consider Box<[T]> or Box<str>"
            )
            .into_boxed_str(),
        ));
    }
}

/// Classify via RA semantic type resolution.
fn classify_via_semantics(
    sema: &Semantics<'_, RootDatabase>,
    let_stmt: &ast::LetStmt,
    db: &RootDatabase,
) -> Option<&'static str> {
    let ty = let_stmt
        .initializer()
        .and_then(|init| sema.type_of_expr(&init))
        .map(|ti| ti.original)
        .or_else(|| {
            let_stmt
                .pat()
                .and_then(|pat| sema.type_of_pat(&pat))
                .map(|ti| ti.original)
        })?;

    let adt = ty.as_adt()?;
    let adt_name = adt.name(db);
    match adt_name.as_str() {
        "Vec" => Some("Vec"),
        "String" => Some("String"),
        _ => None,
    }
}

/// Classify via explicit type annotation on the let statement.
fn classify_via_annotation(let_stmt: &ast::LetStmt) -> Option<&'static str> {
    let ty = let_stmt.ty()?;
    let syntax_text = ty.syntax().text();
    if syntax_text == "String" {
        return Some("String");
    }
    // SyntaxText lacks starts_with; allocate only for the Vec prefix check.
    let text = syntax_text.to_string();
    match text.starts_with("Vec<") || text.starts_with("Vec ") || text == "Vec" {
        true => Some("Vec"),
        false => None,
    }
}
