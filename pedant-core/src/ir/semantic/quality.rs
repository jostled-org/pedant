//! Quality issue detection.
//!
//! Identifies dead stores, discarded results, partial error handling,
//! swallowed `.ok()` calls, and immutable growable bindings within function bodies.

use std::collections::BTreeMap;

use line_index::LineIndex;
use ra_ap_hir::Semantics;
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, ast};

use super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
use super::common::{
    ParsedFile, expr_references_binding, extract_binding_name, quality_fact,
    resolve_call_to_function, span_from_node,
};

/// Detect all quality issues within a function body.
pub(super) fn detect_quality_in_fn(
    pf: &ParsedFile<'_>,
    stmt_list: &ast::StmtList,
) -> Box<[DataFlowFact]> {
    let mut facts = Vec::new();
    detect_dead_stores(stmt_list, pf.line_index, &mut facts);
    detect_discarded_results(&pf.sema, stmt_list, pf.db, pf.line_index, &mut facts);
    detect_partial_error_handling(&pf.sema, stmt_list, pf.db, pf.line_index, &mut facts);
    detect_swallowed_ok(&pf.sema, stmt_list, pf.db, pf.line_index, &mut facts);
    detect_immutable_growable(pf, stmt_list, pf.line_index, &mut facts);
    facts.into_boxed_slice()
}

// --- Dead store detection ---

/// Binding liveness state: (read_since_assignment, assignment_span).
type BindingState = (bool, IrSpan);

/// Detect dead stores: a mutable binding reassigned without the previous value being read.
fn detect_dead_stores(
    stmt_list: &ast::StmtList,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    let mut bindings: BTreeMap<Box<str>, BindingState> = BTreeMap::new();

    for stmt in stmt_list.statements() {
        process_stmt_for_dead_stores(&stmt, line_index, &mut bindings, out);
    }
    if let Some(tail) = stmt_list.tail_expr() {
        mark_reads_in_node(tail.syntax(), &mut bindings);
    }
}

/// Process a single statement for dead store tracking.
fn process_stmt_for_dead_stores(
    stmt: &ast::Stmt,
    line_index: &LineIndex,
    bindings: &mut BTreeMap<Box<str>, BindingState>,
    out: &mut Vec<DataFlowFact>,
) {
    match stmt {
        ast::Stmt::LetStmt(let_stmt) => {
            process_let_for_dead_stores(let_stmt, stmt, line_index, bindings);
        }
        ast::Stmt::ExprStmt(expr_stmt) => {
            process_expr_stmt_for_dead_stores(expr_stmt, stmt, line_index, bindings, out);
        }
        ast::Stmt::Item(_) => {}
    }
}

/// Handle a let statement for dead store tracking.
fn process_let_for_dead_stores(
    let_stmt: &ast::LetStmt,
    stmt: &ast::Stmt,
    line_index: &LineIndex,
    bindings: &mut BTreeMap<Box<str>, BindingState>,
) {
    let Some(pat) = let_stmt.pat() else { return };
    let is_mut = matches!(&pat, ast::Pat::IdentPat(ip) if ip.mut_token().is_some());
    match is_mut {
        true => {
            let Some(name) = extract_binding_name(&pat) else {
                return;
            };
            let span = span_from_node(stmt.syntax(), line_index);
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
    line_index: &LineIndex,
    bindings: &mut BTreeMap<Box<str>, BindingState>,
    out: &mut Vec<DataFlowFact>,
) {
    let Some(expr) = expr_stmt.expr() else { return };
    let assignment = extract_assignment(&expr);
    let Some((lhs_name, rhs)) = assignment else {
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
            span_from_node(stmt.syntax(), line_index),
            format!("value of `{lhs_name}` overwritten before being read").into_boxed_str(),
        ));
    }

    *state = (false, span_from_node(stmt.syntax(), line_index));
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
fn detect_discarded_results(
    sema: &Semantics<'_, RootDatabase>,
    stmt_list: &ast::StmtList,
    db: &RootDatabase,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    for stmt in stmt_list.statements() {
        let ast::Stmt::ExprStmt(expr_stmt) = &stmt else {
            continue;
        };
        let Some(expr) = expr_stmt.expr() else {
            continue;
        };
        if extract_assignment(&expr).is_some() {
            continue;
        }
        if !expr_returns_result(sema, &expr, db) {
            continue;
        }
        let span = span_from_node(stmt.syntax(), line_index);
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
fn detect_partial_error_handling(
    sema: &Semantics<'_, RootDatabase>,
    stmt_list: &ast::StmtList,
    db: &RootDatabase,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    let result_bindings = collect_result_bindings(sema, stmt_list, db, line_index);

    for (name, def_span) in &*result_bindings {
        check_partial_handling_in_stmts(name, def_span, stmt_list, line_index, out);
    }
}

/// Collect all Result-typed let bindings from a statement list.
fn collect_result_bindings(
    sema: &Semantics<'_, RootDatabase>,
    stmt_list: &ast::StmtList,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Box<[(Box<str>, IrSpan)]> {
    stmt_list
        .statements()
        .filter_map(|stmt| {
            let ast::Stmt::LetStmt(let_stmt) = &stmt else {
                return None;
            };
            let pat = let_stmt.pat()?;
            let init = let_stmt.initializer()?;
            match expr_returns_result(sema, &init, db) {
                true => {
                    let name = extract_binding_name(&pat)?;
                    let span = span_from_node(let_stmt.syntax(), line_index);
                    Some((name, span))
                }
                false => None,
            }
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Check a statement list for partial handling of a Result binding in match arms.
fn check_partial_handling_in_stmts(
    name: &str,
    def_span: &IrSpan,
    stmt_list: &ast::StmtList,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    for node in stmt_list.syntax().descendants() {
        if node.kind() != SyntaxKind::MATCH_EXPR {
            continue;
        }
        let Some(match_expr) = ast::MatchExpr::cast(node) else {
            continue;
        };
        check_match_for_partial_handling(name, def_span, &match_expr, line_index, out);
    }
}

/// Analyze a single match expression for partial error handling of a Result binding.
fn check_match_for_partial_handling(
    name: &str,
    def_span: &IrSpan,
    match_expr: &ast::MatchExpr,
    line_index: &LineIndex,
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
fn detect_swallowed_ok(
    sema: &Semantics<'_, RootDatabase>,
    stmt_list: &ast::StmtList,
    db: &RootDatabase,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    for stmt in stmt_list.statements() {
        match &stmt {
            ast::Stmt::ExprStmt(expr_stmt) => {
                check_expr_stmt_swallowed_ok(sema, expr_stmt, db, line_index, &stmt, out);
            }
            ast::Stmt::LetStmt(let_stmt) => {
                check_let_stmt_swallowed_ok(sema, let_stmt, db, line_index, &stmt, out);
            }
            ast::Stmt::Item(_) => {}
        }
    }
}

/// Check an expression statement for swallowed `.ok()` on Result.
fn check_expr_stmt_swallowed_ok(
    sema: &Semantics<'_, RootDatabase>,
    expr_stmt: &ast::ExprStmt,
    db: &RootDatabase,
    line_index: &LineIndex,
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
        sema,
        &mc,
        db,
        line_index,
        stmt,
        ".ok() on Result discards the error silently",
        out,
    );
}

/// Check a let statement with wildcard pattern for swallowed `.ok()` on Result.
fn check_let_stmt_swallowed_ok(
    sema: &Semantics<'_, RootDatabase>,
    let_stmt: &ast::LetStmt,
    db: &RootDatabase,
    line_index: &LineIndex,
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
        sema,
        &mc,
        db,
        line_index,
        stmt,
        "let _ = .ok() on Result discards the error silently",
        out,
    );
}

/// Validate the `.ok()` receiver is a non-write-macro Result and emit the finding.
fn emit_swallowed_ok_if_result(
    sema: &Semantics<'_, RootDatabase>,
    mc: &ast::MethodCallExpr,
    db: &RootDatabase,
    line_index: &LineIndex,
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
    if !expr_returns_result(sema, &receiver, db) {
        return;
    }
    let span = span_from_node(stmt.syntax(), line_index);
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

/// Methods that mutate `Vec<T>`.
const VEC_MUTATION_METHODS: &[&str] = &[
    "push",
    "pop",
    "insert",
    "remove",
    "swap_remove",
    "truncate",
    "clear",
    "retain",
    "reserve",
    "resize",
    "extend",
    "append",
    "splice",
    "drain",
    "dedup",
    "dedup_by",
    "dedup_by_key",
    "sort",
    "sort_by",
    "sort_by_key",
    "sort_unstable",
    "sort_unstable_by",
    "sort_unstable_by_key",
    "reverse",
    "rotate_left",
    "rotate_right",
    "fill",
    "fill_with",
];

/// Methods that mutate `String` (in addition to shared Vec-like methods).
const STRING_MUTATION_METHODS: &[&str] = &["push_str", "insert_str", "replace_range"];

/// Detect Vec/String bindings that are never mutated after construction.
fn detect_immutable_growable(
    pf: &ParsedFile<'_>,
    stmt_list: &ast::StmtList,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    for stmt in stmt_list.statements() {
        let ast::Stmt::LetStmt(let_stmt) = &stmt else {
            continue;
        };
        let Some(pat) = let_stmt.pat() else { continue };
        let Some(name) = extract_binding_name(&pat) else {
            continue;
        };
        let ann = classify_via_annotation(let_stmt);
        let sem = classify_via_semantics(&pf.sema, let_stmt, pf.db);
        let Some(type_label) = ann.or(sem) else {
            continue;
        };

        let mutated = binding_is_mutated(&name, stmt_list);
        let returned = binding_is_returned(&name, stmt_list);
        let passed_mut = binding_passed_as_mut_ref(&name, stmt_list);

        if !mutated && !returned && !passed_mut {
            let span = span_from_node(let_stmt.syntax(), line_index);
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

/// Check whether a binding name has any mutation method calls in the statement list.
fn binding_is_mutated(name: &str, stmt_list: &ast::StmtList) -> bool {
    stmt_list
        .syntax()
        .descendants()
        .any(|node| match node.kind() {
            SyntaxKind::METHOD_CALL_EXPR => method_call_mutates(name, &node),
            SyntaxKind::BIN_EXPR => bin_expr_mutates(name, &node),
            _ => false,
        })
}

/// Check whether a method call expression mutates the named binding.
fn method_call_mutates(binding_name: &str, node: &SyntaxNode) -> bool {
    let Some(mc) = ast::MethodCallExpr::cast(node.clone()) else {
        return false;
    };
    let Some(receiver) = mc.receiver() else {
        return false;
    };
    if receiver.syntax().text() != binding_name {
        return false;
    }
    let Some(method) = mc.name_ref() else {
        return false;
    };
    let method_name = method.text();
    VEC_MUTATION_METHODS
        .iter()
        .chain(STRING_MUTATION_METHODS.iter())
        .any(|m| method_name == *m)
}

/// Check whether a binary expression is an assignment to the named binding.
fn bin_expr_mutates(binding_name: &str, node: &SyntaxNode) -> bool {
    let Some(bin) = ast::BinExpr::cast(node.clone()) else {
        return false;
    };
    let is_assign = bin.op_token().is_some_and(|t| {
        matches!(
            t.kind(),
            SyntaxKind::EQ | SyntaxKind::PLUSEQ | SyntaxKind::MINUSEQ
        )
    });
    match is_assign {
        true => {
            let Some(lhs) = bin.lhs() else { return false };
            let lhs_text = lhs.syntax().text();
            // Matches `binding[...]` (index assignment) or `binding += ...`
            lhs_text == binding_name || {
                let s = lhs_text.to_string();
                s.starts_with(binding_name) && s[binding_name.len()..].starts_with('[')
            }
        }
        false => false,
    }
}

/// Check whether the binding is directly returned (the value itself, not a derived expression).
///
/// Suppresses when the binding is the tail expression or a direct `return binding` statement.
/// Does NOT suppress when the binding is merely referenced within a return expression
/// (e.g., `items.len()` returns `usize`, not the `Vec`).
fn binding_is_returned(name: &str, stmt_list: &ast::StmtList) -> bool {
    let direct_tail = stmt_list
        .tail_expr()
        .is_some_and(|tail| is_direct_name_ref(&tail, name));

    direct_tail
        || stmt_list
            .syntax()
            .descendants()
            .filter_map(ast::ReturnExpr::cast)
            .filter_map(|ret| ret.expr())
            .any(|expr| is_direct_name_ref(&expr, name))
}

/// Check whether an expression is a direct name reference to the given binding.
fn is_direct_name_ref(expr: &ast::Expr, name: &str) -> bool {
    matches!(expr, ast::Expr::PathExpr(pe)
        if pe.path().is_some_and(|p| p.syntax().text() == name))
}

/// Check whether the binding is passed as `&mut` argument to any function call.
fn binding_passed_as_mut_ref(name: &str, stmt_list: &ast::StmtList) -> bool {
    stmt_list
        .syntax()
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::REF_EXPR)
        .any(|n| {
            let Some(ref_expr) = ast::RefExpr::cast(n.clone()) else {
                return false;
            };
            ref_expr.mut_token().is_some()
                && ref_expr.expr().is_some_and(|e| e.syntax().text() == name)
        })
}
