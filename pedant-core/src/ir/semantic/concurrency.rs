//! Concurrency issue detection.
//!
//! Detects lock guards held across `.await` points, inconsistent lock
//! ordering across functions within a file, and unobserved spawn calls
//! where the `JoinHandle` is dropped or unbound.

use std::collections::BTreeMap;

use ra_ap_syntax::ast::HasArgList;
use ra_ap_syntax::{AstNode, SyntaxKind, ast};

use super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
use super::common::{
    FnContext, LockAcquisition, lock_receiver_name, quality_fact, resolve_call_to_function,
};
use super::function_summary::FunctionSummaryData;

/// Detect inconsistent lock ordering across all functions in a file.
///
/// Reads precomputed lock acquisitions from `fn_summaries` rather than
/// rebuilding `FnContext` per function.
pub(super) fn detect_lock_ordering(
    fn_summaries: &BTreeMap<Box<str>, FunctionSummaryData>,
) -> Box<[DataFlowFact]> {
    collect_lock_ordering_violations(fn_summaries)
}

/// Detect per-function concurrency issues using precomputed context.
pub(super) fn detect(ctx: &FnContext<'_>) -> Box<[DataFlowFact]> {
    let mut facts = Vec::new();

    if ctx.is_async {
        detect_lock_across_await(ctx, &mut facts);
    }

    detect_unobserved_spawn(ctx, &mut facts);
    facts.into_boxed_slice()
}

// --- Lock-across-await detection ---

/// Detect lock guards held across await points using precomputed lock
/// acquisitions and shared statement list from `FnContext`.
fn detect_lock_across_await(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
    // Seed the guard map from precomputed lock acquisitions.
    let mut guards: BTreeMap<Box<str>, IrSpan> = ctx
        .lock_acquisitions
        .iter()
        .map(|acq| (Box::from(&*acq.guard_name), acq.span))
        .collect();

    // Walk statements checking for awaits with live guards.
    for stmt in ctx.stmts.iter() {
        let check = match stmt {
            ast::Stmt::LetStmt(let_stmt) => let_stmt
                .initializer()
                .is_none_or(|init| lock_receiver_name(&init).is_none()),
            ast::Stmt::ExprStmt(expr_stmt) => expr_stmt
                .expr()
                .and_then(|e| try_remove_drop_target(&e, &mut guards))
                .is_none(),
            ast::Stmt::Item(_) => false,
        };
        if check {
            check_await_with_live_guards(stmt.syntax(), &guards, ctx, out);
        }
    }

    if let Some(tail) = &ctx.tail_expr {
        check_await_with_live_guards(tail.syntax(), &guards, ctx, out);
    }
}

/// Check whether a syntax subtree contains an `.await` expression.
fn contains_await(node: &ra_ap_syntax::SyntaxNode) -> bool {
    node.descendants()
        .any(|n| n.kind() == SyntaxKind::AWAIT_EXPR)
}

/// If the node contains an await expression and guards are live, emit a finding.
fn check_await_with_live_guards(
    node: &ra_ap_syntax::SyntaxNode,
    guards: &BTreeMap<Box<str>, IrSpan>,
    ctx: &FnContext<'_>,
    out: &mut Vec<DataFlowFact>,
) {
    if guards.is_empty() || !contains_await(node) {
        return;
    }
    let await_span = node
        .descendants()
        .find(|n| n.kind() == SyntaxKind::AWAIT_EXPR)
        .map(|n| ctx.span(&n));
    let Some(await_span) = await_span else {
        return;
    };

    for (name, lock_span) in guards {
        out.push(quality_fact(
            DataFlowKind::LockAcrossAwait,
            *lock_span,
            await_span,
            format!("lock guard `{name}` held across `.await` point").into_boxed_str(),
        ));
    }
}

/// Remove a guard from the map if the expression is `drop(guard_name)`.
fn try_remove_drop_target(
    expr: &ast::Expr,
    guards: &mut BTreeMap<Box<str>, IrSpan>,
) -> Option<IrSpan> {
    let ast::Expr::CallExpr(call) = expr else {
        return None;
    };
    let callee = call.expr()?;
    if callee.syntax().text() != "drop" {
        return None;
    }
    let arg_list = call.arg_list()?;
    let mut args = arg_list.args();
    let first = args.next()?;
    if args.next().is_some() {
        return None;
    }
    let arg_text = first.syntax().text();
    let key = guards.keys().find(|k| arg_text == ***k)?.clone();
    guards.remove(&key)
}

// --- Unobserved spawn detection ---

/// Module path segments that identify standard spawn functions.
const SPAWN_MODULE_MARKERS: &[&str] = &["thread", "tokio"];

/// Detect unobserved spawn calls within the precomputed statement list.
fn detect_unobserved_spawn(ctx: &FnContext<'_>, out: &mut Vec<DataFlowFact>) {
    for stmt in ctx.stmts.iter() {
        match &stmt {
            ast::Stmt::ExprStmt(expr_stmt) => {
                check_expr_stmt_unobserved_spawn(ctx, expr_stmt, stmt, out);
            }
            ast::Stmt::LetStmt(let_stmt) => {
                check_let_stmt_unobserved_spawn(ctx, let_stmt, stmt, out);
            }
            ast::Stmt::Item(_) => {}
        }
    }
}

/// Check an expression statement for an unobserved spawn call.
fn check_expr_stmt_unobserved_spawn(
    ctx: &FnContext<'_>,
    expr_stmt: &ast::ExprStmt,
    stmt: &ast::Stmt,
    out: &mut Vec<DataFlowFact>,
) {
    let Some(expr) = expr_stmt.expr() else {
        return;
    };
    let ast::Expr::CallExpr(call) = &expr else {
        return;
    };
    emit_unobserved_spawn_if_known(
        ctx,
        call,
        stmt,
        "spawn() called without observing JoinHandle",
        out,
    );
}

/// Check a let statement with wildcard pattern for an unobserved spawn call.
fn check_let_stmt_unobserved_spawn(
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
    let ast::Expr::CallExpr(call) = &init else {
        return;
    };
    emit_unobserved_spawn_if_known(ctx, call, stmt, "let _ = spawn() discards JoinHandle", out);
}

/// Validate the call targets a known spawn function and emit the finding.
fn emit_unobserved_spawn_if_known(
    ctx: &FnContext<'_>,
    call: &ast::CallExpr,
    stmt: &ast::Stmt,
    message: &str,
    out: &mut Vec<DataFlowFact>,
) {
    if !is_known_spawn_call(ctx, call) {
        return;
    }
    let span = ctx.span(stmt.syntax());
    out.push(quality_fact(
        DataFlowKind::UnobservedSpawn,
        span,
        span,
        Box::from(message),
    ));
}

/// Resolve a call expression and check if it targets a known spawn function.
fn is_known_spawn_call(ctx: &FnContext<'_>, call: &ast::CallExpr) -> bool {
    let Some(func) = resolve_call_to_function(ctx.sema, call) else {
        return false;
    };
    let name = func.name(ctx.db);
    if name.as_str() != "spawn" {
        return false;
    }
    let module = func.module(ctx.db);
    let module_path = module.path_to_root(ctx.db);
    module_path.iter().any(|m| {
        m.name(ctx.db)
            .is_some_and(|n| SPAWN_MODULE_MARKERS.contains(&n.as_str()))
    })
}

// --- Lock ordering detection ---

/// Borrowed function name + lock acquisition slice from a precomputed summary.
type FnLockSequence<'a> = (&'a str, &'a [LockAcquisition]);

/// Collect inconsistent lock ordering violations by borrowing directly
/// from precomputed function summaries (no cloning of names or spans).
fn collect_lock_ordering_violations(
    fn_summaries: &BTreeMap<Box<str>, FunctionSummaryData>,
) -> Box<[DataFlowFact]> {
    use std::collections::BTreeSet;

    let sequences: Box<[FnLockSequence<'_>]> = fn_summaries
        .iter()
        .filter(|(_, summary)| !summary.lock_acquisitions.is_empty())
        .map(|(name, summary)| (&**name, &*summary.lock_acquisitions))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    let mut first_seen: BTreeMap<(&str, &str), (usize, usize, usize)> = BTreeMap::new();
    for (seq_idx, (_, locks)) in sequences.iter().enumerate() {
        insert_lock_pairs(seq_idx, locks, &mut first_seen);
    }

    let mut facts = Vec::new();
    let mut reported: BTreeSet<(&str, &str)> = BTreeSet::new();

    for (&(a, b), &(fwd_seq, fwd_ia, _)) in &first_seen {
        let Some(&(rev_seq, _, rev_ib)) = first_seen.get(&(b, a)) else {
            continue;
        };
        let canonical = match a < b {
            true => (a, b),
            false => (b, a),
        };
        if !reported.insert(canonical) {
            continue;
        }
        let fwd_fn = sequences[fwd_seq].0;
        let rev_fn = sequences[rev_seq].0;
        facts.push(quality_fact(
            DataFlowKind::InconsistentLockOrder,
            sequences[fwd_seq].1[fwd_ia].span,
            sequences[rev_seq].1[rev_ib].span,
            format!("locks `{a}` and `{b}` acquired in different order: `{fwd_fn}` vs `{rev_fn}`")
                .into_boxed_str(),
        ));
    }

    facts.into_boxed_slice()
}

/// Insert ordered lock pairs from a single function's lock acquisitions.
fn insert_lock_pairs<'a>(
    seq_idx: usize,
    locks: &'a [LockAcquisition],
    first_seen: &mut BTreeMap<(&'a str, &'a str), (usize, usize, usize)>,
) {
    for (i, acq_a) in locks.iter().enumerate() {
        for (j, acq_b) in locks[i + 1..].iter().enumerate() {
            if acq_a.receiver_name != acq_b.receiver_name {
                first_seen
                    .entry((&acq_a.receiver_name, &acq_b.receiver_name))
                    .or_insert((seq_idx, i, i + 1 + j));
            }
        }
    }
}
