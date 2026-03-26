//! Concurrency issue detection.
//!
//! Detects lock guards held across `.await` points and inconsistent lock
//! ordering across functions within a file.

use std::collections::BTreeMap;

use line_index::LineIndex;
use ra_ap_syntax::ast::{HasArgList, HasName};
use ra_ap_syntax::{AstNode, SyntaxKind, ast};

use super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
use super::common::{ParsedFile, extract_binding_name, quality_fact, span_from_node};

/// Lock acquisition method names on `Mutex` and `RwLock`.
const LOCK_METHODS: &[&str] = &["lock", "read", "write"];

/// Detect lock guards held across `.await` points within a function body.
pub(super) fn detect_lock_await_in_fn(
    pf: &ParsedFile<'_>,
    fn_node: &ast::Fn,
    stmt_list: &ast::StmtList,
) -> Box<[DataFlowFact]> {
    if fn_node.async_token().is_none() {
        return Box::<[DataFlowFact]>::default();
    }
    let mut facts = Vec::new();
    detect_lock_across_await_in_stmts(stmt_list, pf.line_index, &mut facts);
    facts.into_boxed_slice()
}

/// Detect inconsistent lock ordering across all functions in a file.
pub(super) fn detect_lock_ordering(pf: &ParsedFile<'_>) -> Box<[DataFlowFact]> {
    collect_lock_ordering_violations(&pf.tree, pf.line_index)
}

// --- Lock-across-await detection ---

/// Check whether an expression is a direct lock acquisition (method chain).
///
/// Returns `true` for `mutex.lock().unwrap()` but `false` for
/// `{ let guard = mutex.lock().unwrap(); *guard }` — nested blocks scope
/// the guard, so the outer binding is not a guard.
fn contains_lock_call(expr: &ast::Expr) -> bool {
    lock_receiver_name(expr).is_some()
}

/// Extract the receiver name from a lock acquisition within an expression.
///
/// For `m1.lock().unwrap()`, returns `"m1"`.
/// Returns `None` when the expression is a block (`{ let g = m.lock(); ... }`)
/// because locks inside block expressions are scoped.
fn lock_receiver_name(expr: &ast::Expr) -> Option<Box<str>> {
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
        .find_map(|mc| extract_path_receiver_name(&mc))
}

/// Returns `true` when `node` is nested inside a `BlockExpr` that is
/// a descendant of `root`.
fn is_inside_block_expr(node: &ra_ap_syntax::SyntaxNode, root: &ra_ap_syntax::SyntaxNode) -> bool {
    node.ancestors()
        .skip(1)
        .take_while(|a| a != root)
        .any(|a| ast::BlockExpr::can_cast(a.kind()))
}

/// Extract a simple binding name from a method call's receiver.
fn extract_path_receiver_name(mc: &ast::MethodCallExpr) -> Option<Box<str>> {
    let recv = mc.receiver()?;
    let ast::Expr::PathExpr(pe) = &recv else {
        return None;
    };
    pe.path()?
        .segment()?
        .name_ref()
        .map(|n| Box::from(n.text().as_str()))
}

/// Check whether a syntax subtree contains an `.await` expression.
fn contains_await(node: &ra_ap_syntax::SyntaxNode) -> bool {
    node.descendants()
        .any(|n| n.kind() == SyntaxKind::AWAIT_EXPR)
}

/// Detect lock guards held across await points within a statement list.
fn detect_lock_across_await_in_stmts(
    stmt_list: &ast::StmtList,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    let mut guards: BTreeMap<Box<str>, IrSpan> = BTreeMap::new();

    for stmt in stmt_list.statements() {
        process_stmt_for_lock_await(&stmt, line_index, &mut guards, out);
    }

    if let Some(tail) = stmt_list.tail_expr() {
        check_await_with_live_guards(tail.syntax(), &guards, line_index, out);
    }
}

/// Process a single statement for lock-across-await tracking.
fn process_stmt_for_lock_await(
    stmt: &ast::Stmt,
    line_index: &LineIndex,
    guards: &mut BTreeMap<Box<str>, IrSpan>,
    out: &mut Vec<DataFlowFact>,
) {
    match stmt {
        ast::Stmt::LetStmt(let_stmt) => {
            process_let_for_lock_await(let_stmt, stmt, line_index, guards, out);
        }
        ast::Stmt::ExprStmt(expr_stmt) => {
            process_expr_for_lock_await(expr_stmt, stmt, line_index, guards, out);
        }
        ast::Stmt::Item(_) => {}
    }
}

/// Handle a let statement for lock-across-await.
fn process_let_for_lock_await(
    let_stmt: &ast::LetStmt,
    stmt: &ast::Stmt,
    line_index: &LineIndex,
    guards: &mut BTreeMap<Box<str>, IrSpan>,
    out: &mut Vec<DataFlowFact>,
) {
    let acquired = let_stmt
        .initializer()
        .is_some_and(|init| contains_lock_call(&init));
    if !acquired {
        check_await_with_live_guards(stmt.syntax(), guards, line_index, out);
        return;
    }
    let name = let_stmt.pat().and_then(|pat| extract_binding_name(&pat));
    let Some(name) = name else { return };
    let span = span_from_node(stmt.syntax(), line_index);
    guards.insert(name, span);
}

/// Handle an expression statement for lock-across-await.
fn process_expr_for_lock_await(
    expr_stmt: &ast::ExprStmt,
    stmt: &ast::Stmt,
    line_index: &LineIndex,
    guards: &mut BTreeMap<Box<str>, IrSpan>,
    out: &mut Vec<DataFlowFact>,
) {
    let removed = expr_stmt
        .expr()
        .and_then(|e| try_remove_drop_target(&e, guards));
    if removed.is_some() {
        return;
    }
    check_await_with_live_guards(stmt.syntax(), guards, line_index, out);
}

/// If the node contains an await expression and guards are live, emit a finding.
fn check_await_with_live_guards(
    node: &ra_ap_syntax::SyntaxNode,
    guards: &BTreeMap<Box<str>, IrSpan>,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    if guards.is_empty() || !contains_await(node) {
        return;
    }
    let await_span = node
        .descendants()
        .find(|n| n.kind() == SyntaxKind::AWAIT_EXPR)
        .map(|n| span_from_node(&n, line_index));
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
///
/// Compares the drop argument text against map keys without allocating,
/// using `SyntaxText` equality against `&str`.
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

// --- Lock ordering detection ---

/// Lock acquisition record: (receiver_name, span).
type LockAcquisition = (Box<str>, IrSpan);

/// A function's name paired with its ordered lock acquisitions.
type FnLockSequence = (Box<str>, Box<[LockAcquisition]>);

/// Extract the ordered sequence of lock acquisitions from a function body.
fn extract_lock_sequence(fn_node: &ast::Fn, line_index: &LineIndex) -> Option<FnLockSequence> {
    let name = fn_node.name()?;
    let body = fn_node.body()?;
    let stmt_list = body.stmt_list()?;

    let mut locks = Vec::new();
    for stmt in stmt_list.statements() {
        let ast::Stmt::LetStmt(let_stmt) = &stmt else {
            continue;
        };
        let Some(init) = let_stmt.initializer() else {
            continue;
        };
        let Some(receiver) = lock_receiver_name(&init) else {
            continue;
        };
        let span = span_from_node(stmt.syntax(), line_index);
        locks.push((receiver, span));
    }

    match locks.is_empty() {
        true => None,
        false => Some((Box::from(name.text().as_str()), locks.into_boxed_slice())),
    }
}

/// Collect inconsistent lock ordering violations across all functions in a file.
fn collect_lock_ordering_violations(
    tree: &ast::SourceFile,
    line_index: &LineIndex,
) -> Box<[DataFlowFact]> {
    use std::collections::BTreeSet;

    let sequences: Box<[FnLockSequence]> = tree
        .syntax()
        .descendants()
        .filter_map(ast::Fn::cast)
        .filter_map(|f| extract_lock_sequence(&f, line_index))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    let pairs: Box<[(usize, usize, usize)]> = sequences
        .iter()
        .enumerate()
        .flat_map(|(seq_idx, (_, locks))| collect_pair_indices(seq_idx, locks))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    let mut first_seen: BTreeMap<(&str, &str), (usize, usize, usize)> = BTreeMap::new();
    for &(seq_idx, ia, ib) in pairs.iter() {
        let recv_a: &str = &sequences[seq_idx].1[ia].0;
        let recv_b: &str = &sequences[seq_idx].1[ib].0;
        first_seen
            .entry((recv_a, recv_b))
            .or_insert((seq_idx, ia, ib));
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
        let fwd_fn = &sequences[fwd_seq].0;
        let rev_fn = &sequences[rev_seq].0;
        facts.push(quality_fact(
            DataFlowKind::InconsistentLockOrder,
            sequences[fwd_seq].1[fwd_ia].1,
            sequences[rev_seq].1[rev_ib].1,
            format!("locks `{a}` and `{b}` acquired in different order: `{fwd_fn}` vs `{rev_fn}`")
                .into_boxed_str(),
        ));
    }

    facts.into_boxed_slice()
}

/// Collect ordered lock pair indices from a single function's lock sequence.
fn collect_pair_indices(seq_idx: usize, locks: &[LockAcquisition]) -> Vec<(usize, usize, usize)> {
    let mut pairs = Vec::new();
    for (i, (recv_a, _)) in locks.iter().enumerate() {
        for (j, (recv_b, _)) in locks[i + 1..].iter().enumerate() {
            if recv_a != recv_b {
                pairs.push((seq_idx, i, i + 1 + j));
            }
        }
    }
    pairs
}
