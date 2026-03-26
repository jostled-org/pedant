//! Performance issue detection.
//!
//! Identifies repeated calls, unnecessary clones, allocations in loops,
//! and redundant collects within function bodies.

use line_index::LineIndex;
use ra_ap_hir::Semantics;
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::ast::HasArgList;
use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, ToSmolStr, ast};

use super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
use super::common::{
    ParsedFile, expr_references_binding, extract_binding_name, quality_fact,
    resolve_call_to_function, span_from_node,
};

/// Detect all performance issues within a function body.
pub(super) fn detect_perf_in_fn(
    pf: &ParsedFile<'_>,
    body: &ast::BlockExpr,
    stmt_list: &ast::StmtList,
) -> Box<[DataFlowFact]> {
    let mut facts = Vec::new();
    detect_repeated_calls(&pf.sema, stmt_list, pf.db, pf.line_index, &mut facts);
    detect_unnecessary_clones(stmt_list, pf.line_index, &mut facts);
    detect_allocation_in_loops(body, pf.line_index, &mut facts);
    detect_redundant_collects(stmt_list, pf.line_index, &mut facts);
    facts.into_boxed_slice()
}

// --- Repeated call detection ---

/// Detect repeated calls: same callee name with identical argument text within a scope.
fn detect_repeated_calls(
    sema: &Semantics<'_, RootDatabase>,
    stmt_list: &ast::StmtList,
    db: &RootDatabase,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    use std::collections::BTreeMap;

    let mut seen: BTreeMap<(Box<str>, u64), IrSpan> = BTreeMap::new();

    let call_nodes = stmt_list
        .syntax()
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::CALL_EXPR);

    for node in call_nodes {
        let sig = ast::CallExpr::cast(node)
            .and_then(|call| extract_call_signature(sema, &call, db, line_index));
        let Some((name, args_hash, span)) = sig else {
            continue;
        };
        let key = (name, args_hash);
        match seen.get(&key) {
            Some(first_span) => {
                out.push(quality_fact(
                    DataFlowKind::RepeatedCall,
                    *first_span,
                    span,
                    format!("`{}` called with identical arguments", key.0).into_boxed_str(),
                ));
            }
            None => {
                seen.insert(key, span);
            }
        }
    }
}

/// Hash the text content of an argument list without allocating.
fn hash_arg_text(arg_list: &ast::ArgList) -> u64 {
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

/// Extract (callee_name, args_hash, span) from a resolved call expression.
fn extract_call_signature(
    sema: &Semantics<'_, RootDatabase>,
    call: &ast::CallExpr,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Option<(Box<str>, u64, IrSpan)> {
    let func = resolve_call_to_function(sema, call)?;
    let name = Box::from(func.name(db).as_str());
    let args_hash = call.arg_list().map(|al| hash_arg_text(&al)).unwrap_or(0);
    Some((name, args_hash, span_from_node(call.syntax(), line_index)))
}

// --- Unnecessary clone detection ---

/// Detect unnecessary clones: `.clone()` called but the original binding is never used afterward.
fn detect_unnecessary_clones(
    stmt_list: &ast::StmtList,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    let stmts: Box<[ast::Stmt]> = stmt_list
        .statements()
        .collect::<Vec<_>>()
        .into_boxed_slice();

    for (idx, stmt) in stmts.iter().enumerate() {
        let ast::Stmt::LetStmt(let_stmt) = stmt else {
            continue;
        };
        let Some(init) = let_stmt.initializer() else {
            continue;
        };
        let receiver_name = match extract_clone_receiver(&init) {
            Some(name) => name,
            None => continue,
        };

        let used_after = stmts[idx + 1..]
            .iter()
            .any(|s| expr_references_binding(s.syntax(), &receiver_name));
        let used_in_tail = stmt_list
            .tail_expr()
            .is_some_and(|tail| expr_references_binding(tail.syntax(), &receiver_name));

        if !used_after && !used_in_tail {
            let span = span_from_node(stmt.syntax(), line_index);
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

/// Allocation constructor patterns that should be flagged inside loops.
const ALLOC_CONSTRUCTORS: &[(&str, &str)] = &[
    ("new", "Vec"),
    ("new", "String"),
    ("with_capacity", "Vec"),
    ("with_capacity", "String"),
];

/// Detect allocations inside loop bodies: `Vec::new()`, `String::new()`, etc.
fn detect_allocation_in_loops(
    body: &ast::BlockExpr,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    let loop_nodes = body.syntax().descendants().filter(|n| {
        matches!(
            n.kind(),
            SyntaxKind::FOR_EXPR | SyntaxKind::WHILE_EXPR | SyntaxKind::LOOP_EXPR
        )
    });
    for node in loop_nodes {
        collect_allocs_in_loop(&node, line_index, out);
    }
}

/// Collect allocation calls within a single loop node.
fn collect_allocs_in_loop(
    loop_node: &SyntaxNode,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    let alloc_calls = loop_node
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::CALL_EXPR)
        .filter_map(ast::CallExpr::cast)
        .filter(is_allocation_call);

    for call in alloc_calls {
        let span = span_from_node(call.syntax(), line_index);
        out.push(quality_fact(
            DataFlowKind::AllocationInLoop,
            span,
            span,
            Box::from("allocation inside loop body — consider hoisting"),
        ));
    }
}

/// Check whether a call expression is a known allocation constructor (e.g., `Vec::new()`).
fn is_allocation_call(call: &ast::CallExpr) -> bool {
    let Some(expr) = call.expr() else {
        return false;
    };
    let Some(path_expr) = ast::PathExpr::cast(expr.syntax().clone()) else {
        return false;
    };
    let Some(path) = path_expr.path() else {
        return false;
    };
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

// --- Redundant collect detection ---

/// Detect redundant collects: `.collect()` into a binding whose next use is `.iter()` or `.into_iter()`.
fn detect_redundant_collects(
    stmt_list: &ast::StmtList,
    line_index: &LineIndex,
    out: &mut Vec<DataFlowFact>,
) {
    let stmts: Box<[ast::Stmt]> = stmt_list
        .statements()
        .collect::<Vec<_>>()
        .into_boxed_slice();

    for (idx, stmt) in stmts.iter().enumerate() {
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
        let Some(binding_name) = extract_binding_name(&pat) else {
            continue;
        };

        let next_use_is_iter = stmts[idx + 1..]
            .iter()
            .any(|s| is_iter_call_on_node(s.syntax(), &binding_name))
            || stmt_list
                .tail_expr()
                .is_some_and(|tail| is_iter_call_on_node(tail.syntax(), &binding_name));

        if next_use_is_iter {
            let span = span_from_node(stmt.syntax(), line_index);
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

/// Check whether a node's first method call on a binding is `iter` or `into_iter`.
fn is_iter_call_on_node(node: &SyntaxNode, binding_name: &str) -> bool {
    first_method_on_binding(node, binding_name).is_some_and(|m| &*m == "iter" || &*m == "into_iter")
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

/// Find the direct method called on a binding within a syntax subtree.
fn first_method_on_binding(node: &SyntaxNode, binding_name: &str) -> Option<Box<str>> {
    node.descendants()
        .filter_map(ast::MethodCallExpr::cast)
        .find_map(|mc| {
            let recv = mc.receiver()?;
            let is_direct = matches!(&recv, ast::Expr::PathExpr(pe)
                if pe.path()
                    .and_then(|p| p.segment())
                    .and_then(|s| s.name_ref())
                    .is_some_and(|n| n.text().as_str() == binding_name));
            match is_direct {
                true => mc.name_ref().map(|n| Box::from(n.text().as_str())),
                false => None,
            }
        })
}
