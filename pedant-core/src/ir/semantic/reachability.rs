//! Call graph reachability analysis.
//!
//! Builds a call graph for a file and determines which functions are
//! transitively reachable from public entry points.

use line_index::LineIndex;
use ra_ap_hir::Semantics;
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::ast::{HasAttrs, HasName, HasVisibility};
use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, ast};

use super::common::{ParsedFile, resolve_call_to_function};

/// Function entry: (name, start_line, end_line, is_entry_point).
type FnEntry = (Box<str>, usize, usize, bool);

/// Build a call graph for all functions in a parsed file.
///
/// Returns deduplicated `(caller, callee)` pairs.
pub(super) fn build_call_graph(pf: &ParsedFile<'_>) -> Box<[(Box<str>, Box<str>)]> {
    let mut edges = Vec::new();
    for fn_node in pf.tree.syntax().descendants().filter_map(ast::Fn::cast) {
        collect_fn_call_edges(&pf.sema, &fn_node, pf.db, &mut edges);
    }
    edges.sort();
    edges.dedup();
    edges.into_boxed_slice()
}

/// Batch reachability check: checks each line against the call graph.
///
/// Reuses the already-parsed `ParsedFile` to build the call graph, avoiding
/// a redundant file setup.
pub(super) fn check_reachability(pf: &ParsedFile<'_>, lines: &[usize]) -> Box<[bool]> {
    let fns: Box<[FnEntry]> = pf
        .tree
        .syntax()
        .descendants()
        .filter_map(ast::Fn::cast)
        .filter_map(|f| fn_entry(&f, pf.line_index))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    let edges = build_call_graph(pf);
    let reachable = reachable_set(&fns, &edges);

    lines
        .iter()
        .map(|&line| is_line_reachable(&fns, &reachable, line))
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Collect call edges from a single function's body.
fn collect_fn_call_edges(
    sema: &Semantics<'_, RootDatabase>,
    fn_node: &ast::Fn,
    db: &RootDatabase,
    edges: &mut Vec<(Box<str>, Box<str>)>,
) {
    let name = match fn_node.name() {
        Some(n) => n,
        None => return,
    };
    let Some(body) = fn_node.body() else {
        return;
    };

    for node in body.syntax().descendants() {
        if let Some(callee_name) = resolve_node_callee(sema, node, db) {
            edges.push((Box::from(name.text().as_str()), callee_name));
        }
    }
}

/// Try to resolve a syntax node as a call target using kind-based dispatch.
fn resolve_node_callee(
    sema: &Semantics<'_, RootDatabase>,
    node: SyntaxNode,
    db: &RootDatabase,
) -> Option<Box<str>> {
    match node.kind() {
        SyntaxKind::CALL_EXPR => {
            ast::CallExpr::cast(node).and_then(|call| resolve_call_callee(sema, &call, db))
        }
        SyntaxKind::METHOD_CALL_EXPR => {
            ast::MethodCallExpr::cast(node).and_then(|mc| resolve_method_callee(sema, &mc, db))
        }
        _ => None,
    }
}

/// Resolve the callee of a path-based call expression.
fn resolve_call_callee(
    sema: &Semantics<'_, RootDatabase>,
    call: &ast::CallExpr,
    db: &RootDatabase,
) -> Option<Box<str>> {
    let func = resolve_call_to_function(sema, call)?;
    Some(Box::from(func.name(db).as_str()))
}

/// Resolve the callee of a method call expression.
fn resolve_method_callee(
    sema: &Semantics<'_, RootDatabase>,
    method_call: &ast::MethodCallExpr,
    db: &RootDatabase,
) -> Option<Box<str>> {
    let func = sema.resolve_method_call(method_call)?;
    Some(Box::from(func.name(db).as_str()))
}

/// Extract function metadata from an `ast::Fn` node.
fn fn_entry(f: &ast::Fn, line_index: &LineIndex) -> Option<FnEntry> {
    let name = Box::from(f.name()?.text().as_str());
    let range = f.syntax().text_range();
    let start = line_index.line_col(range.start());
    let end = line_index.line_col(range.end());
    let is_pub = f.visibility().is_some();
    let is_main = &*name == "main";
    let is_test = f.attrs().any(|attr: ast::Attr| {
        attr.path()
            .map(|p: ast::Path| p.syntax().text() == "test")
            .unwrap_or(false)
    });
    Some((
        name,
        (start.line + 1) as usize,
        (end.line + 1) as usize,
        is_pub || is_main || is_test,
    ))
}

/// Precompute the set of all function names reachable from entry points via BFS.
fn reachable_set<'a>(
    fns: &'a [FnEntry],
    edges: &'a [(Box<str>, Box<str>)],
) -> std::collections::BTreeSet<&'a str> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (caller, callee) in edges {
        adj.entry(caller).or_default().push(callee);
    }

    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut queue = VecDeque::new();

    for (name, _, _, is_entry) in fns {
        if *is_entry {
            visited.insert(name);
            queue.push_back(&**name);
        }
    }

    while let Some(current) = queue.pop_front() {
        let callees = match adj.get(current) {
            Some(c) => c,
            None => continue,
        };
        for callee in callees {
            if visited.insert(callee) {
                queue.push_back(callee);
            }
        }
    }

    visited
}

/// Check whether a single line falls within a reachable function.
fn is_line_reachable(
    fns: &[FnEntry],
    reachable: &std::collections::BTreeSet<&str>,
    line: usize,
) -> bool {
    let target = match fns
        .iter()
        .find(|(_, start, end, _)| line >= *start && line <= *end)
    {
        Some((name, _, _, _)) => name,
        None => return false,
    };

    reachable.contains(&**target)
}
