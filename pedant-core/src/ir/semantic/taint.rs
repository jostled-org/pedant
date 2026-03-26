//! Taint propagation analysis.
//!
//! Traces data flow from capability sources (env var reads, filesystem reads)
//! to capability sinks (network calls, process exec). Reports one
//! `DataFlowFact` per detected source→sink flow.

use line_index::LineIndex;
use ra_ap_hir::Semantics;
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, ast};

use pedant_types::Capability;

use super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
use super::common::{
    ParsedFile, expr_references_binding, extract_binding_name, resolve_call_to_function,
    span_from_node,
};

/// Tainted binding: (name, source capability, source span).
type Taint = (Box<str>, Capability, IrSpan);

/// Known function patterns that produce tainted values.
const SOURCE_PATTERNS: &[(&str, &[&str], Capability)] = &[
    ("var", &["env"], Capability::EnvAccess),
    ("var_os", &["env"], Capability::EnvAccess),
    ("read", &["fs"], Capability::FileRead),
    ("read_to_string", &["fs"], Capability::FileRead),
    ("read_dir", &["fs"], Capability::FileRead),
    ("read_link", &["fs"], Capability::FileRead),
];

/// Known module segments that indicate a capability sink.
const SINK_MODULES: &[(&str, Capability)] = &[
    ("net", Capability::Network),
    ("process", Capability::ProcessExec),
];

/// Trace taint propagation within a function body.
///
/// Identifies bindings from capability sources and detects when tainted
/// values reach capability sinks.
pub(super) fn trace_taints_in_fn(
    pf: &ParsedFile<'_>,
    body: &ast::BlockExpr,
    stmt_list: &ast::StmtList,
) -> Box<[DataFlowFact]> {
    let tainted: Box<[Taint]> = collect_tainted_bindings(&pf.sema, stmt_list, pf.db, pf.line_index);
    collect_taint_flows(&pf.sema, body, pf.db, pf.line_index, &tainted)
}

/// Scan let-bindings in a statement list for capability source initializers.
fn collect_tainted_bindings(
    sema: &Semantics<'_, RootDatabase>,
    stmt_list: &ast::StmtList,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Box<[Taint]> {
    stmt_list
        .statements()
        .filter_map(|stmt| match stmt {
            ast::Stmt::LetStmt(let_stmt) => Some(let_stmt),
            _ => None,
        })
        .filter_map(|let_stmt| {
            let pat = let_stmt.pat()?;
            let init = let_stmt.initializer()?;
            let (cap, span) = find_source_in_expr(sema, init.syntax(), db, line_index)?;
            let name = extract_binding_name(&pat)?;
            Some((name, cap, span))
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Walk a function body for sink calls that consume tainted bindings.
fn collect_taint_flows(
    sema: &Semantics<'_, RootDatabase>,
    body: &ast::BlockExpr,
    db: &RootDatabase,
    line_index: &LineIndex,
    tainted: &[Taint],
) -> Box<[DataFlowFact]> {
    body.syntax()
        .descendants()
        .flat_map(|node| {
            let (sink_cap, sink_span) = classify_node_as_sink(sema, &node, db, line_index)?;
            Some(
                tainted
                    .iter()
                    .filter(move |(name, _, _)| expr_references_binding(&node, name))
                    .map(move |(_, cap, src_span)| DataFlowFact {
                        kind: DataFlowKind::TaintFlow,
                        source_capability: Some(*cap),
                        source_span: *src_span,
                        sink_capability: Some(sink_cap),
                        sink_span,
                        call_chain: Box::new([]),
                        message: format!("{cap:?} flows to {sink_cap:?}").into_boxed_str(),
                    }),
            )
        })
        .flatten()
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Classify a syntax node as a capability sink (call or method call).
fn classify_node_as_sink(
    sema: &Semantics<'_, RootDatabase>,
    node: &SyntaxNode,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Option<(Capability, IrSpan)> {
    match node.kind() {
        SyntaxKind::CALL_EXPR => {
            let call = ast::CallExpr::cast(node.clone())?;
            classify_call_as_sink(sema, &call, db, line_index)
        }
        SyntaxKind::METHOD_CALL_EXPR => {
            let mc = ast::MethodCallExpr::cast(node.clone())?;
            classify_method_call_as_sink(sema, &mc, db, line_index)
        }
        _ => None,
    }
}

/// Walk an expression subtree to find a capability source call.
fn find_source_in_expr(
    sema: &Semantics<'_, RootDatabase>,
    expr: &SyntaxNode,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Option<(Capability, IrSpan)> {
    expr.descendants().find_map(|node| match node.kind() {
        SyntaxKind::CALL_EXPR => {
            let call = ast::CallExpr::cast(node)?;
            let func = resolve_call_to_function(sema, &call)?;
            let cap = classify_function_as_source(func, db)?;
            Some((cap, span_from_node(call.syntax(), line_index)))
        }
        _ => None,
    })
}

/// Classify a resolved function as a capability source by checking its module path.
fn classify_function_as_source(func: ra_ap_hir::Function, db: &RootDatabase) -> Option<Capability> {
    let name = func.name(db);
    let name_str = name.as_str();
    let module = func.module(db);

    SOURCE_PATTERNS
        .iter()
        .find_map(|(fn_name, required_segments, cap)| {
            let name_matches = name_str == *fn_name;
            let path_matches = required_segments
                .iter()
                .all(|seg| module_path_contains(module, db, seg));
            (name_matches && path_matches).then_some(*cap)
        })
}

/// Classify a path-based call expression as a capability sink.
///
/// Tries semantic resolution first. Falls back to resolving the qualifier
/// type's module path for associated function calls (e.g., `TcpStream::connect`)
/// where `sema.resolve_path` on the full path returns `None`.
fn classify_call_as_sink(
    sema: &Semantics<'_, RootDatabase>,
    call: &ast::CallExpr,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Option<(Capability, IrSpan)> {
    if let Some(func) = resolve_call_to_function(sema, call) {
        let cap = classify_function_as_sink(func, db)?;
        return Some((cap, span_from_node(call.syntax(), line_index)));
    }
    let cap = classify_qualified_call_by_type(sema, call, db)?;
    Some((cap, span_from_node(call.syntax(), line_index)))
}

/// Classify an associated function call by resolving the qualifier type's module.
fn classify_qualified_call_by_type(
    sema: &Semantics<'_, RootDatabase>,
    call: &ast::CallExpr,
    db: &RootDatabase,
) -> Option<Capability> {
    let expr = call.expr()?;
    let path_expr = ast::PathExpr::cast(expr.syntax().clone())?;
    let path = path_expr.path()?;
    let qualifier = path.qualifier()?;
    let resolution = sema.resolve_path(&qualifier)?;
    match resolution {
        ra_ap_hir::PathResolution::Def(module_def) => {
            let module = module_def_module(module_def, db)?;
            match_sink_in_module(module, db)
        }
        _ => None,
    }
}

/// Get the defining module for a `ModuleDef`.
fn module_def_module(def: ra_ap_hir::ModuleDef, db: &RootDatabase) -> Option<ra_ap_hir::Module> {
    match def {
        ra_ap_hir::ModuleDef::Adt(adt) => Some(adt.module(db)),
        ra_ap_hir::ModuleDef::Function(f) => Some(f.module(db)),
        ra_ap_hir::ModuleDef::Module(m) => Some(m),
        ra_ap_hir::ModuleDef::TypeAlias(ta) => Some(ta.module(db)),
        ra_ap_hir::ModuleDef::Trait(t) => Some(t.module(db)),
        _ => None,
    }
}

/// Classify a method call expression as a capability sink.
fn classify_method_call_as_sink(
    sema: &Semantics<'_, RootDatabase>,
    method_call: &ast::MethodCallExpr,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Option<(Capability, IrSpan)> {
    let func = sema.resolve_method_call(method_call)?;
    let cap = classify_function_as_sink(func, db)?;
    Some((cap, span_from_node(method_call.syntax(), line_index)))
}

/// Classify a resolved function as a capability sink by checking its module path.
fn classify_function_as_sink(func: ra_ap_hir::Function, db: &RootDatabase) -> Option<Capability> {
    match_sink_in_module(func.module(db), db)
}

/// Walk a module's ancestors to find a known sink module segment.
fn match_sink_in_module(module: ra_ap_hir::Module, db: &RootDatabase) -> Option<Capability> {
    let mut current = Some(module);
    while let Some(m) = current {
        let cap = m
            .name(db)
            .and_then(|name| classify_segment_as_sink(name.as_str()));
        match cap {
            Some(_) => return cap,
            None => current = m.parent(db),
        }
    }
    None
}

/// Check whether a single module name matches a known sink.
fn classify_segment_as_sink(name: &str) -> Option<Capability> {
    SINK_MODULES
        .iter()
        .find_map(|(segment, cap)| (*segment == name).then_some(*cap))
}

/// Check whether any ancestor of a module has the given name.
fn module_path_contains(module: ra_ap_hir::Module, db: &RootDatabase, target: &str) -> bool {
    let mut current = Some(module);
    while let Some(m) = current {
        if m.name(db).is_some_and(|name| name.as_str() == target) {
            return true;
        }
        current = m.parent(db);
    }
    false
}
