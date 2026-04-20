//! Taint propagation analysis.
//!
//! Traces data flow from capability sources (env var reads, filesystem reads)
//! to capability sinks (network calls, process exec). Reports one
//! `DataFlowFact` per detected source→sink flow.
//!
//! Sink locations are precomputed by `FnContext::build` during the merged
//! body walk. This module iterates the precomputed sinks rather than
//! rescanning the function body.

use ra_ap_hir::Semantics;
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, ast};

use pedant_types::Capability;

use super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
use super::common::{FnContext, extract_binding_name, resolve_call_to_function, span_from_node};

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

/// Detect taint propagation within a function body.
pub(super) fn detect(ctx: &FnContext<'_>) -> Box<[DataFlowFact]> {
    let tainted: Box<[Taint]> = collect_tainted_bindings(ctx);
    if tainted.is_empty() {
        return Box::default();
    }
    collect_taint_flows(ctx, &tainted)
}

/// Scan let-bindings in the precomputed statement list for capability source initializers.
fn collect_tainted_bindings(ctx: &FnContext<'_>) -> Box<[Taint]> {
    ctx.stmts
        .iter()
        .filter_map(|stmt| match stmt {
            ast::Stmt::LetStmt(let_stmt) => Some(let_stmt),
            _ => None,
        })
        .filter_map(|let_stmt| {
            let pat = let_stmt.pat()?;
            let init = let_stmt.initializer()?;
            let (cap, span) = find_source_in_expr(ctx.sema, init.syntax(), ctx.db, ctx.line_index)?;
            let name = extract_binding_name(&pat)?;
            Some((name, cap, span))
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Check precomputed capability sinks for tainted binding references.
///
/// Iterates `ctx.capability_sinks` (built during `FnContext::build`).
/// Each sink carries precomputed NAME_REF names, so this is a pure
/// set intersection — no AST walk at detection time.
fn collect_taint_flows(ctx: &FnContext<'_>, tainted: &[Taint]) -> Box<[DataFlowFact]> {
    let mut facts = Vec::new();

    for sink in ctx.capability_sinks.iter() {
        // Check precomputed NAME_REFs against tainted bindings — no subtree walk.
        for (name, cap, src_span) in tainted {
            let flows = sink
                .referenced_names
                .iter()
                .any(|ref_name| **ref_name == **name);
            if flows {
                facts.push(DataFlowFact {
                    kind: DataFlowKind::TaintFlow,
                    source_capability: Some(*cap),
                    source_span: *src_span,
                    sink_capability: Some(sink.capability),
                    sink_span: sink.span,
                    call_chain: Box::new([]),
                    message: format!("{cap:?} flows to {:?}", sink.capability).into_boxed_str(),
                });
            }
        }
    }

    facts.into_boxed_slice()
}

/// Walk an expression subtree to find a capability source call.
fn find_source_in_expr(
    sema: &Semantics<'_, RootDatabase>,
    expr: &SyntaxNode,
    db: &RootDatabase,
    line_index: &line_index::LineIndex,
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
