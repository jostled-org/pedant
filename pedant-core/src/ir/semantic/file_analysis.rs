//! Cached file-level semantic analysis.
//!
//! `SemanticFileAnalysis` is the primary semantic boundary. For one file, it
//! owns every derived fact that the per-query API previously rebuilt on each
//! call: call graph edges, function entries, reachability set, per-function
//! data flow facts, resolved types, and a flat aggregate of all flows.
//! Constructed once by `SemanticContext::analyze_file`, then cached and
//! shared via `Arc`.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;

use ra_ap_hir::{DisplayTarget, Semantics};
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::{AstNode, SyntaxKind, ast};

use super::super::facts::DataFlowFact;
use super::common::{FnContext, ParsedFile, display_target_for_file, format_type};
use super::function_summary::{FlowRange, FunctionAnalysisSummary, FunctionSummaryData};
use super::{FnEntry, concurrency, perf, quality, reachability};

/// Cached file-level semantic analysis.
///
/// Immutable after construction. Collections use `Box<[T]>` or `Arc<[T]>`
/// depending on whether downstream consumers share ownership. Per-function
/// summaries are stored in a sorted `BTreeMap` keyed by function name.
pub struct SemanticFileAnalysis {
    call_graph: Box<[(Box<str>, Box<str>)]>,
    fn_entries: Box<[FnEntry]>,
    reachable_names: BTreeSet<Box<str>>,
    data_flows: Arc<[DataFlowFact]>,
    fn_summaries: BTreeMap<Box<str>, FunctionSummaryData>,
    /// Eagerly resolved types keyed by `(line, column)` (1-based line, 0-based col).
    resolved_types: BTreeMap<(usize, usize), Box<str>>,
}

impl SemanticFileAnalysis {
    /// Build a complete file analysis from a parsed file context.
    ///
    /// One traversal of the file's functions builds `FnContext` per function,
    /// deriving call graph edges, function entries, data flow facts, and
    /// detector outputs from the same precomputed state. Type resolution is
    /// eagerly cached. No subsequent parse is needed.
    pub(super) fn build(pf: &ParsedFile<'_>) -> Self {
        let mut call_graph_edges: Vec<(Box<str>, Box<str>)> = Vec::new();
        let mut fn_entries: Vec<FnEntry> = Vec::new();
        let mut fn_summaries: BTreeMap<Box<str>, FunctionSummaryData> = BTreeMap::new();
        let mut all_flows: Vec<DataFlowFact> = Vec::new();
        let mut resolved_types: BTreeMap<(usize, usize), Box<str>> = BTreeMap::new();

        // Compute display target once for the file (all functions share it).
        let display_target = display_target_for_file(&pf.sema, pf.file_id, pf.db);

        // Track function syntax ranges to skip during module-level type resolution.
        let mut fn_ranges: Vec<ra_ap_syntax::TextRange> = Vec::new();

        for fn_node in pf.tree.syntax().descendants().filter_map(ast::Fn::cast) {
            let fn_range = fn_node.syntax().text_range();
            fn_ranges.push(fn_range);

            let Some(ctx) = FnContext::build(pf, &fn_node) else {
                continue;
            };

            // Derive call graph edges from precomputed call sites.
            ctx.extend_call_graph(&mut call_graph_edges);

            // Run detectors over the shared precomputed context.
            let taint = super::taint::detect(&ctx);
            let quality = quality::detect(&ctx);
            let performance = perf::detect(&ctx);
            let concurrency = concurrency::detect(&ctx);

            // Append flows to the file-level aggregate, recording ranges.
            let taint_range = append_flows(&mut all_flows, taint);
            let quality_range = append_flows(&mut all_flows, quality);
            let perf_range = append_flows(&mut all_flows, performance);
            let conc_range = append_flows(&mut all_flows, concurrency);

            // Resolve types from this function's syntax tree.
            if let Some(dt) = display_target {
                resolve_types_in_subtree(pf, fn_node.syntax(), dt, &mut resolved_types);
            }

            let (name, start, end, entry, lock_acquisitions) = ctx.into_entry_data();
            fn_entries.push((Box::from(&*name), start, end, entry));
            fn_summaries.insert(
                name,
                FunctionSummaryData {
                    lock_acquisitions,
                    taint: taint_range,
                    quality: quality_range,
                    performance: perf_range,
                    concurrency: conc_range,
                },
            );
        }

        call_graph_edges.sort();
        call_graph_edges.dedup();
        let call_graph = call_graph_edges.into_boxed_slice();
        let fn_entries = fn_entries.into_boxed_slice();
        let reachable_names = reachability::compute_reachable_names(&fn_entries, &call_graph);

        // File-level lock ordering analysis from precomputed summaries.
        let lock_ordering = concurrency::detect_lock_ordering(&fn_summaries);
        all_flows.extend(lock_ordering.into_vec());

        let data_flows: Arc<[DataFlowFact]> = all_flows.into();

        // Module-level type resolution: skip nodes inside function syntax ranges.
        if let Some(dt) = display_target {
            resolve_module_level_types(pf, dt, &fn_ranges, &mut resolved_types);
        }

        Self {
            call_graph,
            fn_entries,
            reachable_names,
            data_flows,
            fn_summaries,
            resolved_types,
        }
    }

    /// Deduplicated `(caller, callee)` pairs for this file's call graph.
    pub fn call_graph(&self) -> &[(Box<str>, Box<str>)] {
        &self.call_graph
    }

    /// All data flow facts detected in this file (taint, quality, perf, concurrency).
    ///
    /// Returns a shared `Arc` — callers that need ownership clone the `Arc`,
    /// not the individual facts.
    pub fn data_flows(&self) -> &Arc<[DataFlowFact]> {
        &self.data_flows
    }

    /// Borrowed view into a named function's precomputed semantic summary.
    ///
    /// Returns `None` when the function is not found in the file or has
    /// no body (e.g., trait method declarations).
    pub fn function(&self, name: &str) -> Option<FunctionAnalysisSummary<'_>> {
        self.fn_summaries
            .get(name)
            .map(|data| FunctionAnalysisSummary::new(data, &self.data_flows))
    }

    /// Resolve the type at a `(line, column)` position from the cached table.
    ///
    /// Uses 1-based line numbers and 0-based column offsets. Returns `None`
    /// when the position was not resolvable during file analysis construction.
    pub fn resolve_type(&self, line: usize, column: usize) -> Option<&str> {
        self.resolved_types.get(&(line, column)).map(|s| &**s)
    }

    /// Check whether a line falls within a function reachable from entry points.
    pub fn is_line_reachable(&self, line: usize) -> bool {
        reachability::is_line_in_reachable_fn(&self.fn_entries, &self.reachable_names, line)
    }

    /// Batch reachability check: one `bool` per input line.
    pub fn check_reachability_batch(&self, lines: &[usize]) -> Box<[bool]> {
        lines
            .iter()
            .map(|&line| self.is_line_reachable(line))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

/// Append a batch of facts to the aggregate and return the range they occupy.
fn append_flows(all: &mut Vec<DataFlowFact>, facts: Box<[DataFlowFact]>) -> FlowRange {
    let start = all.len();
    all.extend(facts.into_vec());
    FlowRange::new(start, all.len())
}

/// Resolve type-bearing positions within a syntax subtree (function or item).
fn resolve_types_in_subtree(
    pf: &ParsedFile<'_>,
    root: &ra_ap_syntax::SyntaxNode,
    display_target: DisplayTarget,
    resolved: &mut BTreeMap<(usize, usize), Box<str>>,
) {
    for node in root.descendants() {
        resolve_type_bearing_node(pf, &node, display_target, resolved);
    }
}

/// Resolve module-level type-bearing positions, skipping function syntax ranges.
///
/// Function-scoped types are already resolved during the per-function loop.
fn resolve_module_level_types(
    pf: &ParsedFile<'_>,
    display_target: DisplayTarget,
    fn_ranges: &[ra_ap_syntax::TextRange],
    resolved: &mut BTreeMap<(usize, usize), Box<str>>,
) {
    for node in pf.tree.syntax().descendants() {
        let range = node.text_range();
        if fn_ranges.iter().any(|fr| fr.contains_range(range)) {
            continue;
        }
        resolve_type_bearing_node(pf, &node, display_target, resolved);
    }
}

/// Classify and resolve a single type-bearing syntax node.
fn resolve_type_bearing_node(
    pf: &ParsedFile<'_>,
    node: &ra_ap_syntax::SyntaxNode,
    display_target: DisplayTarget,
    resolved: &mut BTreeMap<(usize, usize), Box<str>>,
) {
    match node.kind() {
        SyntaxKind::LET_STMT => {
            resolve_let_stmt_type(pf, node, display_target, resolved);
        }
        SyntaxKind::PATH_TYPE
        | SyntaxKind::TUPLE_TYPE
        | SyntaxKind::ARRAY_TYPE
        | SyntaxKind::SLICE_TYPE
        | SyntaxKind::REF_TYPE
        | SyntaxKind::PTR_TYPE => {
            resolve_type_node(pf, node, display_target, resolved);
        }
        _ => {}
    }
}

/// Resolve the type annotation on a let statement and cache at the annotation's position.
fn resolve_let_stmt_type(
    pf: &ParsedFile<'_>,
    node: &ra_ap_syntax::SyntaxNode,
    display_target: DisplayTarget,
    resolved: &mut BTreeMap<(usize, usize), Box<str>>,
) {
    let Some(let_stmt) = ast::LetStmt::cast(node.clone()) else {
        return;
    };

    // Resolve from initializer expression type.
    let init_resolved = let_stmt.initializer().and_then(|init| {
        let type_str = resolve_expr_type(&pf.sema, &init, pf.db, display_target)?;
        let lc = pf.line_index.line_col(init.syntax().text_range().start());
        Some(((lc.line + 1) as usize, lc.col as usize, type_str))
    });
    if let Some((line, col, type_str)) = init_resolved {
        resolved.insert((line, col), type_str);
    }

    // Resolve from type annotation if present.
    let ann_resolved = let_stmt.ty().and_then(|ty| {
        let type_str = resolve_ast_type(&pf.sema, &ty, pf.db, display_target)?;
        let lc = pf.line_index.line_col(ty.syntax().text_range().start());
        Some(((lc.line + 1) as usize, lc.col as usize, type_str))
    });
    if let Some((line, col, type_str)) = ann_resolved {
        resolved.insert((line, col), type_str);
    }
}

/// Resolve a standalone type syntax node.
fn resolve_type_node(
    pf: &ParsedFile<'_>,
    node: &ra_ap_syntax::SyntaxNode,
    display_target: DisplayTarget,
    resolved: &mut BTreeMap<(usize, usize), Box<str>>,
) {
    let Some(ty) = ast::Type::cast(node.clone()) else {
        return;
    };
    let Some(type_str) = resolve_ast_type(&pf.sema, &ty, pf.db, display_target) else {
        return;
    };
    let range = ty.syntax().text_range();
    let lc = pf.line_index.line_col(range.start());
    resolved.insert(((lc.line + 1) as usize, lc.col as usize), type_str);
}

/// Resolve an expression's type to a canonical string.
fn resolve_expr_type(
    sema: &Semantics<'_, RootDatabase>,
    expr: &ast::Expr,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Option<Box<str>> {
    let ty_info = sema.type_of_expr(expr)?;
    Some(format_type(&ty_info.original, db, display_target))
}

/// Resolve an AST type node to a canonical string.
fn resolve_ast_type(
    sema: &Semantics<'_, RootDatabase>,
    ty: &ast::Type,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Option<Box<str>> {
    sema.resolve_type(ty)
        .map(|resolved| format_type(&resolved, db, display_target))
        .or_else(|| resolve_path_type(sema, ty, db, display_target))
}

/// Resolve a path type by looking up the path definition.
fn resolve_path_type(
    sema: &Semantics<'_, RootDatabase>,
    ty: &ast::Type,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Option<Box<str>> {
    let ast::Type::PathType(p) = ty else {
        return None;
    };
    let path = p.path()?;
    let resolution = sema.resolve_path(&path)?;
    match resolution {
        ra_ap_hir::PathResolution::Def(module_def) => {
            resolve_module_def_type(module_def, db, display_target)
        }
        _ => None,
    }
}

/// Get the type representation for a module-level definition.
fn resolve_module_def_type(
    def: ra_ap_hir::ModuleDef,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Option<Box<str>> {
    match def {
        ra_ap_hir::ModuleDef::TypeAlias(alias) => {
            Some(format_type(&alias.ty(db), db, display_target))
        }
        ra_ap_hir::ModuleDef::Adt(adt) => Some(format_type(&adt.ty(db), db, display_target)),
        ra_ap_hir::ModuleDef::BuiltinType(builtin) => Some(builtin.name().as_str().into()),
        _ => None,
    }
}
