//! Shared helpers for semantic analysis submodules.
//!
//! Contains the file parsing preamble (`with_parsed_file`) and utility
//! functions used across multiple detection domains.

use std::collections::{BTreeMap, BTreeSet};

use line_index::LineIndex;
use ra_ap_hir::{DisplayTarget, EditionedFileId, HirDisplay, Semantics};
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::ast::{HasArgList, HasAttrs, HasName, HasVisibility};
use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, ToSmolStr, ast};
use ra_ap_vfs::{AbsPathBuf, VfsPath};

use pedant_types::Capability;

use super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
use super::SemanticContext;

/// A precomputed capability sink: call or method call classified as
/// a capability target (network, process exec, etc.) during the body walk.
///
/// NAME_REFs in the sink's subtree are collected eagerly so that taint
/// detection becomes a set intersection — no per-sink subtree walk needed.
pub(super) struct CapabilitySink {
    pub(super) capability: Capability,
    pub(super) span: IrSpan,
    /// All NAME_REF texts found in this sink's syntax subtree.
    pub(super) referenced_names: Box<[Box<str>]>,
}

/// Derived state from the single body descendants walk.
struct BodyDerivedState {
    mutated_bindings: BTreeSet<Box<str>>,
    returned_bindings: BTreeSet<Box<str>>,
    mut_ref_bindings: BTreeSet<Box<str>>,
    call_sites: Box<[CallSite]>,
    alloc_in_loop_spans: Box<[IrSpan]>,
    capability_sinks: Box<[CapabilitySink]>,
}

/// Parsed file context passed to semantic analysis closures.
///
/// Created once per file by [`with_parsed_file`], then shared across
/// all detection passes to avoid redundant parsing.
pub(super) struct ParsedFile<'a> {
    pub(super) sema: Semantics<'a, RootDatabase>,
    pub(super) tree: ast::SourceFile,
    pub(super) line_index: &'a LineIndex,
    pub(super) db: &'a RootDatabase,
    pub(super) file_id: ra_ap_ide::FileId,
}

/// Parse a file and run a closure with the parsed context.
///
/// Handles file lookup, database attachment, semantic construction,
/// and line index retrieval. Returns `None` when the file is not in
/// the VFS or the line index cannot be computed.
pub(super) fn with_parsed_file<T>(
    ctx: &SemanticContext,
    file: &str,
    f: impl FnOnce(&ParsedFile<'_>) -> T,
) -> Option<T> {
    ctx.file_setup_count.set(ctx.file_setup_count.get() + 1);
    let (file_id, db) = file_setup(ctx, file)?;
    let line_index_arc = ctx.host.analysis().file_line_index(file_id).ok()?;
    ra_ap_hir::attach_db(db, || {
        let sema = Semantics::new(db);
        let editioned = EditionedFileId::current_edition(db, file_id);
        let tree = sema.parse(editioned);
        Some(f(&ParsedFile {
            sema,
            tree,
            line_index: &line_index_arc,
            db,
            file_id,
        }))
    })
}

/// Map an absolute file path to a VFS `FileId` and database reference.
fn file_setup<'a>(
    ctx: &'a SemanticContext,
    file: &str,
) -> Option<(ra_ap_ide::FileId, &'a RootDatabase)> {
    let file_id = file_id_for_path(ctx, file)?;
    let db = ctx.host.raw_database();
    Some((file_id, db))
}

/// Map an absolute file path to a VFS `FileId`.
fn file_id_for_path(ctx: &SemanticContext, path: &str) -> Option<ra_ap_ide::FileId> {
    let abs = AbsPathBuf::try_from(path).ok()?;
    let vfs_path = VfsPath::from(abs);
    let (file_id, _) = ctx.vfs.file_id(&vfs_path)?;
    Some(file_id)
}

/// Convert a `SyntaxNode` position to an `IrSpan` using the file's line index.
pub(super) fn span_from_node(node: &SyntaxNode, line_index: &LineIndex) -> IrSpan {
    let offset = node.text_range().start();
    let lc = line_index.line_col(offset);
    IrSpan {
        line: (lc.line + 1) as usize,
        column: lc.col as usize,
    }
}

/// Construct a quality/perf/concurrency `DataFlowFact` (no capability source/sink).
pub(super) fn quality_fact(
    kind: DataFlowKind,
    source_span: IrSpan,
    sink_span: IrSpan,
    message: Box<str>,
) -> DataFlowFact {
    DataFlowFact {
        kind,
        source_capability: None,
        source_span,
        sink_capability: None,
        sink_span,
        call_chain: Box::new([]),
        message,
    }
}

/// Format a resolved `Type` as a canonical string.
pub(super) fn format_type(
    ty: &ra_ap_hir::Type<'_>,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Box<str> {
    ty.display(db, display_target).to_string().into_boxed_str()
}

/// Build a `DisplayTarget` for rendering types from a given file.
///
/// Returns `None` if the file does not belong to any crate.
pub(super) fn display_target_for_file(
    sema: &Semantics<'_, RootDatabase>,
    file_id: ra_ap_ide::FileId,
    db: &RootDatabase,
) -> Option<DisplayTarget> {
    let krate = sema.first_crate(file_id)?;
    Some(DisplayTarget::from_crate(db, krate.into()))
}

/// Extract the simple binding name from a pattern (e.g., `let key = ...` → `"key"`).
pub(super) fn extract_binding_name(pat: &ast::Pat) -> Option<Box<str>> {
    match pat {
        ast::Pat::IdentPat(ident) => ident.name().map(|n| Box::from(n.text().as_str())),
        _ => None,
    }
}

/// Check whether a syntax subtree contains a `NameRef` matching `binding_name`.
pub(super) fn expr_references_binding(expr: &SyntaxNode, binding_name: &str) -> bool {
    expr.descendants()
        .filter(|n| n.kind() == SyntaxKind::NAME_REF)
        .any(|n| n.text() == binding_name)
}

/// Resolve a path-based call expression to its `ra_ap_hir::Function`.
pub(super) fn resolve_call_to_function(
    sema: &Semantics<'_, RootDatabase>,
    call: &ast::CallExpr,
) -> Option<ra_ap_hir::Function> {
    let expr = call.expr()?;
    let path_expr = ast::PathExpr::cast(expr.syntax().clone())?;
    let path = path_expr.path()?;
    let resolution = sema.resolve_path(&path)?;
    match resolution {
        ra_ap_hir::PathResolution::Def(ra_ap_hir::ModuleDef::Function(f)) => Some(f),
        _ => None,
    }
}

/// Extract a simple name from a direct path expression (e.g., `x` → `"x"`).
///
/// Returns `None` for qualified paths (`a::b`) or non-path expressions.
pub(super) fn direct_path_name(expr: &ast::Expr) -> Option<Box<str>> {
    let ast::Expr::PathExpr(pe) = expr else {
        return None;
    };
    let path = pe.path()?;
    path.qualifier().is_none().then_some(())?;
    path.segment()?
        .name_ref()
        .map(|n| Box::from(n.text().as_str()))
}

// ---------------------------------------------------------------------------
// Mutation method classification
// ---------------------------------------------------------------------------

/// Methods that mutate `Vec<T>`.
pub(super) const VEC_MUTATION_METHODS: &[&str] = &[
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
pub(super) const STRING_MUTATION_METHODS: &[&str] = &["push_str", "insert_str", "replace_range"];

/// Check whether a method name is a known mutation method on `Vec` or `String`.
pub(super) fn is_mutation_method(method: &str) -> bool {
    VEC_MUTATION_METHODS
        .iter()
        .chain(STRING_MUTATION_METHODS.iter())
        .any(|m| *m == method)
}

// ---------------------------------------------------------------------------
// FnContext — precomputed per-function analysis context
// ---------------------------------------------------------------------------

/// Per-binding method call index: binding name → sorted (stmt_index, method_name) pairs.
type BindingMethodIndex = BTreeMap<Box<str>, Box<[(usize, Box<str>)]>>;

/// A resolved call site: callee name, argument hash, and source span.
pub(super) struct CallSite {
    pub(super) callee: Box<str>,
    pub(super) args_hash: u64,
    pub(super) span: IrSpan,
}

/// A lock acquisition: guard binding name, lock receiver name, source span.
pub(super) struct LockAcquisition {
    pub(super) guard_name: Box<str>,
    pub(super) receiver_name: Box<str>,
    pub(super) span: IrSpan,
}

/// Precomputed per-function analysis context.
///
/// Built once per function during `SemanticFileAnalysis` construction.
/// Holds shared AST handles and precomputed derived facts that all
/// detectors and the call-graph builder consume. One traversal of the
/// function body populates binding indices, call sites, loop ranges,
/// lock acquisitions, and function entry metadata.
pub(super) struct FnContext<'a> {
    /// Collected statements (shared across all detectors).
    pub(super) stmts: Box<[ast::Stmt]>,
    /// Tail expression, if any.
    pub(super) tail_expr: Option<ast::Expr>,
    /// Whether the function is async.
    pub(super) is_async: bool,
    /// Semantics handle for type resolution.
    pub(super) sema: &'a Semantics<'a, RootDatabase>,
    /// Root database for name resolution.
    pub(super) db: &'a RootDatabase,
    /// Line index for span computation.
    pub(super) line_index: &'a LineIndex,

    // --- Binding indices ---
    /// Per-binding sorted statement indices where the name appears as a reference.
    pub(super) binding_stmt_refs: BTreeMap<Box<str>, Box<[usize]>>,
    /// Binding names referenced in the tail expression.
    pub(super) binding_in_tail: BTreeSet<Box<str>>,
    /// Binding names with mutation method calls or assignment operators.
    pub(super) mutated_bindings: BTreeSet<Box<str>>,
    /// Binding names directly returned via tail or `return` statement.
    pub(super) returned_bindings: BTreeSet<Box<str>>,
    /// Binding names passed as `&mut` references.
    pub(super) mut_ref_bindings: BTreeSet<Box<str>>,

    // --- Call sites ---
    /// Resolved call sites in statement order. Used by repeated-call detection
    /// and fed into the file-level call graph.
    pub(super) call_sites: Box<[CallSite]>,

    // --- Loop ranges ---
    /// Allocation calls found inside loop bodies. Pre-identified during build
    /// so the detector just emits findings.
    pub(super) alloc_in_loop_spans: Box<[IrSpan]>,

    // --- Capability sinks ---
    /// Precomputed capability sink locations for taint analysis.
    pub(super) capability_sinks: Box<[CapabilitySink]>,

    // --- Match expressions ---
    /// All match expressions found in the statement list, precomputed for
    /// partial error handling detection (avoids per-binding descendants walks).
    pub(super) match_exprs: Box<[ast::MatchExpr]>,

    // --- Method-on-binding index ---
    /// Per-binding sorted `(stmt_index, method_name)` pairs for direct method
    /// calls. Used by redundant-collect detection to avoid forward-scanning.
    pub(super) binding_method_calls: BindingMethodIndex,
    /// Method called on a binding in the tail expression, if any.
    pub(super) binding_method_in_tail: BTreeMap<Box<str>, Box<str>>,

    // --- Lock acquisitions ---
    /// Ordered lock acquisitions for lock-across-await and lock-ordering.
    pub(super) lock_acquisitions: Box<[LockAcquisition]>,

    // --- Function entry metadata ---
    /// Function name.
    pub(super) fn_name: Box<str>,
    /// 1-based start line.
    pub(super) start_line: usize,
    /// 1-based end line.
    pub(super) end_line: usize,
    /// `true` when `pub`, `main`, or `#[test]`.
    pub(super) is_entry_point: bool,
}

impl<'a> FnContext<'a> {
    /// Build a precomputed context from a parsed file and function node.
    ///
    /// Returns `None` when the function has no body, statement list, or name.
    pub(super) fn build(pf: &'a ParsedFile<'a>, fn_node: &ast::Fn) -> Option<Self> {
        let name_node = fn_node.name()?;
        let body = fn_node.body()?;
        let stmt_list = body.stmt_list()?;
        let stmts: Box<[ast::Stmt]> = stmt_list
            .statements()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let tail_expr = stmt_list.tail_expr();
        let is_async = fn_node.async_token().is_some();

        // Per-statement NAME_REF index (needs statement-level granularity).
        let binding_stmt_refs = build_binding_stmt_refs(&stmts);
        let binding_in_tail = build_binding_refs_in_expr(tail_expr.as_ref());

        // Single walk over body descendants: binding flags + call sites + alloc-in-loop + sinks.
        let derived = build_body_derived_state(pf, &body, tail_expr.as_ref());

        // Per-statement lock acquisitions (no descendants walk needed).
        let lock_acquisitions = build_lock_acquisitions(pf.line_index, &stmts);

        // Match expressions for partial error handling detection.
        let match_exprs = build_match_exprs(&stmt_list);

        // Per-binding method call index for redundant-collect detection.
        let binding_method_calls = build_binding_method_calls(&stmts);
        let binding_method_in_tail = build_binding_method_in_tail(tail_expr.as_ref());

        // Function entry metadata.
        let fn_name = Box::from(name_node.text().as_str());
        let range = fn_node.syntax().text_range();
        let start_lc = pf.line_index.line_col(range.start());
        let end_lc = pf.line_index.line_col(range.end());
        let is_pub = fn_node.visibility().is_some();
        let is_main = &*fn_name == "main";
        let is_test = fn_node.attrs().any(|attr: ast::Attr| {
            attr.path()
                .map(|p: ast::Path| p.syntax().text() == "test")
                .unwrap_or(false)
        });

        Some(Self {
            stmts,
            tail_expr,
            is_async,
            sema: &pf.sema,
            db: pf.db,
            line_index: pf.line_index,
            binding_stmt_refs,
            binding_in_tail,
            mutated_bindings: derived.mutated_bindings,
            returned_bindings: derived.returned_bindings,
            mut_ref_bindings: derived.mut_ref_bindings,
            call_sites: derived.call_sites,
            alloc_in_loop_spans: derived.alloc_in_loop_spans,
            capability_sinks: derived.capability_sinks,
            match_exprs,
            binding_method_calls,
            binding_method_in_tail,
            lock_acquisitions,
            fn_name,
            start_line: (start_lc.line + 1) as usize,
            end_line: (end_lc.line + 1) as usize,
            is_entry_point: is_pub || is_main || is_test,
        })
    }

    /// Check if `name` is referenced in any statement after `after_index`.
    pub(super) fn binding_used_after(&self, name: &str, after_index: usize) -> bool {
        self.binding_stmt_refs
            .get(name)
            .is_some_and(|indices| indices.partition_point(|&i| i <= after_index) < indices.len())
    }

    /// Check if `name` is referenced in the tail expression.
    pub(super) fn binding_used_in_tail(&self, name: &str) -> bool {
        self.binding_in_tail.contains(name)
    }

    /// Check if `name` has any mutation method calls or assignments.
    pub(super) fn binding_is_mutated(&self, name: &str) -> bool {
        self.mutated_bindings.contains(name)
    }

    /// Check if `name` is directly returned.
    pub(super) fn binding_is_returned(&self, name: &str) -> bool {
        self.returned_bindings.contains(name)
    }

    /// Check if `name` is passed as `&mut`.
    pub(super) fn binding_passed_as_mut_ref(&self, name: &str) -> bool {
        self.mut_ref_bindings.contains(name)
    }

    /// Check if any statement after `after_index` (or the tail) has an
    /// `iter()` or `into_iter()` call directly on `name`.
    pub(super) fn next_use_is_iter(&self, name: &str, after_index: usize) -> bool {
        let in_stmts = self.binding_method_calls.get(name).is_some_and(|calls| {
            calls
                .iter()
                .filter(|(idx, _)| *idx > after_index)
                .any(|(_, method)| &**method == "iter" || &**method == "into_iter")
        });
        let in_tail = self
            .binding_method_in_tail
            .get(name)
            .is_some_and(|m| &**m == "iter" || &**m == "into_iter");
        in_stmts || in_tail
    }

    /// Compute an `IrSpan` from a syntax node.
    pub(super) fn span(&self, node: &SyntaxNode) -> IrSpan {
        span_from_node(node, self.line_index)
    }

    /// Extend a mutable edge vec with `(caller, callee)` pairs from call sites.
    ///
    /// Takes a pre-allocated vec to extend rather than returning a new collection,
    /// avoiding intermediate allocation.
    pub(super) fn extend_call_graph(&self, edges: &mut Vec<(Box<str>, Box<str>)>) {
        let caller: &str = &self.fn_name;
        edges.extend(
            self.call_sites
                .iter()
                .map(|cs| (Box::from(caller), cs.callee.clone())),
        );
    }

    /// Consume the context and return function entry metadata and lock acquisitions.
    ///
    /// Flow facts are stored separately via `FlowRange` in the caller.
    pub(super) fn into_entry_data(self) -> (Box<str>, usize, usize, bool, Box<[LockAcquisition]>) {
        (
            self.fn_name,
            self.start_line,
            self.end_line,
            self.is_entry_point,
            self.lock_acquisitions,
        )
    }
}

/// Build per-binding → sorted statement indices where NAME_REF appears.
fn build_binding_stmt_refs(stmts: &[ast::Stmt]) -> BTreeMap<Box<str>, Box<[usize]>> {
    let mut refs: BTreeMap<Box<str>, Vec<usize>> = BTreeMap::new();
    for (i, stmt) in stmts.iter().enumerate() {
        for node in stmt.syntax().descendants() {
            if node.kind() == SyntaxKind::NAME_REF {
                refs.entry(node.text().to_string().into_boxed_str())
                    .or_default()
                    .push(i);
            }
        }
    }
    refs.into_iter()
        .map(|(k, mut v)| {
            v.dedup();
            (k, v.into_boxed_slice())
        })
        .collect()
}

/// Collect binding names referenced in an expression subtree.
fn build_binding_refs_in_expr(expr: Option<&ast::Expr>) -> BTreeSet<Box<str>> {
    expr.map(|e| {
        e.syntax()
            .descendants()
            .filter(|n| n.kind() == SyntaxKind::NAME_REF)
            .map(|n| n.text().to_string().into_boxed_str())
            .collect()
    })
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Merged body walk — binding flags, call sites, alloc-in-loop
// ---------------------------------------------------------------------------

/// Single walk over `body.syntax().descendants()` that computes:
/// - Binding mutation/return/&mut-pass flags
/// - Resolved call sites (for repeated-call detection and call graph)
/// - Allocation-in-loop spans (for performance detection)
///
/// Replaces three separate `descendants()` traversals with one.
fn build_body_derived_state(
    pf: &ParsedFile<'_>,
    body: &ast::BlockExpr,
    tail: Option<&ast::Expr>,
) -> BodyDerivedState {
    let mut mutated = BTreeSet::new();
    let mut returned = BTreeSet::new();
    let mut mut_ref = BTreeSet::new();
    let mut call_sites = Vec::new();
    let mut alloc_in_loop_spans = Vec::new();
    let mut sinks = Vec::new();

    let body_syntax = body.syntax();

    for node in body_syntax.descendants() {
        match node.kind() {
            SyntaxKind::METHOD_CALL_EXPR => {
                process_method_call(&node, pf, &mut mutated, &mut call_sites, &mut sinks);
            }
            SyntaxKind::CALL_EXPR => {
                process_call_expr(
                    &node,
                    pf,
                    body_syntax,
                    &mut call_sites,
                    &mut alloc_in_loop_spans,
                    &mut sinks,
                );
            }
            SyntaxKind::BIN_EXPR => {
                process_bin_expr(&node, &mut mutated);
            }
            SyntaxKind::REF_EXPR => {
                process_ref_expr(&node, &mut mut_ref);
            }
            SyntaxKind::RETURN_EXPR => {
                process_return_expr(&node, &mut returned);
            }
            _ => {}
        }
    }

    // Check tail expression for direct return.
    let tail_name = tail.and_then(direct_path_name);
    if let Some(name) = tail_name {
        returned.insert(name);
    }

    BodyDerivedState {
        mutated_bindings: mutated,
        returned_bindings: returned,
        mut_ref_bindings: mut_ref,
        call_sites: call_sites.into_boxed_slice(),
        alloc_in_loop_spans: alloc_in_loop_spans.into_boxed_slice(),
        capability_sinks: sinks.into_boxed_slice(),
    }
}

/// Handle a METHOD_CALL_EXPR: check mutation, resolve as call site, classify as sink.
fn process_method_call(
    node: &SyntaxNode,
    pf: &ParsedFile<'_>,
    mutated: &mut BTreeSet<Box<str>>,
    call_sites: &mut Vec<CallSite>,
    sinks: &mut Vec<CapabilitySink>,
) {
    let Some(mc) = ast::MethodCallExpr::cast(node.clone()) else {
        return;
    };
    // Mutation check.
    let is_mut = mc
        .receiver()
        .zip(mc.name_ref())
        .filter(|(_, method)| is_mutation_method(method.text().as_str()));
    if let Some((recv, _)) = is_mut {
        mutated.insert(recv.syntax().text().to_string().into_boxed_str());
    }
    // Call site resolution + sink classification.
    let Some(func) = pf.sema.resolve_method_call(&mc) else {
        return;
    };
    let name = Box::from(func.name(pf.db).as_str());
    let hash = mc.arg_list().map(|al| hash_arg_text(&al)).unwrap_or(0);
    let span = span_from_node(mc.syntax(), pf.line_index);
    call_sites.push(CallSite {
        callee: name,
        args_hash: hash,
        span,
    });
    let sink_cap = classify_function_as_sink(func, pf.db);
    if let Some(cap) = sink_cap {
        sinks.push(CapabilitySink {
            capability: cap,
            span,
            referenced_names: collect_name_refs(node),
        });
    }
}

/// Handle a CALL_EXPR: resolve as call site, check alloc-in-loop, classify as sink.
fn process_call_expr(
    node: &SyntaxNode,
    pf: &ParsedFile<'_>,
    body_syntax: &SyntaxNode,
    call_sites: &mut Vec<CallSite>,
    alloc_in_loop_spans: &mut Vec<IrSpan>,
    sinks: &mut Vec<CapabilitySink>,
) {
    let Some(call) = ast::CallExpr::cast(node.clone()) else {
        return;
    };
    // Call site resolution + sink classification.
    let resolved = resolve_call_to_function(&pf.sema, &call);
    let sink_cap = match resolved {
        Some(func) => {
            let name = Box::from(func.name(pf.db).as_str());
            let hash = call.arg_list().map(|al| hash_arg_text(&al)).unwrap_or(0);
            let span = span_from_node(call.syntax(), pf.line_index);
            call_sites.push(CallSite {
                callee: name,
                args_hash: hash,
                span,
            });
            classify_function_as_sink(func, pf.db)
        }
        // Fallback: resolve qualifier type for associated function calls
        // (e.g., TcpStream::connect where full path resolution returns None).
        None => classify_qualified_call_by_type(&pf.sema, &call, pf.db),
    };
    if let Some(cap) = sink_cap {
        sinks.push(CapabilitySink {
            capability: cap,
            span: span_from_node(call.syntax(), pf.line_index),
            referenced_names: collect_name_refs(node),
        });
    }
    // Allocation-in-loop check.
    if is_allocation_call(&call) && is_inside_loop(node, body_syntax) {
        alloc_in_loop_spans.push(span_from_node(call.syntax(), pf.line_index));
    }
}

/// Handle a BIN_EXPR: check assignment mutation.
fn process_bin_expr(node: &SyntaxNode, mutated: &mut BTreeSet<Box<str>>) {
    let Some(bin) = ast::BinExpr::cast(node.clone()) else {
        return;
    };
    let is_assign = bin.op_token().is_some_and(|t| {
        matches!(
            t.kind(),
            SyntaxKind::EQ | SyntaxKind::PLUSEQ | SyntaxKind::MINUSEQ
        )
    });
    if !is_assign {
        return;
    }
    let Some(lhs) = bin.lhs() else { return };
    let text = lhs.syntax().text().to_string();
    let name = text.split('[').next().unwrap_or(&text);
    mutated.insert(Box::from(name));
}

/// Handle a REF_EXPR: check &mut pass.
fn process_ref_expr(node: &SyntaxNode, mut_ref: &mut BTreeSet<Box<str>>) {
    let Some(ref_expr) = ast::RefExpr::cast(node.clone()) else {
        return;
    };
    if ref_expr.mut_token().is_none() {
        return;
    }
    let Some(e) = ref_expr.expr() else { return };
    mut_ref.insert(e.syntax().text().to_string().into_boxed_str());
}

/// Handle a RETURN_EXPR: check direct binding return.
fn process_return_expr(node: &SyntaxNode, returned: &mut BTreeSet<Box<str>>) {
    let name = ast::ReturnExpr::cast(node.clone())
        .and_then(|ret| ret.expr())
        .and_then(|expr| direct_path_name(&expr));
    let Some(n) = name else { return };
    returned.insert(n);
}

/// Hash the text content of an argument list.
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

/// Allocation constructor patterns that should be flagged inside loops.
const ALLOC_CONSTRUCTORS: &[(&str, &str)] = &[
    ("new", "Vec"),
    ("new", "String"),
    ("with_capacity", "Vec"),
    ("with_capacity", "String"),
];

/// Check whether a call expression is a known allocation constructor.
fn is_allocation_call(call: &ast::CallExpr) -> bool {
    let path = call
        .expr()
        .and_then(|e| ast::PathExpr::cast(e.syntax().clone()))
        .and_then(|pe| pe.path());
    let Some(path) = path else { return false };
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

/// Check whether a node is inside a loop body by walking ancestors.
fn is_inside_loop(node: &SyntaxNode, root: &SyntaxNode) -> bool {
    node.ancestors().take_while(|a| a != root).any(|a| {
        matches!(
            a.kind(),
            SyntaxKind::FOR_EXPR | SyntaxKind::WHILE_EXPR | SyntaxKind::LOOP_EXPR
        )
    })
}

/// Collect all NAME_REF text values from a syntax subtree.
///
/// Used to eagerly capture references in capability sink nodes so that
/// taint detection can do a set intersection without per-sink subtree walks.
fn collect_name_refs(node: &SyntaxNode) -> Box<[Box<str>]> {
    node.descendants()
        .filter(|n| n.kind() == SyntaxKind::NAME_REF)
        .map(|n| n.text().to_string().into_boxed_str())
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

// ---------------------------------------------------------------------------
// Binding method-call precomputation
// ---------------------------------------------------------------------------

/// Build per-binding `(stmt_index, method_name)` pairs for direct method calls.
///
/// A "direct method call" is `binding_name.method(...)` where the receiver
/// is a simple path expression matching the binding.
fn build_binding_method_calls(stmts: &[ast::Stmt]) -> BindingMethodIndex {
    let mut map: BTreeMap<Box<str>, Vec<(usize, Box<str>)>> = BTreeMap::new();
    for (i, stmt) in stmts.iter().enumerate() {
        for mc in stmt
            .syntax()
            .descendants()
            .filter_map(ast::MethodCallExpr::cast)
        {
            let entry = mc
                .receiver()
                .and_then(|recv| direct_path_name(&recv))
                .zip(mc.name_ref().map(|n| Box::from(n.text().as_str())));
            if let Some((binding, method)) = entry {
                map.entry(binding).or_default().push((i, method));
            }
        }
    }
    map.into_iter()
        .map(|(k, v)| (k, v.into_boxed_slice()))
        .collect()
}

/// Find the first direct method call on any binding in the tail expression.
fn build_binding_method_in_tail(tail: Option<&ast::Expr>) -> BTreeMap<Box<str>, Box<str>> {
    let Some(expr) = tail else {
        return BTreeMap::new();
    };
    let mut result = BTreeMap::new();
    for mc in expr
        .syntax()
        .descendants()
        .filter_map(ast::MethodCallExpr::cast)
    {
        let entry = mc
            .receiver()
            .and_then(|recv| direct_path_name(&recv))
            .zip(mc.name_ref().map(|n| Box::from(n.text().as_str())));
        if let Some((binding, method)) = entry {
            result.entry(binding).or_insert(method);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Match expression precomputation
// ---------------------------------------------------------------------------

/// Collect all match expressions from the statement list for use by
/// partial error handling detection.
fn build_match_exprs(stmt_list: &ast::StmtList) -> Box<[ast::MatchExpr]> {
    stmt_list
        .syntax()
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::MATCH_EXPR)
        .filter_map(ast::MatchExpr::cast)
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

// ---------------------------------------------------------------------------
// Lock acquisition precomputation
// ---------------------------------------------------------------------------

/// Lock acquisition method names on `Mutex` and `RwLock`.
const LOCK_METHODS: &[&str] = &["lock", "read", "write"];

/// Extract ordered lock acquisitions from the statement list.
fn build_lock_acquisitions(line_index: &LineIndex, stmts: &[ast::Stmt]) -> Box<[LockAcquisition]> {
    stmts
        .iter()
        .filter_map(|stmt| {
            let ast::Stmt::LetStmt(let_stmt) = stmt else {
                return None;
            };
            let init = let_stmt.initializer()?;
            let receiver_name = lock_receiver_name(&init)?;
            let guard_name = let_stmt.pat().and_then(|p| extract_binding_name(&p))?;
            let span = span_from_node(stmt.syntax(), line_index);
            Some(LockAcquisition {
                guard_name,
                receiver_name,
                span,
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Extract the receiver name from a lock acquisition within an expression.
///
/// For `m1.lock().unwrap()`, returns `"m1"`.
/// Returns `None` when the expression is a block (`{ let g = m.lock(); ... }`)
/// because locks inside block expressions are scoped.
pub(super) fn lock_receiver_name(expr: &ast::Expr) -> Option<Box<str>> {
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
        .find_map(|mc| extract_lock_receiver(&mc))
}

/// Returns `true` when `node` is nested inside a `BlockExpr` that is
/// a descendant of `root`.
fn is_inside_block_expr(node: &SyntaxNode, root: &SyntaxNode) -> bool {
    node.ancestors()
        .skip(1)
        .take_while(|a| a != root)
        .any(|a| ast::BlockExpr::can_cast(a.kind()))
}

/// Extract a simple binding name from a method call's receiver.
fn extract_lock_receiver(mc: &ast::MethodCallExpr) -> Option<Box<str>> {
    let recv = mc.receiver()?;
    let ast::Expr::PathExpr(pe) = &recv else {
        return None;
    };
    pe.path()?
        .segment()?
        .name_ref()
        .map(|n| Box::from(n.text().as_str()))
}

// ---------------------------------------------------------------------------
// Capability sink classification (shared with taint detection)
// ---------------------------------------------------------------------------

/// Known module segments that indicate a capability sink.
const SINK_MODULES: &[(&str, Capability)] = &[
    ("net", Capability::Network),
    ("process", Capability::ProcessExec),
];

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

/// Classify an associated function call by resolving the qualifier type's module.
///
/// Handles calls like `TcpStream::connect` where `resolve_call_to_function`
/// returns `None` but the qualifier resolves to an ADT in a known sink module.
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
