//! Precomputed per-function semantic state.

use super::analysis::CapabilitySink;
use super::analysis::{
    build_binding_method_calls, build_binding_method_in_tail, build_binding_refs_in_expr,
    build_binding_stmt_refs, build_body_derived_state, build_lock_acquisitions, build_match_exprs,
};
use super::file::{ParsedFile, span_from_node};
use super::prelude::*;

// ---------------------------------------------------------------------------
// FnContext — precomputed per-function analysis context
// ---------------------------------------------------------------------------

/// Per-binding method call index: binding name → sorted (stmt_index, method_name) pairs.
pub(super) type BindingMethodIndex = BTreeMap<Box<str>, Box<[(usize, Box<str>)]>>;

/// A resolved call site: callee name, argument hash, and source span.
pub(in crate::ir::semantic) struct CallSite {
    pub(in crate::ir::semantic) callee: Box<str>,
    pub(in crate::ir::semantic) args_hash: u64,
    pub(in crate::ir::semantic) span: IrSpan,
}

/// A lock acquisition: guard binding name, lock receiver name, source span.
pub(in crate::ir::semantic) struct LockAcquisition {
    pub(in crate::ir::semantic) guard_name: Box<str>,
    pub(in crate::ir::semantic) receiver_name: Box<str>,
    pub(in crate::ir::semantic) span: IrSpan,
}

/// Precomputed per-function analysis context.
///
/// Built once per function during `SemanticFileAnalysis` construction.
/// Holds shared AST handles and precomputed derived facts that all
/// detectors and the call-graph builder consume. One traversal of the
/// function body populates binding indices, call sites, loop ranges,
/// lock acquisitions, and function entry metadata.
pub(in crate::ir::semantic) struct FnContext<'a, 'db> {
    /// Collected statements (shared across all detectors).
    pub(in crate::ir::semantic) stmts: Box<[ast::Stmt]>,
    /// Tail expression, if any.
    pub(in crate::ir::semantic) tail_expr: Option<ast::Expr>,
    /// Whether the function is async.
    pub(in crate::ir::semantic) is_async: bool,
    /// Semantics handle for type resolution.
    pub(in crate::ir::semantic) sema: &'a Semantics<'db, RootDatabase>,
    /// Root database for name resolution.
    pub(in crate::ir::semantic) db: &'db RootDatabase,
    /// Line index for span computation.
    pub(in crate::ir::semantic) line_index: &'db LineIndex,

    // --- Binding indices ---
    /// Per-binding sorted statement indices where the name appears as a reference.
    pub(in crate::ir::semantic) binding_stmt_refs: BTreeMap<Box<str>, Box<[usize]>>,
    /// Binding names referenced in the tail expression.
    pub(in crate::ir::semantic) binding_in_tail: BTreeSet<Box<str>>,
    /// Binding names with mutation method calls or assignment operators.
    pub(in crate::ir::semantic) mutated_bindings: BTreeSet<Box<str>>,
    /// Binding names directly returned via tail or `return` statement.
    pub(in crate::ir::semantic) returned_bindings: BTreeSet<Box<str>>,
    /// Binding names passed as `&mut` references.
    pub(in crate::ir::semantic) mut_ref_bindings: BTreeSet<Box<str>>,

    // --- Call sites ---
    /// Resolved call sites in statement order. Used by repeated-call detection
    /// and fed into the file-level call graph.
    pub(in crate::ir::semantic) call_sites: Box<[CallSite]>,

    // --- Loop ranges ---
    /// Allocation calls found inside loop bodies. Pre-identified during build
    /// so the detector just emits findings.
    pub(in crate::ir::semantic) alloc_in_loop_spans: Box<[IrSpan]>,

    // --- Capability sinks ---
    /// Precomputed capability sink locations for taint analysis.
    pub(in crate::ir::semantic) capability_sinks: Box<[CapabilitySink]>,

    // --- Match expressions ---
    /// All match expressions found in the statement list, precomputed for
    /// partial error handling detection (avoids per-binding descendants walks).
    pub(in crate::ir::semantic) match_exprs: Box<[ast::MatchExpr]>,

    // --- Method-on-binding index ---
    /// Per-binding sorted `(stmt_index, method_name)` pairs for direct method
    /// calls. Used by redundant-collect detection to avoid forward-scanning.
    pub(in crate::ir::semantic) binding_method_calls: BindingMethodIndex,
    /// Method called on a binding in the tail expression, if any.
    pub(in crate::ir::semantic) binding_method_in_tail: BTreeMap<Box<str>, Box<str>>,

    // --- Lock acquisitions ---
    /// Ordered lock acquisitions for lock-across-await and lock-ordering.
    pub(in crate::ir::semantic) lock_acquisitions: Box<[LockAcquisition]>,

    // --- Function entry metadata ---
    /// Function name.
    pub(in crate::ir::semantic) fn_name: Box<str>,
    /// 1-based start line.
    pub(in crate::ir::semantic) start_line: usize,
    /// 1-based end line.
    pub(in crate::ir::semantic) end_line: usize,
    /// `true` when `pub`, `main`, or `#[test]`.
    pub(in crate::ir::semantic) is_entry_point: bool,
}

impl<'a, 'db> FnContext<'a, 'db> {
    /// Build a precomputed context from a parsed file and function node.
    ///
    /// Returns `None` when the function has no body, statement list, or name.
    pub(in crate::ir::semantic) fn build(
        pf: &'a ParsedFile<'db>,
        fn_node: &ast::Fn,
    ) -> Option<Self> {
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
    pub(in crate::ir::semantic) fn binding_used_after(
        &self,
        name: &str,
        after_index: usize,
    ) -> bool {
        self.binding_stmt_refs
            .get(name)
            .is_some_and(|indices| indices.partition_point(|&i| i <= after_index) < indices.len())
    }

    /// Check if `name` is referenced in the tail expression.
    pub(in crate::ir::semantic) fn binding_used_in_tail(&self, name: &str) -> bool {
        self.binding_in_tail.contains(name)
    }

    /// Check if `name` has any mutation method calls or assignments.
    pub(in crate::ir::semantic) fn binding_is_mutated(&self, name: &str) -> bool {
        self.mutated_bindings.contains(name)
    }

    /// Check if `name` is directly returned.
    pub(in crate::ir::semantic) fn binding_is_returned(&self, name: &str) -> bool {
        self.returned_bindings.contains(name)
    }

    /// Check if `name` is passed as `&mut`.
    pub(in crate::ir::semantic) fn binding_passed_as_mut_ref(&self, name: &str) -> bool {
        self.mut_ref_bindings.contains(name)
    }

    /// Check if any statement after `after_index` (or the tail) has an
    /// `iter()` or `into_iter()` call directly on `name`.
    pub(in crate::ir::semantic) fn next_use_is_iter(&self, name: &str, after_index: usize) -> bool {
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
    pub(in crate::ir::semantic) fn span(&self, node: &SyntaxNode) -> IrSpan {
        span_from_node(node, self.line_index)
    }

    /// Extend a mutable edge vec with `(caller, callee)` pairs from call sites.
    ///
    /// Takes a pre-allocated vec to extend rather than returning a new collection,
    /// avoiding intermediate allocation.
    pub(in crate::ir::semantic) fn extend_call_graph(&self, edges: &mut Vec<(Box<str>, Box<str>)>) {
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
    pub(in crate::ir::semantic) fn into_entry_data(
        self,
    ) -> (Box<str>, usize, usize, bool, Box<[LockAcquisition]>) {
        (
            self.fn_name,
            self.start_line,
            self.end_line,
            self.is_entry_point,
            self.lock_acquisitions,
        )
    }
}
