//! Per-function classification state.
//!
//! Tracks which bindings inside the function body under traversal are
//! reference-counted, which are growable strings, and which types its body
//! mentions. Function bodies nest (items may be declared inside a `fn`), so the
//! state is saved and restored around each nested body via [`FnScope::enter`]
//! and [`FnScope::leave`].

use std::collections::BTreeSet;
use std::sync::Arc;

use syn::{Expr, FnArg, Signature, Type};

use crate::graph::extend_pairwise_edges;
use crate::ir::type_introspection::{
    contains_refcounted_type, for_each_pat_ident, is_refcounted_type, is_string_type,
    iter_expr_ident,
};

use super::syn_helpers::typed_ident_from_pat;

/// Saved per-function state for nested function handling.
pub(super) struct FnSavedState {
    fn_index: Option<usize>,
    refcounted_bindings: BTreeSet<Box<str>>,
    refcounted_containers: BTreeSet<Box<str>>,
    string_bindings: BTreeSet<Box<str>>,
    body_types: BTreeSet<Arc<str>>,
}

/// Classification sets for the function body currently being traversed.
pub(super) struct FnScope {
    /// Index into the extractor's function list, or `None` outside any body.
    current: Option<usize>,
    refcounted_bindings: BTreeSet<Box<str>>,
    refcounted_containers: BTreeSet<Box<str>>,
    string_bindings: BTreeSet<Box<str>>,
    body_types: BTreeSet<Arc<str>>,
    /// Scratch buffer for edge computation, reused across function bodies.
    body_type_names_buf: Vec<Arc<str>>,
}

impl FnScope {
    pub(super) fn new() -> Self {
        Self {
            current: None,
            refcounted_bindings: BTreeSet::new(),
            refcounted_containers: BTreeSet::new(),
            string_bindings: BTreeSet::new(),
            body_types: BTreeSet::new(),
            body_type_names_buf: Vec::new(),
        }
    }

    /// Index of the function body being traversed, if any.
    pub(super) fn current(&self) -> Option<usize> {
        self.current
    }

    /// Begin a fresh scope for `fn_index`, handing back the outer scope's state.
    pub(super) fn enter(&mut self, fn_index: usize) -> FnSavedState {
        let saved = FnSavedState {
            fn_index: self.current,
            refcounted_bindings: std::mem::take(&mut self.refcounted_bindings),
            refcounted_containers: std::mem::take(&mut self.refcounted_containers),
            string_bindings: std::mem::take(&mut self.string_bindings),
            body_types: std::mem::take(&mut self.body_types),
        };
        self.current = Some(fn_index);
        saved
    }

    /// Restore the outer scope captured by [`FnScope::enter`].
    pub(super) fn leave(&mut self, saved: FnSavedState) {
        self.current = saved.fn_index;
        self.refcounted_bindings = saved.refcounted_bindings;
        self.refcounted_containers = saved.refcounted_containers;
        self.string_bindings = saved.string_bindings;
        self.body_types = saved.body_types;
    }

    /// `true` when `name` was classified as a reference-counted binding.
    pub(super) fn is_refcounted(&self, name: &str) -> bool {
        self.refcounted_bindings.contains(name)
    }

    pub(super) fn record_refcounted_params(&mut self, sig: &Signature) {
        for input in &sig.inputs {
            let FnArg::Typed(pt) = input else { continue };
            let syn::Pat::Ident(pi) = pt.pat.as_ref() else {
                continue;
            };
            self.classify_refcounted_ident(&pi.ident, &pt.ty);
        }
    }

    /// Sort `ident` into the refcounted set (`Arc<T>`) or the container set
    /// (`Vec<Arc<T>>` and friends, whose elements are refcounted).
    fn classify_refcounted_ident(&mut self, ident: &syn::Ident, ty: &Type) {
        match (is_refcounted_type(ty), contains_refcounted_type(ty)) {
            (true, _) => {
                self.refcounted_bindings
                    .insert(ident.to_string().into_boxed_str());
            }
            (false, true) => {
                self.refcounted_containers
                    .insert(ident.to_string().into_boxed_str());
            }
            _ => {}
        }
    }

    pub(super) fn record_refcounted_from_pat(&mut self, pat: &syn::Pat) {
        let Some((ident, ty)) = typed_ident_from_pat(pat) else {
            return;
        };
        self.classify_refcounted_ident(ident, ty);
    }

    pub(super) fn record_string_binding(&mut self, pat: &syn::Pat) {
        let Some((ident, ty)) = typed_ident_from_pat(pat) else {
            return;
        };
        if !is_string_type(ty) {
            return;
        }
        self.string_bindings
            .insert(ident.to_string().into_boxed_str());
    }

    /// Iterating a refcounted container yields refcounted bindings.
    pub(super) fn record_refcounted_loop_bindings(&mut self, pat: &syn::Pat, iter_expr: &Expr) {
        let Some(ident) = iter_expr_ident(iter_expr) else {
            return;
        };
        if !self.refcounted_containers.iter().any(|s| ident == &**s) {
            return;
        }
        for_each_pat_ident(pat, &mut |name| {
            self.refcounted_bindings.insert(name);
        });
    }

    /// `true` when `expr` is `write!`/`writeln!` targeting a tracked `String`.
    pub(super) fn is_write_macro_to_string(&self, expr: &Expr) -> bool {
        let Expr::Macro(expr_macro) = expr else {
            return false;
        };
        let is_write = expr_macro
            .mac
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "write" || s.ident == "writeln");
        if !is_write {
            return false;
        }
        let tokens = &expr_macro.mac.tokens;
        let first_ident = tokens.clone().into_iter().next();
        match first_ident {
            Some(proc_macro2::TokenTree::Ident(ident)) => {
                self.string_bindings.iter().any(|s| ident == **s)
            }
            _ => false,
        }
    }

    /// Record the last segment of `path` as a type this body mentions.
    pub(super) fn collect_body_type(&mut self, path: &syn::Path) {
        if self.current.is_none() {
            return;
        }
        let Some(seg) = path.segments.last() else {
            return;
        };
        let ident_str = seg.ident.to_string();
        if self.body_types.contains(ident_str.as_str()) {
            return;
        }
        self.body_types.insert(Arc::from(ident_str));
    }

    /// Pairwise edges between every type mentioned in this body, for
    /// mixed-concerns analysis.
    pub(super) fn body_type_edges(&mut self) -> Box<[(Arc<str>, Arc<str>)]> {
        self.body_type_names_buf.clear();
        self.body_type_names_buf
            .extend(self.body_types.iter().cloned());
        let mut edges = Vec::new();
        extend_pairwise_edges(&self.body_type_names_buf, &mut edges);
        edges.into_boxed_slice()
    }
}
