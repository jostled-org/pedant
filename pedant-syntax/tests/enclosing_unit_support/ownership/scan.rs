//! What one parsed source names, read in a single walk.
//!
//! Every ownership claim is a count over the same six questions: which
//! identifiers a source names, which functions it calls, which methods it calls,
//! which associated routes it takes, which fields it reads, and how many times
//! it propagates with `?`. One walk answers all six, so a subject is parsed once
//! rather than once per question.

use std::collections::BTreeMap;

use syn::visit::Visit;

/// What one parsed source names: identifiers, calls, method calls, associated
/// calls, field reads, and `?` propagations.
#[derive(Default)]
pub(super) struct SourceScan {
    idents: BTreeMap<Box<str>, usize>,
    calls: BTreeMap<Box<str>, usize>,
    method_calls: BTreeMap<Box<str>, usize>,
    /// Path calls keyed by their last two segments, `Owner::method`.
    associated: BTreeMap<Box<str>, usize>,
    fields: BTreeMap<Box<str>, usize>,
    pub(super) try_expressions: usize,
}

impl SourceScan {
    pub(super) fn of_file(file: &syn::File) -> Self {
        let mut scan = Self::default();
        scan.visit_file(file);
        scan
    }

    pub(super) fn of_block(block: &syn::Block) -> Self {
        let mut scan = Self::default();
        scan.visit_block(block);
        scan
    }

    pub(super) fn names(&self, ident: &str) -> bool {
        self.idents.contains_key(ident)
    }

    /// How many call expressions name `function` as their last path segment.
    pub(super) fn calls(&self, function: &str) -> usize {
        self.calls.get(function).copied().unwrap_or_default()
    }

    /// How many method calls name `method`.
    pub(super) fn method_calls(&self, method: &str) -> usize {
        self.method_calls.get(method).copied().unwrap_or_default()
    }

    /// How many ways a body reaches `name` at all: as a free call, and as a
    /// method call on some receiver.
    ///
    /// A claim about a route rather than about a spelling reads both, because
    /// `route(x)` and `x.route()` are the same reach.
    pub(super) fn reaches(&self, name: &str) -> usize {
        self.calls(name) + self.method_calls(name)
    }

    /// How many path calls name `route`, written `Owner::method`.
    pub(super) fn associated_calls(&self, route: &str) -> usize {
        self.associated.get(route).copied().unwrap_or_default()
    }

    /// How many `Type::new(...)` calls name `type_name`.
    pub(super) fn constructions(&self, type_name: &str) -> usize {
        self.associated_calls(&format!("{type_name}::new"))
    }

    pub(super) fn reads(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }

    /// Count one path call by its last segment, and again by the owner that
    /// segment hangs off when the path names one.
    fn record_path_call(&mut self, path: &syn::Path) {
        let mut segments = path.segments.iter().rev();
        let Some(last) = segments.next() else {
            return;
        };
        let name = last.ident.to_string();
        *self.calls.entry(name.as_str().into()).or_default() += 1;
        if let Some(owner) = segments.next() {
            *self
                .associated
                .entry(format!("{}::{name}", owner.ident).into_boxed_str())
                .or_default() += 1;
        }
    }
}

impl<'ast> Visit<'ast> for SourceScan {
    fn visit_ident(&mut self, node: &'ast proc_macro2::Ident) {
        *self
            .idents
            .entry(node.to_string().into_boxed_str())
            .or_default() += 1;
    }

    fn visit_member(&mut self, node: &'ast syn::Member) {
        if let syn::Member::Named(ident) = node {
            *self
                .fields
                .entry(ident.to_string().into_boxed_str())
                .or_default() += 1;
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(called) = node.func.as_ref() {
            self.record_path_call(&called.path);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        *self
            .method_calls
            .entry(node.method.to_string().into_boxed_str())
            .or_default() += 1;
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.try_expressions += 1;
        syn::visit::visit_expr_try(self, node);
    }
}

/// The free function one file declares under `name`.
pub(super) fn free_function<'file>(
    file: &'file syn::File,
    name: &str,
) -> Option<&'file syn::ItemFn> {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    })
}

/// The inherent method one file declares under `name`.
pub(super) fn impl_method<'file>(
    file: &'file syn::File,
    name: &str,
) -> Option<&'file syn::ImplItemFn> {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(block) => Some(block),
            _ => None,
        })
        .flat_map(|block| block.items.iter())
        .find_map(|member| match member {
            syn::ImplItem::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
}
