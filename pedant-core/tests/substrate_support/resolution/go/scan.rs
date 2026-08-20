//! What one parsed production source names, read in a single walk.
//!
//! An order claim cannot be made behaviorally: a ceiling checked after a push
//! and rolled back answers a caller exactly as one checked before it. So the
//! owner is parsed and its statements are compared, which needs three counts —
//! which routes a body takes, which of them it takes on a named field, and where
//! in the body each first appears.

use std::collections::BTreeMap;

use syn::visit::Visit;

/// The routes one parsed source takes.
#[derive(Default)]
pub struct SourceScan {
    calls: BTreeMap<Box<str>, usize>,
    method_calls: BTreeMap<Box<str>, usize>,
    /// Method calls whose receiver is a field, keyed `field.method`.
    field_calls: BTreeMap<Box<str>, usize>,
}

impl SourceScan {
    pub fn of_file(file: &syn::File) -> Self {
        let mut scan = Self::default();
        scan.visit_file(file);
        scan
    }

    fn of_statement(statement: &syn::Stmt) -> Self {
        let mut scan = Self::default();
        scan.visit_stmt(statement);
        scan
    }

    /// How many ways a body reaches `name`: as a free call and as a method call.
    ///
    /// A claim about a route rather than about a spelling reads both, because
    /// `route(x)` and `x.route()` are the same reach.
    pub fn reaches(&self, name: &str) -> usize {
        let free = self.calls.get(name).copied().unwrap_or_default();
        free + self.method_calls.get(name).copied().unwrap_or_default()
    }

    /// How many times a body calls `field.method`, written `field.method`.
    ///
    /// A retention claim is about one table, and `push` alone cannot tell the
    /// module table from the queue beside it.
    pub fn reaches_on_field(&self, route: &str) -> usize {
        self.field_calls.get(route).copied().unwrap_or_default()
    }

    fn record_path_call(&mut self, path: &syn::Path) {
        if let Some(last) = path.segments.last() {
            *self
                .calls
                .entry(last.ident.to_string().into_boxed_str())
                .or_default() += 1;
        }
    }
}

impl<'ast> Visit<'ast> for SourceScan {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(called) = node.func.as_ref() {
            self.record_path_call(&called.path);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        *self.method_calls.entry(method.as_str().into()).or_default() += 1;
        if let syn::Expr::Field(field) = node.receiver.as_ref()
            && let syn::Member::Named(name) = &field.member
        {
            *self
                .field_calls
                .entry(format!("{name}.{method}").into_boxed_str())
                .or_default() += 1;
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

/// The index of the first statement in `block` that reaches `token`.
pub fn statement_naming(block: &syn::Block, token: &str) -> Option<usize> {
    block
        .stmts
        .iter()
        .position(|statement| SourceScan::of_statement(statement).reaches(token) > 0)
}

/// The index of the first statement in `block` that calls `field.method`.
pub fn statement_naming_field(block: &syn::Block, route: &str) -> Option<usize> {
    block
        .stmts
        .iter()
        .position(|statement| SourceScan::of_statement(statement).reaches_on_field(route) > 0)
}

/// The inherent method one file declares under `name`.
pub fn impl_method<'file>(file: &'file syn::File, name: &str) -> Option<&'file syn::ImplItemFn> {
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
