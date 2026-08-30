//! What one parsed source names, read in a single walk.
//!
//! Every ownership claim is a count over the same six questions: which
//! identifiers a source names, which functions it calls, which methods it calls,
//! which associated routes it takes, which fields it reads, and how many times
//! it propagates with `?`. One walk answers all six, so a subject is parsed once
//! rather than once per question.

use std::collections::BTreeMap;

use syn::visit::Visit;

#[cfg(feature = "ts-go")]
use super::closure::Member;

/// The tree-sitter route that moves a cursor one level deeper.
///
/// Shared by the two ceiling claims beside each other, which read the same route
/// out of two walks. Two copies were two chances for one of them to be renamed
/// with the walk it names and leave the other claim reading a route nothing
/// takes — which passes.
#[cfg(feature = "ts-go")]
pub(super) const DESCENT_ROUTE: &str = "goto_first_child";

/// The route that retains one record, shared for the same reason.
#[cfg(feature = "ts-go")]
pub(super) const INSERTION_ROUTE: &str = "push";

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
    /// String literals, which is how a grammar node kind is written down.
    literals: BTreeMap<Box<str>, usize>,
    /// Integer literals, which is how a ceiling that was chosen rather than
    /// measured is written down.
    #[cfg(feature = "ts-go")]
    integers: BTreeMap<Box<str>, usize>,
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

    /// One statement of a body, so a claim can compare where two routes sit.
    #[cfg(feature = "ts-go")]
    pub(super) fn of_statement(statement: &syn::Stmt) -> Self {
        let mut scan = Self::default();
        scan.visit_stmt(statement);
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

    /// Whether a source writes `literal` down.
    ///
    /// A grammar node kind is a string, so a claim about who may recognize a
    /// language reads literals rather than identifiers.
    pub(super) fn quotes(&self, literal: &str) -> bool {
        self.literals.contains_key(literal)
    }

    /// Every integer one source writes down, in the digits it wrote.
    ///
    /// A measured ceiling states no number of its own: the one it hands a walk
    /// is read from the source it bounds. So a claim that nothing here chose a
    /// ceiling reads the numbers the owner wrote rather than the route it took
    /// to answer with one.
    #[cfg(feature = "ts-go")]
    pub(super) fn integers(&self) -> Box<[&str]> {
        self.integers.keys().map(|digits| digits.as_ref()).collect()
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

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        *self
            .literals
            .entry(node.value().into_boxed_str())
            .or_default() += 1;
    }

    #[cfg(feature = "ts-go")]
    fn visit_lit_int(&mut self, node: &'ast syn::LitInt) {
        *self
            .integers
            .entry(node.base10_digits().into())
            .or_default() += 1;
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.try_expressions += 1;
        syn::visit::visit_expr_try(self, node);
    }
}

/// The index of the first statement in `block` that reaches `token`.
///
/// A claim about order rather than about presence: two routes counted in the
/// same body prove nothing about which of them ran first, and only a body whose
/// statements are compared can state that the check dominates the spend.
#[cfg(feature = "ts-go")]
pub(super) fn statement_naming(block: &syn::Block, token: &str) -> Option<usize> {
    block
        .stmts
        .iter()
        .position(|statement| SourceScan::of_statement(statement).reaches(token) > 0)
}

/// The statement that checks a ceiling precedes the statement that spends it.
///
/// Both walks make the same claim about their own ceilings, so both ask it
/// here: `owner` names the module and the function being read, and the body is
/// required to reach each token exactly once, so a second unchecked site cannot
/// hide behind the one this reads.
#[cfg(feature = "ts-go")]
pub(super) fn assert_check_precedes(
    block: &syn::Block,
    owner: (&str, &str),
    check: &str,
    route: &str,
) {
    let (module, name) = owner;
    let scan = SourceScan::of_block(block);
    assert_eq!(
        scan.reaches(check),
        1,
        "`{name}` in {module} must reach `{check}` exactly once"
    );
    assert_eq!(
        scan.reaches(route),
        1,
        "`{name}` in {module} must reach `{route}` exactly once"
    );

    let checked = statement_naming(block, check)
        .unwrap_or_else(|| panic!("`{name}` in {module} should state `{check}` as a statement"));
    let spent = statement_naming(block, route)
        .unwrap_or_else(|| panic!("`{name}` in {module} should state `{route}` as a statement"));
    assert!(
        checked < spent,
        "`{name}` in {module} must check with `{check}` (statement {checked}) before reaching `{route}` (statement {spent})"
    );
}

/// Exactly the named modules of one owner family may take `route`.
///
/// Both walks make the same claim about their own routes, so both ask it here:
/// `members` is the family the claim is about, and the labels that reach `route`
/// are compared to `owners` in order, so a module that gained the route and one
/// that lost it both fail with the same difference.
#[cfg(feature = "ts-go")]
pub(super) fn assert_single_owner(members: &[&Member], route: &str, owners: &[&str]) {
    let naming: Box<[&str]> = members
        .iter()
        .filter(|member| member.scan.reaches(route) > 0)
        .map(|member| member.label.as_ref())
        .collect();
    assert_eq!(&*naming, owners, "only {owners:?} may reach `{route}`");
}

/// The free function one file declares under `name`, or a failure naming both.
///
/// Every claim in this tree reads a named owner out of a parsed module and has
/// no answer without it, so the absence is a broken claim rather than a result
/// to handle. Stated once here: written out beside each lookup it was the same
/// sentence eight times, each free to word its own failure differently.
pub(super) fn owner<'file>(file: &'file syn::File, name: &str, module: &str) -> &'file syn::ItemFn {
    free_function(file, name).unwrap_or_else(|| panic!("{module} should declare `{name}`"))
}

/// The same, for the inherent method one file declares under `name`.
pub(super) fn method_owner<'file>(
    file: &'file syn::File,
    name: &str,
    module: &str,
) -> &'file syn::ImplItemFn {
    impl_method(file, name).unwrap_or_else(|| panic!("{module} should declare `{name}`"))
}

/// The free function one file declares under `name`.
fn free_function<'file>(file: &'file syn::File, name: &str) -> Option<&'file syn::ItemFn> {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    })
}

/// The inherent method one file declares under `name`.
fn impl_method<'file>(file: &'file syn::File, name: &str) -> Option<&'file syn::ImplItemFn> {
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
