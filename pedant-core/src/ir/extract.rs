use std::collections::BTreeSet;
use std::fmt::Write;
use std::rc::Rc;
use std::sync::Arc;

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ExprIf, FnArg, ReturnType, Signature, Type};

use super::type_introspection::{
    classify_type_ref, collect_signature_type_names_into, collect_type_names_into,
    contains_refcounted_type, first_pat_ident, first_type_name, for_each_pat_ident,
    get_type_span_start, is_refcounted_type, is_string_type, iter_expr_ident,
};
use crate::graph::{extend_edges_from_names, extend_pairwise_edges};
use crate::pattern::{
    extract_attribute_text, extract_macro_text, extract_method_call_text, extract_type_text,
};

use super::facts::{
    AttributeFact, BindingFact, BranchContext, ControlFlowFact, ControlFlowKind, ElseInfo,
    ExternBlockFact, FileIr, FnFact, ImplFact, IrSpan, MacroFact, MethodCallFact, ModuleFact,
    ParamFact, StringLitFact, TypeDefFact, TypeDefKind, TypeInfo, TypeRefContext, TypeRefFact,
    UnsafeFact, UnsafeKind, UsePathFact,
};

/// Single-pass AST visitor that populates a [`FileIr`] from a parsed source file.
///
/// When `semantic` is `Some`, a second enrichment pass resolves type aliases
/// and marks `Copy` receivers.
pub fn extract(
    file_path: &str,
    syntax: &syn::File,
    semantic: Option<&super::semantic::SemanticContext>,
) -> FileIr {
    let mut extractor = IrExtractor::new(file_path);
    extractor.visit_file(syntax);
    #[cfg(feature = "semantic")]
    {
        let mut ir = extractor.finalize();
        if let Some(ctx) = semantic {
            enrich_ir(&mut ir, ctx);
        }
        ir
    }
    #[cfg(not(feature = "semantic"))]
    {
        _ = semantic;
        extractor.finalize()
    }
}

/// Check if an attribute is `#[cfg(test)]` without allocating.
fn is_cfg_test_attr(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("cfg")
        && attr.meta.require_list().ok().is_some_and(|list| {
            let mut iter = list.tokens.clone().into_iter();
            let first = iter.next();
            matches!(
                (&first, iter.next()),
                (Some(proc_macro2::TokenTree::Ident(ident)), None) if ident == "test"
            )
        })
}

/// Saved per-function state for nested function handling.
struct FnSavedState {
    fn_index: Option<usize>,
    refcounted_bindings: BTreeSet<Box<str>>,
    refcounted_containers: BTreeSet<Box<str>>,
    string_bindings: BTreeSet<Box<str>>,
    fn_body_types: BTreeSet<Rc<str>>,
}

struct IrExtractor {
    file_path: Arc<str>,
    functions: Vec<FnFact>,
    type_defs: Vec<TypeDefFact>,
    impl_blocks: Vec<ImplFact>,
    use_paths: Vec<UsePathFact>,
    control_flow: Vec<ControlFlowFact>,
    bindings: Vec<BindingFact>,
    type_refs: Vec<TypeRefFact>,
    method_calls: Vec<MethodCallFact>,
    macro_invocations: Vec<MacroFact>,
    attributes: Vec<AttributeFact>,
    string_literals: Vec<StringLitFact>,
    unsafe_sites: Vec<UnsafeFact>,
    extern_blocks: Vec<ExternBlockFact>,
    modules: Vec<ModuleFact>,

    // Traversal state
    depth: usize,
    loop_depth: usize,
    branch_context: Option<BranchContext>,
    item_depth: usize,

    // Suppresses Body-context emission inside signature/field type visits
    in_non_body_type: bool,

    // Per-function state
    current_fn: Option<usize>,
    refcounted_bindings: BTreeSet<Box<str>>,
    refcounted_containers: BTreeSet<Box<str>>,
    string_bindings: BTreeSet<Box<str>>,
    fn_body_types: BTreeSet<Rc<str>>,

    // Dedup set for use paths (O(log n) lookup instead of O(n) linear scan)
    use_path_set: BTreeSet<Box<str>>,

    // Scratch buffer for body type edge computation (reused across function bodies)
    body_type_names_buf: Vec<Rc<str>>,

    // Scratch buffer for path building (reused across use-items and expr-paths)
    path_buf: String,
}

impl IrExtractor {
    fn new(file_path: &str) -> Self {
        Self {
            file_path: Arc::from(file_path),
            functions: Vec::new(),
            type_defs: Vec::new(),
            impl_blocks: Vec::new(),
            use_paths: Vec::new(),
            control_flow: Vec::new(),
            bindings: Vec::new(),
            type_refs: Vec::new(),
            method_calls: Vec::new(),
            macro_invocations: Vec::new(),
            attributes: Vec::new(),
            string_literals: Vec::new(),
            unsafe_sites: Vec::new(),
            extern_blocks: Vec::new(),
            modules: Vec::new(),
            depth: 0,
            loop_depth: 0,
            branch_context: None,
            item_depth: 0,
            in_non_body_type: false,
            current_fn: None,
            refcounted_bindings: BTreeSet::new(),
            refcounted_containers: BTreeSet::new(),
            string_bindings: BTreeSet::new(),
            fn_body_types: BTreeSet::new(),
            use_path_set: BTreeSet::new(),
            body_type_names_buf: Vec::new(),
            path_buf: String::new(),
        }
    }

    fn finalize(self) -> FileIr {
        FileIr {
            file_path: self.file_path,
            functions: self.functions.into_boxed_slice(),
            type_defs: self.type_defs.into_boxed_slice(),
            impl_blocks: self.impl_blocks.into_boxed_slice(),
            use_paths: self.use_paths.into_boxed_slice(),
            control_flow: self.control_flow.into_boxed_slice(),
            bindings: self.bindings.into_boxed_slice(),
            type_refs: self.type_refs.into_boxed_slice(),
            method_calls: self.method_calls.into_boxed_slice(),
            macro_invocations: self.macro_invocations.into_boxed_slice(),
            attributes: self.attributes.into_boxed_slice(),
            string_literals: self.string_literals.into_boxed_slice(),
            unsafe_sites: self.unsafe_sites.into_boxed_slice(),
            extern_blocks: self.extern_blocks.into_boxed_slice(),
            modules: self.modules.into_boxed_slice(),
            data_flows: Box::new([]),
        }
    }

    fn span_from(lc: proc_macro2::LineColumn) -> IrSpan {
        IrSpan {
            line: lc.line,
            column: lc.column,
        }
    }

    fn save_fn_state(&mut self) -> FnSavedState {
        FnSavedState {
            fn_index: self.current_fn,
            refcounted_bindings: std::mem::take(&mut self.refcounted_bindings),
            refcounted_containers: std::mem::take(&mut self.refcounted_containers),
            string_bindings: std::mem::take(&mut self.string_bindings),
            fn_body_types: std::mem::take(&mut self.fn_body_types),
        }
    }

    fn restore_fn_state(&mut self, state: FnSavedState) {
        self.current_fn = state.fn_index;
        self.refcounted_bindings = state.refcounted_bindings;
        self.refcounted_containers = state.refcounted_containers;
        self.string_bindings = state.string_bindings;
        self.fn_body_types = state.fn_body_types;
    }

    fn reset_fn_state(&mut self, fn_index: usize) {
        self.refcounted_bindings.clear();
        self.refcounted_containers.clear();
        self.string_bindings.clear();
        self.fn_body_types.clear();
        self.current_fn = Some(fn_index);
    }

    fn push_fn(&mut self, sig: &Signature) -> usize {
        let name: Box<str> = sig.ident.to_string().into_boxed_str();
        let span = Self::span_from(sig.ident.span().start());
        let is_unsafe = sig.unsafety.is_some();

        let params: Box<[ParamFact]> = sig
            .inputs
            .iter()
            .filter_map(|input| match input {
                FnArg::Typed(pt) => {
                    let type_text = extract_type_text(&pt.ty);
                    first_pat_ident(&pt.pat).map(|name| ParamFact { name, type_text })
                }
                FnArg::Receiver(_) => None,
            })
            .collect();

        let return_type = match &sig.output {
            ReturnType::Type(_, ty) => {
                let text = extract_type_text(ty);
                let flags = classify_type_ref(ty);
                Some(TypeInfo {
                    text,
                    involves_dyn: flags.involves_dyn,
                })
            }
            ReturnType::Default => None,
        };

        let mut sig_type_names = Vec::new();
        collect_signature_type_names_into(sig, &mut sig_type_names);
        let signature_type_names: Box<[Rc<str>]> = sig_type_names.into();
        let item_depth = self.item_depth;

        let index = self.functions.len();
        self.functions.push(FnFact {
            name,
            span,
            is_unsafe,
            params,
            return_type,
            signature_type_names,
            item_depth,
            has_arithmetic: false,
            body_type_edges: Box::default(),
        });
        index
    }

    fn record_refcounted_params(&mut self, sig: &Signature) {
        for input in &sig.inputs {
            let FnArg::Typed(pt) = input else { continue };
            let syn::Pat::Ident(pi) = pt.pat.as_ref() else {
                continue;
            };
            self.classify_refcounted_ident(&pi.ident, &pt.ty);
        }
    }

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

    /// Visit binding identifiers with their spans and optional type annotation spans.
    fn for_each_pat_ident_span(
        pat: &syn::Pat,
        type_span: Option<IrSpan>,
        f: &mut impl FnMut(Box<str>, IrSpan, Option<IrSpan>),
    ) {
        match pat {
            syn::Pat::Ident(pi) => {
                let name: Box<str> = pi.ident.to_string().into_boxed_str();
                let span = Self::span_from(pi.ident.span().start());
                f(name, span, type_span);
            }
            syn::Pat::Type(pt) => {
                let ty_span = Self::span_from(get_type_span_start(&pt.ty));
                Self::for_each_pat_ident_span(&pt.pat, Some(ty_span), f);
            }
            syn::Pat::Tuple(pt) => {
                for inner_pat in &pt.elems {
                    Self::for_each_pat_ident_span(inner_pat, None, f);
                }
            }
            syn::Pat::TupleStruct(pts) => {
                for field_pat in &pts.elems {
                    Self::for_each_pat_ident_span(field_pat, None, f);
                }
            }
            syn::Pat::Struct(ps) => {
                for field in &ps.fields {
                    Self::for_each_pat_ident_span(&field.pat, None, f);
                }
            }
            syn::Pat::Slice(psl) => {
                for slice_pat in &psl.elems {
                    Self::for_each_pat_ident_span(slice_pat, None, f);
                }
            }
            syn::Pat::Or(po) => {
                for case in &po.cases {
                    Self::for_each_pat_ident_span(case, None, f);
                }
            }
            syn::Pat::Reference(pr) => Self::for_each_pat_ident_span(&pr.pat, type_span, f),
            _ => {}
        }
    }

    fn typed_ident_from_pat(pat: &syn::Pat) -> Option<(&syn::Ident, &Type)> {
        let syn::Pat::Type(pt) = pat else { return None };
        let syn::Pat::Ident(pi) = pt.pat.as_ref() else {
            return None;
        };
        Some((&pi.ident, &pt.ty))
    }

    fn record_refcounted_from_pat(&mut self, pat: &syn::Pat) {
        let Some((ident, ty)) = Self::typed_ident_from_pat(pat) else {
            return;
        };
        self.classify_refcounted_ident(ident, ty);
    }

    fn record_string_binding(&mut self, pat: &syn::Pat) {
        let Some((ident, ty)) = Self::typed_ident_from_pat(pat) else {
            return;
        };
        if !is_string_type(ty) {
            return;
        }
        self.string_bindings
            .insert(ident.to_string().into_boxed_str());
    }

    fn record_refcounted_loop_bindings(&mut self, pat: &syn::Pat, iter_expr: &Expr) {
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

    fn is_write_macro_to_string(&self, expr: &Expr) -> bool {
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

    fn collect_body_type_from_path(&mut self, path: &syn::Path) {
        if self.current_fn.is_none() || self.item_depth == 0 {
            return;
        }
        let Some(seg) = path.segments.last() else {
            return;
        };
        let ident_str = seg.ident.to_string();
        if self.fn_body_types.contains(ident_str.as_str()) {
            return;
        }
        self.fn_body_types.insert(Rc::from(ident_str));
    }

    fn collect_body_type_from_type(&mut self, ty: &Type) {
        if let Type::Path(tp) = ty {
            self.collect_body_type_from_path(&tp.path);
        }
    }

    fn emit_multi_segment_path(&mut self, path: &syn::Path) {
        if path.segments.len() <= 1 {
            return;
        }
        self.path_buf.clear();
        push_segment(&mut self.path_buf, &path.segments[0].ident);
        for seg in path.segments.iter().skip(1) {
            write!(self.path_buf, "{PATH_SEPARATOR}{}", seg.ident).ok();
        }

        let span = path.segments.first().map_or_else(
            || {
                path.leading_colon
                    .map_or(proc_macro2::Span::call_site(), |c| c.spans[0])
            },
            |s| s.ident.span(),
        );

        let path_str = self.path_buf.as_str();
        if self.use_path_set.contains(path_str) {
            return;
        }
        self.use_path_set.insert(Box::from(path_str));
        self.use_paths.push(UsePathFact {
            path: Box::from(path_str),
            span: Self::span_from(span.start()),
        });
    }

    fn fn_body_type_edges(&mut self) -> Box<[(Rc<str>, Rc<str>)]> {
        self.body_type_names_buf.clear();
        self.body_type_names_buf
            .extend(self.fn_body_types.iter().cloned());
        let mut edges = Vec::new();
        extend_pairwise_edges(&self.body_type_names_buf, &mut edges);
        edges.into_boxed_slice()
    }

    fn count_else_chain(expr: &ExprIf) -> usize {
        let mut count = 1;
        let mut current = expr;
        while let Some(ref else_branch) = current.else_branch {
            match else_branch.1.as_ref() {
                Expr::If(next_if) => {
                    count += 1;
                    current = next_if;
                }
                Expr::Block(_) => {
                    count += 1;
                    break;
                }
                _ => break,
            }
        }
        count
    }

    fn visit_fn_body(
        &mut self,
        sig: &Signature,
        increment_depth: bool,
        visit: impl FnOnce(&mut Self),
    ) {
        let fn_index = self.push_fn(sig);

        // Emit type refs for signature
        self.emit_signature_type_refs(sig, fn_index);

        let saved = self.save_fn_state();
        self.reset_fn_state(fn_index);

        let binding_start = self.bindings.len();

        // Record param bindings for naming
        self.record_fn_param_bindings(sig);
        self.record_refcounted_params(sig);

        if increment_depth {
            self.item_depth += 1;
        }

        visit(self);

        // Store body type edges for mixed-concerns analysis
        if self.item_depth == 1 {
            self.functions[fn_index].body_type_edges = self.fn_body_type_edges();
        }

        // Post-process bindings: set is_refcounted from the per-function tracking sets
        for binding in &mut self.bindings[binding_start..] {
            if binding.is_wildcard {
                continue;
            }
            binding.is_refcounted = self.refcounted_bindings.contains(&binding.name);
        }

        if increment_depth {
            self.item_depth -= 1;
        }

        self.restore_fn_state(saved);
    }

    fn record_fn_param_bindings(&mut self, sig: &Signature) {
        for input in &sig.inputs {
            match input {
                FnArg::Typed(pt) => {
                    for_each_pat_ident(&pt.pat, &mut |name| {
                        self.push_binding_fact(name, None, false, false, false, None);
                    });
                }
                FnArg::Receiver(_) => {}
            }
        }
    }

    fn push_binding_fact(
        &mut self,
        name: Box<str>,
        span: Option<IrSpan>,
        is_wildcard: bool,
        has_init: bool,
        init_is_write_macro: bool,
        type_annotation_span: Option<IrSpan>,
    ) {
        self.bindings.push(BindingFact {
            name,
            span,
            loop_depth: self.loop_depth,
            is_refcounted: false,
            is_wildcard,
            has_init,
            init_is_write_macro,
            containing_fn: self.current_fn,
            type_annotation_span,
            resolved_type: None,
        });
    }

    fn push_type_ref(&mut self, ty: &Type, context: TypeRefContext, containing_fn: Option<usize>) {
        let span = Self::span_from(get_type_span_start(ty));
        let flags = classify_type_ref(ty);
        self.type_refs.push(TypeRefFact {
            text: extract_type_text(ty),
            span,
            involves_dyn: flags.involves_dyn,
            is_vec_box_dyn: flags.is_vec_box_dyn,
            is_default_hasher: flags.is_default_hasher,
            containing_fn,
            context,
        });
    }

    fn emit_signature_type_refs(&mut self, sig: &Signature, fn_index: usize) {
        if let ReturnType::Type(_, ty) = &sig.output {
            self.push_type_ref(ty, TypeRefContext::Return, Some(fn_index));
        }
        for input in &sig.inputs {
            let FnArg::Typed(pt) = input else { continue };
            self.push_type_ref(&pt.ty, TypeRefContext::Param, Some(fn_index));
        }
    }

    fn record_unsafe_fn(&mut self, sig: &Signature) {
        if let Some(token) = sig.unsafety {
            self.unsafe_sites.push(UnsafeFact {
                kind: UnsafeKind::Fn,
                span: Self::span_from(token.span.start()),
                evidence: "unsafe fn".into(),
            });
        }
    }

    fn register_type_with_edges(
        &mut self,
        name: Rc<str>,
        kind: TypeDefKind,
        span: IrSpan,
        edges: Box<[(Rc<str>, Rc<str>)]>,
    ) {
        self.type_defs.push(TypeDefFact {
            name,
            span,
            kind,
            edges,
        });
    }

    /// Shared scaffolding for type-def visitors: extract name/span from ident,
    /// compute edges via the provided closure, register the type def, and wrap
    /// the syn visit dispatch in item_depth guards.
    fn visit_type_def(
        &mut self,
        ident: &syn::Ident,
        kind: TypeDefKind,
        compute_edges: impl FnOnce(&Rc<str>) -> Box<[(Rc<str>, Rc<str>)]>,
        visit: impl FnOnce(&mut Self),
    ) {
        let name: Rc<str> = Rc::from(ident.to_string());
        let span = Self::span_from(ident.span().start());
        let edges = compute_edges(&name);
        self.register_type_with_edges(name, kind, span, edges);
        self.item_depth += 1;
        visit(self);
        self.item_depth -= 1;
    }

    /// Shared scaffolding for loop visitors: increment depth + loop_depth,
    /// push a control flow fact, run the body callback, then decrement.
    fn visit_loop_body(
        &mut self,
        kind: ControlFlowKind,
        span: IrSpan,
        body: impl FnOnce(&mut Self),
    ) {
        self.depth += 1;
        self.loop_depth += 1;

        self.control_flow.push(ControlFlowFact {
            kind,
            span,
            depth: self.depth,
            loop_depth: self.loop_depth,
            parent_branch: self.branch_context,
            else_info: None,
        });

        body(self);
        self.loop_depth -= 1;
        self.depth -= 1;
    }
}

use super::PATH_SEPARATOR;

const MAX_USE_TREE_DEPTH: usize = 32;

fn push_segment(buf: &mut String, ident: &impl std::fmt::Display) {
    match buf.is_empty() {
        true => {
            write!(buf, "{ident}").ok();
        }
        false => {
            write!(buf, "{PATH_SEPARATOR}{ident}").ok();
        }
    }
}

fn walk_use_tree(
    tree: &syn::UseTree,
    buf: &mut String,
    depth: usize,
    paths: &mut Vec<UsePathFact>,
    span: IrSpan,
) {
    if depth > MAX_USE_TREE_DEPTH {
        return;
    }
    let restore_len = buf.len();
    match tree {
        syn::UseTree::Path(syn::UsePath { ident, tree, .. }) => {
            push_segment(buf, ident);
            walk_use_tree(tree, buf, depth + 1, paths, span);
        }
        syn::UseTree::Name(syn::UseName { ident, .. }) => {
            push_segment(buf, ident);
            paths.push(UsePathFact {
                path: Box::from(buf.as_str()),
                span,
            });
        }
        syn::UseTree::Rename(syn::UseRename { ident, .. }) => {
            push_segment(buf, ident);
            paths.push(UsePathFact {
                path: Box::from(buf.as_str()),
                span,
            });
        }
        syn::UseTree::Glob(_) => {
            paths.push(UsePathFact {
                path: Box::from(&buf[..restore_len]),
                span,
            });
        }
        syn::UseTree::Group(syn::UseGroup { items, .. }) => {
            for item in items {
                walk_use_tree(item, buf, depth + 1, paths, span);
            }
        }
    }
    buf.truncate(restore_len);
}

impl<'ast> Visit<'ast> for IrExtractor {
    fn visit_signature(&mut self, node: &'ast Signature) {
        self.in_non_body_type = true;
        syn::visit::visit_signature(self, node);
        self.in_non_body_type = false;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.record_unsafe_fn(&node.sig);
        self.visit_fn_body(&node.sig, true, |this| {
            syn::visit::visit_item_fn(this, node);
        });
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.record_unsafe_fn(&node.sig);
        self.visit_fn_body(&node.sig, false, |this| {
            syn::visit::visit_impl_item_fn(this, node);
        });
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        match node.default {
            Some(_) => {
                self.record_unsafe_fn(&node.sig);
                self.visit_fn_body(&node.sig, false, |this| {
                    syn::visit::visit_trait_item_fn(this, node);
                });
            }
            None => {
                let fn_index = self.push_fn(&node.sig);
                self.emit_signature_type_refs(&node.sig, fn_index);
                syn::visit::visit_trait_item_fn(self, node);
            }
        }
    }

    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        let span_start = node.if_token.span.start();
        let span = Self::span_from(span_start);

        let else_info = node.else_branch.as_ref().map(|(else_token, _)| {
            let chain_len = match self.branch_context {
                Some(BranchContext::If) => None,
                _ => Some(Self::count_else_chain(node)),
            };
            ElseInfo {
                chain_len,
                span: Some(Self::span_from(else_token.span.start())),
            }
        });

        self.control_flow.push(ControlFlowFact {
            kind: ControlFlowKind::If,
            span,
            depth: self.depth + 1,
            loop_depth: self.loop_depth,
            parent_branch: self.branch_context,
            else_info,
        });

        self.depth += 1;
        let old_context = self.branch_context;
        self.branch_context = Some(BranchContext::If);
        syn::visit::visit_expr_if(self, node);
        self.branch_context = old_context;
        self.depth -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let span_start = node.match_token.span.start();
        let span = Self::span_from(span_start);

        self.control_flow.push(ControlFlowFact {
            kind: ControlFlowKind::Match,
            span,
            depth: self.depth + 1,
            loop_depth: self.loop_depth,
            parent_branch: self.branch_context,
            else_info: None,
        });

        self.depth += 1;
        let old_context = self.branch_context;
        self.branch_context = Some(BranchContext::Match);
        syn::visit::visit_expr_match(self, node);
        self.branch_context = old_context;
        self.depth -= 1;
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        let span = Self::span_from(node.for_token.span.start());
        self.visit_loop_body(ControlFlowKind::ForLoop, span, |s| {
            // Record pat names for naming check
            for_each_pat_ident(&node.pat, &mut |name| {
                s.push_binding_fact(name, None, false, false, false, None);
            });
            s.record_refcounted_loop_bindings(&node.pat, &node.expr);
            syn::visit::visit_expr_for_loop(s, node);
        });
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        let span = Self::span_from(node.while_token.span.start());
        self.visit_loop_body(ControlFlowKind::WhileLoop, span, |s| {
            syn::visit::visit_expr_while(s, node);
        });
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        let span = Self::span_from(node.loop_token.span.start());
        self.visit_loop_body(ControlFlowKind::Loop, span, |s| {
            syn::visit::visit_expr_loop(s, node);
        });
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        let span_start = node.or1_token.span.start();
        let span = Self::span_from(span_start);

        self.depth += 1;

        self.control_flow.push(ControlFlowFact {
            kind: ControlFlowKind::Closure,
            span,
            depth: self.depth,
            loop_depth: self.loop_depth,
            parent_branch: self.branch_context,
            else_info: None,
        });

        syn::visit::visit_expr_closure(self, node);
        self.depth -= 1;
    }

    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        let start = node.unsafe_token.span.start();
        self.unsafe_sites.push(UnsafeFact {
            kind: UnsafeKind::Block,
            span: Self::span_from(start),
            evidence: "unsafe block".into(),
        });
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        // Unsafe impl
        if let Some(token) = node.unsafety {
            let start = token.span.start();
            self.unsafe_sites.push(UnsafeFact {
                kind: UnsafeKind::Impl,
                span: Self::span_from(start),
                evidence: "unsafe impl".into(),
            });
        }

        let span = Self::span_from(get_type_span_start(&node.self_ty));

        let Some(self_name) = first_type_name(&node.self_ty) else {
            self.item_depth += 1;
            syn::visit::visit_item_impl(self, node);
            self.item_depth -= 1;
            return;
        };

        let trait_name: Option<Box<str>> = node
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .map(|seg| seg.ident.to_string().into_boxed_str());

        let mut edges: Vec<(Rc<str>, Rc<str>)> = Vec::with_capacity(node.items.len());

        if let Some(ref tn) = trait_name {
            edges.push((Rc::clone(&self_name), Rc::from(tn.as_ref())));
        }

        let mut sig_names = Vec::new();
        for item in &node.items {
            let syn::ImplItem::Fn(method) = item else {
                continue;
            };
            sig_names.clear();
            collect_signature_type_names_into(&method.sig, &mut sig_names);
            extend_edges_from_names(&self_name, &sig_names, &mut edges);
        }

        self.impl_blocks.push(ImplFact {
            self_type: Rc::clone(&self_name),
            trait_name,
            span,
            edges: edges.into_boxed_slice(),
        });

        self.item_depth += 1;
        syn::visit::visit_item_impl(self, node);
        self.item_depth -= 1;
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.visit_type_def(
            &node.ident,
            TypeDefKind::Struct,
            |name| {
                let mut edges = Vec::new();
                let mut type_names = Vec::new();
                for field in &node.fields {
                    type_names.clear();
                    collect_type_names_into(&field.ty, &mut type_names);
                    extend_edges_from_names(name, &type_names, &mut edges);
                }
                edges.into_boxed_slice()
            },
            |s| syn::visit::visit_item_struct(s, node),
        );
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        self.visit_type_def(
            &node.ident,
            TypeDefKind::Enum,
            |name| {
                let mut edges = Vec::new();
                let mut type_names = Vec::new();
                for variant in &node.variants {
                    for field in &variant.fields {
                        type_names.clear();
                        collect_type_names_into(&field.ty, &mut type_names);
                        extend_edges_from_names(name, &type_names, &mut edges);
                    }
                }
                edges.into_boxed_slice()
            },
            |s| syn::visit::visit_item_enum(s, node),
        );
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        self.visit_type_def(
            &node.ident,
            TypeDefKind::Trait,
            |name| {
                let mut edges = Vec::new();
                let mut sig_names = Vec::new();
                for item in &node.items {
                    let syn::TraitItem::Fn(method) = item else {
                        continue;
                    };
                    sig_names.clear();
                    collect_signature_type_names_into(&method.sig, &mut sig_names);
                    extend_edges_from_names(name, &sig_names, &mut edges);
                }
                edges.into_boxed_slice()
            },
            |s| syn::visit::visit_item_trait(s, node),
        );
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        self.item_depth += 1;
        syn::visit::visit_item_const(self, node);
        self.item_depth -= 1;
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        self.item_depth += 1;
        syn::visit::visit_item_type(self, node);
        self.item_depth -= 1;
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let span_start = node.use_token.span.start();
        let span = Self::span_from(span_start);

        self.path_buf.clear();
        walk_use_tree(&node.tree, &mut self.path_buf, 0, &mut self.use_paths, span);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        self.emit_multi_segment_path(&node.path);
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        self.record_string_binding(&node.pat);
        self.record_refcounted_from_pat(&node.pat);

        // Wildcard binding
        if let syn::Pat::Wild(w) = &node.pat {
            let init_is_write = node
                .init
                .as_ref()
                .map(|init| self.is_write_macro_to_string(&init.expr))
                .unwrap_or(false);

            let span = Self::span_from(w.underscore_token.span.start());
            self.push_binding_fact(
                "_".into(),
                Some(span),
                true,
                node.init.is_some(),
                init_is_write,
                None,
            );
        }

        // Extract named bindings for naming check
        Self::for_each_pat_ident_span(&node.pat, None, &mut |name, span, type_ann_span| {
            if !name.starts_with('_') {
                self.push_binding_fact(name, Some(span), false, false, false, type_ann_span);
            }
        });

        syn::visit::visit_local(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        let is_arithmetic = matches!(
            node.op,
            syn::BinOp::Add(_) | syn::BinOp::Sub(_) | syn::BinOp::Mul(_) | syn::BinOp::Div(_)
        );
        if let (true, Some(fn_idx)) = (is_arithmetic, self.current_fn) {
            self.functions[fn_idx].has_arithmetic = true;
        }
        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        let Some(last_seg) = node.path().segments.last() else {
            syn::visit::visit_attribute(self, node);
            return;
        };
        let text = extract_attribute_text(node);
        let span = Self::span_from(node.pound_token.spans[0].start());
        let name: Box<str> = last_seg.ident.to_string().into_boxed_str();

        self.attributes.push(AttributeFact { text, span, name });

        syn::visit::visit_attribute(self, node);
    }

    fn visit_type(&mut self, node: &'ast Type) {
        if !self.in_non_body_type {
            self.push_type_ref(node, TypeRefContext::Body, self.current_fn);
        }
        self.collect_body_type_from_type(node);
        syn::visit::visit_type(self, node);
    }

    fn visit_field(&mut self, node: &'ast syn::Field) {
        self.push_type_ref(&node.ty, TypeRefContext::Field, self.current_fn);
        self.in_non_body_type = true;
        syn::visit::visit_field(self, node);
        self.in_non_body_type = false;
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        self.collect_body_type_from_path(&node.path);
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let text = extract_method_call_text(node);
        let span = Self::span_from(node.dot_token.span.start());
        let receiver_span = Self::span_from(node.receiver.span().start());
        let method_name: Box<str> = node.method.to_string().into_boxed_str();
        let recv = iter_expr_ident(&node.receiver).map(|i| i.to_string().into_boxed_str());

        self.method_calls.push(MethodCallFact {
            method_name,
            text,
            span,
            receiver_ident: recv,
            receiver_span,
            loop_depth: self.loop_depth,
            containing_fn: self.current_fn,
            receiver_type: None,
            is_copy_receiver: false,
        });

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let Some(first_seg) = node.path.segments.first() else {
            return;
        };
        let span = Self::span_from(first_seg.ident.span().start());
        let text = extract_macro_text(node);

        self.macro_invocations.push(MacroFact { text, span });

        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_lit(&mut self, node: &'ast syn::ExprLit) {
        if let syn::Lit::Str(ref lit_str) = node.lit {
            let value: Box<str> = lit_str.value().into_boxed_str();
            self.string_literals.push(StringLitFact {
                value,
                span: Self::span_from(lit_str.span().start()),
            });
        }
        syn::visit::visit_expr_lit(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let start = node.abi.extern_token.span.start();
        self.extern_blocks.push(ExternBlockFact {
            span: Self::span_from(start),
        });
        syn::visit::visit_item_foreign_mod(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let has_cfg_test = node.attrs.iter().any(is_cfg_test_attr);
        let span = Self::span_from(node.mod_token.span.start());
        self.modules.push(ModuleFact {
            name: node.ident.to_string().into_boxed_str(),
            span,
            is_cfg_test: has_cfg_test,
        });
        syn::visit::visit_item_mod(self, node);
    }
}

/// Enrich IR facts with resolved type information from semantic analysis.
#[cfg(feature = "semantic")]
fn enrich_ir(ir: &mut FileIr, ctx: &super::semantic::SemanticContext) {
    let file_path: &str = &ir.file_path;
    enrich_bindings(&mut ir.bindings, file_path, ctx);
    enrich_type_refs(&mut ir.type_refs, file_path, ctx);
    enrich_method_calls(&mut ir.method_calls, &ir.bindings);
    enrich_data_flows(ir, ctx);
}

/// Trace taint propagation, detect quality, performance, and concurrency issues, populating `ir.data_flows`.
///
/// Delegates to `SemanticContext::enrich_all_data_flows` which parses the file
/// once and runs all detection passes within that single parse context.
#[cfg(feature = "semantic")]
fn enrich_data_flows(ir: &mut FileIr, ctx: &super::semantic::SemanticContext) {
    ir.data_flows = ctx.enrich_all_data_flows(&ir.file_path);
}

/// Resolve binding types through aliases and update `is_refcounted`.
#[cfg(feature = "semantic")]
fn enrich_bindings(
    bindings: &mut [BindingFact],
    file_path: &str,
    ctx: &super::semantic::SemanticContext,
) {
    for binding in bindings.iter_mut() {
        let Some(type_span) = binding.type_annotation_span else {
            continue;
        };
        let Some(resolved) = ctx.resolve_type(file_path, type_span.line, type_span.column) else {
            continue;
        };
        if resolved.contains("Arc<") || resolved.contains("Rc<") {
            binding.is_refcounted = true;
        }
        binding.resolved_type = Some(resolved);
    }
}

/// Resolve type references through aliases and update classification flags.
#[cfg(feature = "semantic")]
fn enrich_type_refs(
    type_refs: &mut [TypeRefFact],
    file_path: &str,
    ctx: &super::semantic::SemanticContext,
) {
    for tr in type_refs.iter_mut() {
        let Some(resolved) = ctx.resolve_type(file_path, tr.span.line, tr.span.column) else {
            continue;
        };
        if resolved.contains("dyn ") {
            tr.involves_dyn = true;
        }
        if resolved.contains("HashMap") && !resolved.contains("BuildHasher") {
            tr.is_default_hasher = true;
        }
        if resolved.contains("Vec") && resolved.contains("Box") && resolved.contains("dyn ") {
            tr.is_vec_box_dyn = true;
        }
    }
}

/// Resolve method call receiver types using enriched binding data.
///
/// Looks up the receiver identifier's resolved type from the binding facts
/// (already enriched by `enrich_bindings`). This works because `resolve_type`
/// resolves type annotations but not expression-level references.
#[cfg(feature = "semantic")]
fn enrich_method_calls(method_calls: &mut [MethodCallFact], bindings: &[BindingFact]) {
    use std::collections::BTreeMap;

    let mut binding_types: BTreeMap<(Option<usize>, &str), &str> = BTreeMap::new();
    for b in bindings {
        let Some(resolved) = b.resolved_type.as_deref() else {
            continue;
        };
        binding_types
            .entry((b.containing_fn, &b.name))
            .or_insert(resolved);
    }

    for mc in method_calls.iter_mut() {
        let Some(recv_ident) = mc.receiver_ident.as_deref() else {
            continue;
        };
        let Some(resolved) = binding_types.get(&(mc.containing_fn, recv_ident)) else {
            continue;
        };
        mc.is_copy_receiver = super::semantic::SemanticContext::is_copy(resolved);
        mc.receiver_type = Some(Box::from(*resolved));
    }
}
