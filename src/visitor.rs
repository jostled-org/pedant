use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use proc_macro2::LineColumn;
use syn::visit::Visit;
use syn::{
    Attribute, Expr, ExprIf, ExprMethodCall, ExprUnsafe, FnArg, Macro, ReturnType, Signature, Type,
};

use crate::config::{NamingCheck, PatternCheck};
use crate::pattern::{
    extract_attribute_text, extract_macro_text, extract_method_call_text, extract_type_text,
    matches_pattern,
};
use crate::violation::{Violation, ViolationType};

#[derive(Debug, Clone, Copy, PartialEq)]
enum BranchContext {
    If,
    Match,
}

/// Configuration controlling which checks are enabled and their thresholds.
#[derive(Debug, Clone)]
pub struct CheckConfig {
    /// Maximum allowed nesting depth.
    pub max_depth: usize,
    /// Flag `if` inside `if`.
    pub check_nested_if: bool,
    /// Flag `if` inside `match` arm.
    pub check_if_in_match: bool,
    /// Flag `match` inside `match`.
    pub check_nested_match: bool,
    /// Flag `match` inside `if` branch.
    pub check_match_in_if: bool,
    /// Flag long `if/else if` chains.
    pub check_else_chain: bool,
    /// Minimum branches to trigger `else-chain`.
    pub else_chain_threshold: usize,
    /// Banned attribute patterns.
    pub forbid_attributes: PatternCheck,
    /// Banned type patterns.
    pub forbid_types: PatternCheck,
    /// Banned method call patterns.
    pub forbid_calls: PatternCheck,
    /// Banned macro patterns.
    pub forbid_macros: PatternCheck,
    /// Flag any use of the `else` keyword.
    pub forbid_else: bool,
    /// Flag any `unsafe` block.
    pub forbid_unsafe: bool,
    /// Flag dynamic dispatch in return types.
    pub check_dyn_return: bool,
    /// Flag dynamic dispatch in function parameters.
    pub check_dyn_param: bool,
    /// Flag `Vec<Box<dyn T>>`.
    pub check_vec_box_dyn: bool,
    /// Flag dynamic dispatch in struct fields.
    pub check_dyn_field: bool,
    /// Flag `.clone()` inside loop bodies.
    pub check_clone_in_loop: bool,
    /// Flag `HashMap`/`HashSet` with default hasher.
    pub check_default_hasher: bool,
    /// Flag disconnected type groups in a single file.
    pub check_mixed_concerns: bool,
    /// Flag `#[cfg(test)] mod` blocks in source files.
    pub check_inline_tests: bool,
    /// Generic naming check configuration.
    pub check_naming: NamingCheck,
}

impl Default for CheckConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            check_nested_if: true,
            check_if_in_match: true,
            check_nested_match: true,
            check_match_in_if: true,
            check_else_chain: true,
            else_chain_threshold: 3,
            forbid_attributes: PatternCheck::default(),
            forbid_types: PatternCheck::default(),
            forbid_calls: PatternCheck::default(),
            forbid_macros: PatternCheck::default(),
            forbid_else: false,
            forbid_unsafe: true,
            check_dyn_return: false,
            check_dyn_param: false,
            check_vec_box_dyn: false,
            check_dyn_field: false,
            check_clone_in_loop: false,
            check_default_hasher: false,
            check_mixed_concerns: false,
            check_inline_tests: false,
            check_naming: NamingCheck::default(),
        }
    }
}

/// A recorded binding with the loop depth at time of capture.
#[derive(Clone)]
struct RecordedBinding {
    name: String,
    loop_depth: usize,
}

/// Saved per-function state for entry/exit.
struct FnSavedState {
    bindings: Vec<RecordedBinding>,
    has_arithmetic: bool,
    fn_span: Option<LineColumn>,
    refcounted_bindings: BTreeSet<String>,
    refcounted_containers: BTreeSet<String>,
}

/// AST visitor that collects violations during a single-pass walk.
pub struct NestingVisitor<'a> {
    file_path: &'a str,
    config: &'a CheckConfig,
    depth: usize,
    loop_depth: usize,
    branch_context: Option<BranchContext>,
    item_depth: usize,
    refcounted_bindings: BTreeSet<String>,
    refcounted_containers: BTreeSet<String>,
    defined_types: BTreeSet<Rc<str>>,
    type_edges: Vec<(Rc<str>, Rc<str>)>,
    violations: Vec<Violation>,
    naming_bindings: Vec<RecordedBinding>,
    naming_has_arithmetic: bool,
    naming_fn_span: Option<LineColumn>,
}

impl<'a> NestingVisitor<'a> {
    /// Creates a visitor for the given file path and config.
    pub fn new(file_path: &'a str, config: &'a CheckConfig) -> Self {
        Self {
            file_path,
            config,
            depth: 0,
            loop_depth: 0,
            branch_context: None,
            item_depth: 0,
            refcounted_bindings: BTreeSet::new(),
            refcounted_containers: BTreeSet::new(),
            defined_types: BTreeSet::new(),
            type_edges: Vec::new(),
            violations: Vec::new(),
            naming_bindings: Vec::new(),
            naming_has_arithmetic: false,
            naming_fn_span: None,
        }
    }

    fn save_fn_state(&self) -> FnSavedState {
        FnSavedState {
            bindings: self.naming_bindings.clone(),
            has_arithmetic: self.naming_has_arithmetic,
            fn_span: self.naming_fn_span,
            refcounted_bindings: self.refcounted_bindings.clone(),
            refcounted_containers: self.refcounted_containers.clone(),
        }
    }

    fn restore_fn_state(&mut self, state: FnSavedState) {
        self.naming_bindings = state.bindings;
        self.naming_has_arithmetic = state.has_arithmetic;
        self.naming_fn_span = state.fn_span;
        self.refcounted_bindings = state.refcounted_bindings;
        self.refcounted_containers = state.refcounted_containers;
    }

    fn reset_fn_state(&mut self, fn_span: LineColumn) {
        self.naming_bindings.clear();
        self.refcounted_bindings.clear();
        self.refcounted_containers.clear();
        self.naming_has_arithmetic = false;
        self.naming_fn_span = Some(fn_span);
    }

    fn record_binding(&mut self, name: String) {
        if name.starts_with('_') {
            return;
        }
        self.naming_bindings.push(RecordedBinding {
            name,
            loop_depth: self.loop_depth,
        });
    }

    fn extract_pat_names(&mut self, pat: &syn::Pat) {
        match pat {
            syn::Pat::Ident(pi) => self.record_binding(pi.ident.to_string()),
            syn::Pat::Tuple(pt) => pt.elems.iter().for_each(|p| self.extract_pat_names(p)),
            syn::Pat::TupleStruct(pts) => pts.elems.iter().for_each(|p| self.extract_pat_names(p)),
            syn::Pat::Struct(ps) => ps
                .fields
                .iter()
                .for_each(|fp| self.extract_pat_names(&fp.pat)),
            syn::Pat::Slice(psl) => psl.elems.iter().for_each(|p| self.extract_pat_names(p)),
            syn::Pat::Or(po) => po.cases.iter().for_each(|p| self.extract_pat_names(p)),
            syn::Pat::Reference(pr) => self.extract_pat_names(&pr.pat),
            _ => {}
        }
    }

    fn count_fn_params(&mut self, sig: &Signature) {
        for input in &sig.inputs {
            match input {
                FnArg::Typed(pt) => self.extract_pat_names(&pt.pat),
                FnArg::Receiver(_) => {}
            }
        }
    }

    fn record_refcounted_params(&mut self, sig: &Signature) {
        for input in &sig.inputs {
            let FnArg::Typed(pt) = input else {
                continue;
            };
            let syn::Pat::Ident(pi) = pt.pat.as_ref() else {
                continue;
            };
            let name = pi.ident.to_string();
            match (is_refcounted_type(&pt.ty), contains_refcounted_type(&pt.ty)) {
                (true, _) => {
                    self.refcounted_bindings.insert(name);
                }
                (false, true) => {
                    self.refcounted_containers.insert(name);
                }
                _ => {}
            }
        }
    }

    fn record_refcounted_from_pat(&mut self, pat: &syn::Pat) {
        let syn::Pat::Type(pt) = pat else {
            return;
        };
        let syn::Pat::Ident(pi) = pt.pat.as_ref() else {
            return;
        };
        let name = pi.ident.to_string();
        match (is_refcounted_type(&pt.ty), contains_refcounted_type(&pt.ty)) {
            (true, _) => {
                self.refcounted_bindings.insert(name);
            }
            (false, true) => {
                self.refcounted_containers.insert(name);
            }
            _ => {}
        }
    }

    fn record_refcounted_loop_bindings(&mut self, pat: &syn::Pat, iter_expr: &Expr) {
        let Some(ident) = iter_expr_ident(iter_expr) else {
            return;
        };
        if !self.refcounted_containers.contains(&ident) {
            return;
        }
        for name in collect_pat_idents(pat) {
            self.refcounted_bindings.insert(name);
        }
    }

    fn classify_binding(
        binding: &RecordedBinding,
        has_arithmetic: bool,
        generic_names: &[String],
    ) -> bool {
        classify_single_char(&binding.name, binding.loop_depth, has_arithmetic)
            .unwrap_or_else(|| generic_names.iter().any(|g| g == &binding.name))
    }

    fn check_naming_entropy(&mut self) {
        if !self.config.check_naming.enabled {
            return;
        }
        let total = self.naming_bindings.len();
        if total == 0 {
            return;
        }
        let has_arithmetic = self.naming_has_arithmetic;
        let generic_names = &self.config.check_naming.generic_names;
        let offenders: Vec<&str> = self
            .naming_bindings
            .iter()
            .filter(|b| Self::classify_binding(b, has_arithmetic, generic_names))
            .map(|b| b.name.as_str())
            .collect();
        let generic_count = offenders.len();
        if generic_count < self.config.check_naming.min_generic_count {
            return;
        }
        let ratio = generic_count as f64 / total as f64;
        if ratio <= self.config.check_naming.max_generic_ratio {
            return;
        }
        let Some(span) = self.naming_fn_span else {
            return;
        };
        let offender_list = offenders.join(", ");
        self.report(
            span,
            ViolationType::GenericNaming,
            format!(
                "{generic_count}/{total} bindings are generic ({offender_list}), use domain-specific names",
            ),
        );
    }

    /// Consumes the visitor and returns all collected violations.
    pub fn violations(self) -> Vec<Violation> {
        self.violations
    }

    fn report(&mut self, span_start: LineColumn, violation_type: ViolationType, message: String) {
        self.violations.push(Violation::new(
            violation_type,
            self.file_path.to_string(),
            span_start.line,
            span_start.column + 1,
            message,
        ));
    }

    fn check_max_depth(&mut self, span_start: LineColumn) {
        if self.depth > self.config.max_depth {
            self.report(
                span_start,
                ViolationType::MaxDepth,
                format!(
                    "nesting depth {} exceeds limit of {}",
                    self.depth, self.config.max_depth
                ),
            );
        }
    }

    fn check_else_chain(&mut self, node: &ExprIf, span_start: LineColumn) {
        let is_top_level = self.branch_context != Some(BranchContext::If);
        if !self.config.check_else_chain || !is_top_level {
            return;
        }
        let chain_len = Self::count_else_chain(node);
        if chain_len < self.config.else_chain_threshold {
            return;
        }
        self.report(
            span_start,
            ViolationType::ElseChain,
            format!("if/else chain has {} branches, consider match", chain_len),
        );
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

    fn check_attribute(&mut self, attr: &Attribute) {
        if !self.config.forbid_attributes.enabled {
            return;
        }

        let attr_text = extract_attribute_text(attr);
        for pattern in &self.config.forbid_attributes.patterns {
            if matches_pattern(&attr_text, pattern) {
                let span_start = attr.pound_token.span.start();
                self.report(
                    span_start,
                    ViolationType::ForbiddenAttribute {
                        pattern: pattern.to_owned(),
                    },
                    attr_text,
                );
                return;
            }
        }
    }

    fn check_type(&mut self, ty: &Type, span_start: LineColumn) {
        if !self.config.forbid_types.enabled {
            return;
        }

        let type_text = extract_type_text(ty);
        for pattern in &self.config.forbid_types.patterns {
            if matches_pattern(&type_text, pattern) {
                self.report(
                    span_start,
                    ViolationType::ForbiddenType {
                        pattern: pattern.to_owned(),
                    },
                    type_text,
                );
                return;
            }
        }
    }

    fn check_call(&mut self, call: &ExprMethodCall) {
        if !self.config.forbid_calls.enabled {
            return;
        }

        let call_text = extract_method_call_text(call);
        for pattern in &self.config.forbid_calls.patterns {
            if matches_pattern(&call_text, pattern) {
                let span_start = call.dot_token.span.start();
                self.report(
                    span_start,
                    ViolationType::ForbiddenCall {
                        pattern: pattern.to_owned(),
                    },
                    call_text,
                );
                return;
            }
        }
    }

    fn check_macro(&mut self, mac: &Macro, span_start: LineColumn) {
        if !self.config.forbid_macros.enabled {
            return;
        }

        let macro_text = extract_macro_text(mac);
        for pattern in &self.config.forbid_macros.patterns {
            if matches_pattern(&macro_text, pattern) {
                self.report(
                    span_start,
                    ViolationType::ForbiddenMacro {
                        pattern: pattern.to_owned(),
                    },
                    macro_text,
                );
                return;
            }
        }
    }

    fn check_else(&mut self, span_start: LineColumn) {
        if !self.config.forbid_else {
            return;
        }
        self.report(
            span_start,
            ViolationType::ForbiddenElse,
            "use match or early return instead of else".to_string(),
        );
    }

    fn check_unsafe(&mut self, span_start: LineColumn) {
        if !self.config.forbid_unsafe {
            return;
        }
        self.report(
            span_start,
            ViolationType::ForbiddenUnsafe,
            "unsafe block detected".to_string(),
        );
    }

    fn check_inline_tests(&mut self, node: &syn::ItemMod) {
        if !self.config.check_inline_tests {
            return;
        }
        let has_cfg_test = node.attrs.iter().any(|attr| {
            let text = extract_attribute_text(attr);
            text == "cfg(test)"
        });
        if !has_cfg_test {
            return;
        }
        let span_start = node.mod_token.span.start();
        self.report(
            span_start,
            ViolationType::InlineTests,
            format!("test module `{}` should be in tests/ directory", node.ident),
        );
    }

    fn check_mixed_concerns(&mut self) {
        if !self.config.check_mixed_concerns || self.defined_types.len() < 2 {
            return;
        }
        let Some(message) = self.find_disconnected_groups() else {
            return;
        };
        self.report(
            LineColumn { line: 1, column: 0 },
            ViolationType::MixedConcerns,
            message,
        );
    }

    fn find_disconnected_groups(&self) -> Option<String> {
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for name in &self.defined_types {
            adj.entry(name).or_default();
        }
        for (src, dst) in &self.type_edges {
            let (src, dst) = (src.as_ref(), dst.as_ref());
            if src == dst || !self.defined_types.contains(src) || !self.defined_types.contains(dst)
            {
                continue;
            }
            adj.entry(src).or_default().push(dst);
            adj.entry(dst).or_default().push(src);
        }

        let mut visited: BTreeSet<&str> = BTreeSet::new();
        let mut components: Vec<Vec<&str>> = Vec::new();

        for name in &self.defined_types {
            if visited.contains(name.as_ref()) {
                continue;
            }
            components.push(bfs_component(name, &adj, &mut visited));
        }

        if components.len() < 2 {
            return None;
        }

        components.sort_by(|a, b| a.first().cmp(&b.first()));
        let groups: Vec<String> = components
            .iter()
            .map(|c| format!("{{{}}}", c.join(", ")))
            .collect();
        Some(format!("disconnected type groups: {}", groups.join(", ")))
    }

    fn check_fn_signature(&mut self, sig: &Signature) {
        self.check_dyn_return(sig);
        self.check_dyn_params(sig);
    }

    fn check_dyn_return(&mut self, sig: &Signature) {
        if !self.config.check_dyn_return {
            return;
        }
        let ReturnType::Type(_, ty) = &sig.output else {
            return;
        };
        if !involves_dyn_dispatch(ty) {
            return;
        }
        let span_start = sig.ident.span().start();
        let type_text = extract_type_text(ty);
        self.report(
            span_start,
            ViolationType::DynReturn,
            format!("dynamic dispatch in return type: {type_text}"),
        );
    }

    fn check_dyn_params(&mut self, sig: &Signature) {
        if !self.config.check_dyn_param {
            return;
        }
        for input in &sig.inputs {
            let FnArg::Typed(pat_type) = input else {
                continue;
            };
            if !involves_dyn_dispatch(&pat_type.ty) {
                continue;
            }
            let span_start = pat_type.colon_token.span.start();
            let type_text = extract_type_text(&pat_type.ty);
            self.report(
                span_start,
                ViolationType::DynParam,
                format!("dynamic dispatch in parameter: {type_text}"),
            );
        }
    }

    fn check_vec_box_dyn(&mut self, ty: &Type, span_start: LineColumn) {
        if !self.config.check_vec_box_dyn {
            return;
        }
        if !is_vec_box_dyn(ty) {
            return;
        }
        let type_text = extract_type_text(ty);
        self.report(
            span_start,
            ViolationType::VecBoxDyn,
            format!("Vec of boxed trait object: {type_text}"),
        );
    }

    fn check_dyn_field(&mut self, field: &syn::Field) {
        if !self.config.check_dyn_field {
            return;
        }
        if !involves_dyn_dispatch(&field.ty) {
            return;
        }
        let span_start = get_type_span_start(&field.ty);
        let type_text = extract_type_text(&field.ty);
        self.report(
            span_start,
            ViolationType::DynField,
            format!("dynamic dispatch in struct field: {type_text}"),
        );
    }

    fn check_clone_in_loop(&mut self, call: &ExprMethodCall) {
        if !self.config.check_clone_in_loop || self.loop_depth == 0 {
            return;
        }
        if call.method != "clone" {
            return;
        }
        let is_refcounted = receiver_ident(&call.receiver)
            .is_some_and(|ident| self.refcounted_bindings.contains(&ident));
        if is_refcounted {
            return;
        }
        let span_start = call.dot_token.span.start();
        self.report(
            span_start,
            ViolationType::CloneInLoop,
            ".clone() inside loop body allocates per iteration".to_string(),
        );
    }

    fn check_default_hasher(&mut self, ty: &Type, span_start: LineColumn) {
        if !self.config.check_default_hasher {
            return;
        }
        if !is_default_hasher(ty) {
            return;
        }
        let type_text = extract_type_text(ty);
        self.report(
            span_start,
            ViolationType::DefaultHasher,
            format!("default SipHash hasher: {type_text}"),
        );
    }
}

/// Classifies a single-character binding name. Returns `Some(true)` if generic,
/// `Some(false)` if contextually allowed, `None` if the name is multi-character.
fn classify_single_char(name: &str, loop_depth: usize, has_arithmetic: bool) -> Option<bool> {
    match name {
        "i" | "j" | "k" | "n" => Some(loop_depth == 0),
        "x" | "y" | "z" => Some(!has_arithmetic),
        _ => None,
    }
}

fn collect_type_names(ty: &Type) -> Vec<String> {
    match ty {
        Type::Path(tp) => {
            let mut names: Vec<String> = tp
                .path
                .segments
                .iter()
                .map(|seg| seg.ident.to_string())
                .collect();
            for seg in &tp.path.segments {
                let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
                    continue;
                };
                for arg in &args.args {
                    let syn::GenericArgument::Type(inner) = arg else {
                        continue;
                    };
                    names.extend(collect_type_names(inner));
                }
            }
            names
        }
        Type::Reference(r) => collect_type_names(&r.elem),
        Type::Tuple(t) => t.elems.iter().flat_map(collect_type_names).collect(),
        Type::Slice(s) => collect_type_names(&s.elem),
        Type::Array(a) => collect_type_names(&a.elem),
        _ => Vec::new(),
    }
}

fn collect_signature_type_names(sig: &Signature) -> Vec<String> {
    let mut names = Vec::new();
    for input in &sig.inputs {
        match input {
            FnArg::Typed(pat) => names.extend(collect_type_names(&pat.ty)),
            FnArg::Receiver(_) => {}
        }
    }
    if let ReturnType::Type(_, ty) = &sig.output {
        names.extend(collect_type_names(ty));
    }
    names
}

fn bfs_component<'a>(
    start: &'a str,
    adj: &BTreeMap<&'a str, Vec<&'a str>>,
    visited: &mut BTreeSet<&'a str>,
) -> Vec<&'a str> {
    let mut component = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(start);
    visited.insert(start);
    while let Some(current) = queue.pop_front() {
        component.push(current);
        for &neighbor in &adj[current] {
            if visited.insert(neighbor) {
                queue.push_back(neighbor);
            }
        }
    }
    component.sort_unstable();
    component
}

fn contains_refcounted_type(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => path_contains_refcounted(tp),
        Type::Reference(r) => contains_refcounted_type(&r.elem),
        Type::Slice(s) => contains_refcounted_type(&s.elem),
        Type::Array(a) => contains_refcounted_type(&a.elem),
        Type::Tuple(t) => t.elems.iter().any(contains_refcounted_type),
        _ => false,
    }
}

fn path_contains_refcounted(tp: &syn::TypePath) -> bool {
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    if seg.ident == "Arc" || seg.ident == "Rc" {
        return true;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return false;
    };
    args.args.iter().any(
        |arg| matches!(arg, syn::GenericArgument::Type(inner) if contains_refcounted_type(inner)),
    )
}

fn iter_expr_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(ep) if ep.path.segments.len() == 1 => {
            Some(ep.path.segments[0].ident.to_string())
        }
        Expr::Reference(er) => iter_expr_ident(&er.expr),
        _ => None,
    }
}

fn collect_pat_idents(pat: &syn::Pat) -> Vec<String> {
    match pat {
        syn::Pat::Ident(pi) => vec![pi.ident.to_string()],
        syn::Pat::Tuple(pt) => pt.elems.iter().flat_map(collect_pat_idents).collect(),
        syn::Pat::TupleStruct(pts) => pts.elems.iter().flat_map(collect_pat_idents).collect(),
        syn::Pat::Reference(pr) => collect_pat_idents(&pr.pat),
        syn::Pat::Type(pt) => collect_pat_idents(&pt.pat),
        _ => vec![],
    }
}

fn receiver_ident(expr: &Expr) -> Option<String> {
    let Expr::Path(ep) = expr else {
        return None;
    };
    match ep.path.segments.len() {
        1 => Some(ep.path.segments[0].ident.to_string()),
        _ => None,
    }
}

fn is_refcounted_type(ty: &Type) -> bool {
    let ty = match ty {
        Type::Reference(r) => &r.elem,
        _ => ty,
    };
    type_path_last_segment(ty)
        .map(|seg| seg.ident == "Arc" || seg.ident == "Rc")
        .unwrap_or(false)
}

fn type_path_last_segment(ty: &Type) -> Option<&syn::PathSegment> {
    match ty {
        Type::Path(tp) => tp.path.segments.last(),
        _ => None,
    }
}

fn first_type_arg(seg: &syn::PathSegment) -> Option<&Type> {
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    args.args.iter().find_map(as_type_arg)
}

fn as_type_arg(arg: &syn::GenericArgument) -> Option<&Type> {
    if let syn::GenericArgument::Type(ty) = arg {
        return Some(ty);
    }
    None
}

fn count_type_args(seg: &syn::PathSegment) -> usize {
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return 0;
    };
    args.args
        .iter()
        .filter(|arg| matches!(arg, syn::GenericArgument::Type(_)))
        .count()
}

fn involves_dyn_dispatch(ty: &Type) -> bool {
    match ty {
        Type::TraitObject(_) => true,
        Type::Reference(r) => matches!(r.elem.as_ref(), Type::TraitObject(_)),
        _ => {
            let Some(seg) = type_path_last_segment(ty) else {
                return false;
            };
            let name = seg.ident.to_string();
            matches!(name.as_str(), "Box" | "Arc" | "Rc")
                && first_type_arg(seg).is_some_and(|inner| matches!(inner, Type::TraitObject(_)))
        }
    }
}

fn is_vec_box_dyn(ty: &Type) -> bool {
    let Some(seg) = type_path_last_segment(ty) else {
        return false;
    };
    if seg.ident != "Vec" {
        return false;
    }
    let Some(inner) = first_type_arg(seg) else {
        return false;
    };
    let Some(inner_seg) = type_path_last_segment(inner) else {
        return false;
    };
    if inner_seg.ident != "Box" {
        return false;
    }
    first_type_arg(inner_seg).is_some_and(|ty| matches!(ty, Type::TraitObject(_)))
}

fn is_default_hasher(ty: &Type) -> bool {
    let Some(seg) = type_path_last_segment(ty) else {
        return false;
    };
    let name = seg.ident.to_string();
    match name.as_str() {
        "HashMap" => count_type_args(seg) == 2,
        "HashSet" => count_type_args(seg) == 1,
        _ => false,
    }
}

fn get_type_span_start(ty: &Type) -> LineColumn {
    match ty {
        Type::Path(tp) => tp
            .path
            .segments
            .first()
            .map(|s| s.ident.span().start())
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 }),
        Type::Reference(tr) => tr.and_token.span.start(),
        Type::Ptr(tp) => tp.star_token.span.start(),
        Type::Array(ta) => ta.bracket_token.span.open().start(),
        Type::Slice(ts) => ts.bracket_token.span.open().start(),
        Type::Tuple(tt) => tt.paren_token.span.open().start(),
        Type::Group(tg) => tg.group_token.span.start(),
        Type::Paren(tp) => tp.paren_token.span.open().start(),
        Type::ImplTrait(ti) => ti.impl_token.span.start(),
        Type::TraitObject(to) => to
            .bounds
            .first()
            .map(get_type_param_bound_span)
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 }),
        Type::BareFn(bf) => bf.fn_token.span.start(),
        Type::Never(tn) => tn.bang_token.span.start(),
        Type::Infer(ti) => ti.underscore_token.span.start(),
        Type::Macro(tm) => tm
            .mac
            .path
            .segments
            .first()
            .map(|s| s.ident.span().start())
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 }),
        _ => LineColumn { line: 1, column: 0 },
    }
}

fn get_type_param_bound_span(bound: &syn::TypeParamBound) -> LineColumn {
    match bound {
        syn::TypeParamBound::Trait(tb) => tb
            .path
            .segments
            .first()
            .map(|s| s.ident.span().start())
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 }),
        syn::TypeParamBound::Lifetime(lt) => lt.apostrophe.start(),
        _ => LineColumn { line: 1, column: 0 },
    }
}

fn edges_from_names(owner: &Rc<str>, type_names: Vec<String>) -> Vec<(Rc<str>, Rc<str>)> {
    type_names
        .into_iter()
        .map(|tn| (Rc::clone(owner), Rc::from(tn)))
        .collect()
}

fn signature_edge_pairs(sig: &Signature) -> Vec<(Rc<str>, Rc<str>)> {
    let names: Vec<Rc<str>> = collect_signature_type_names(sig)
        .into_iter()
        .map(Rc::from)
        .collect();
    let mut pairs = Vec::new();
    let len = names.len();
    (0..len).for_each(|i| {
        ((i + 1)..len).for_each(|j| {
            pairs.push((Rc::clone(&names[i]), Rc::clone(&names[j])));
        });
    });
    pairs
}

impl<'ast> Visit<'ast> for NestingVisitor<'_> {
    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        let span_start = node.if_token.span.start();

        match self.branch_context {
            Some(BranchContext::If) if self.config.check_nested_if => {
                self.report(
                    span_start,
                    ViolationType::NestedIf,
                    "if nested inside if, consider combining conditions".to_string(),
                );
            }
            Some(BranchContext::Match) if self.config.check_if_in_match => {
                self.report(
                    span_start,
                    ViolationType::IfInMatch,
                    "if inside match arm, consider match guard".to_string(),
                );
            }
            _ => {}
        }

        self.check_else_chain(node, span_start);

        // Check for `else` keyword
        if let Some((else_token, _)) = &node.else_branch {
            self.check_else(else_token.span.start());
        }

        self.depth += 1;
        self.check_max_depth(span_start);

        let old_context = self.branch_context;
        self.branch_context = Some(BranchContext::If);
        syn::visit::visit_expr_if(self, node);
        self.branch_context = old_context;

        self.depth -= 1;
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        let span_start = node.unsafe_token.span.start();
        self.check_unsafe(span_start);
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let span_start = node.match_token.span.start();

        match self.branch_context {
            Some(BranchContext::Match) if self.config.check_nested_match => {
                self.report(
                    span_start,
                    ViolationType::NestedMatch,
                    "nested match expression, consider tuple matching".to_string(),
                );
            }
            Some(BranchContext::If) if self.config.check_match_in_if => {
                self.report(
                    span_start,
                    ViolationType::MatchInIf,
                    "match inside if, consider restructuring".to_string(),
                );
            }
            _ => {}
        }

        self.depth += 1;
        self.check_max_depth(span_start);

        let old_context = self.branch_context;
        self.branch_context = Some(BranchContext::Match);
        syn::visit::visit_expr_match(self, node);
        self.branch_context = old_context;

        self.depth -= 1;
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        let span_start = node.for_token.span.start();
        self.depth += 1;
        self.loop_depth += 1;
        self.check_max_depth(span_start);
        self.extract_pat_names(&node.pat);
        self.record_refcounted_loop_bindings(&node.pat, &node.expr);
        syn::visit::visit_expr_for_loop(self, node);
        self.loop_depth -= 1;
        self.depth -= 1;
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        let span_start = node.while_token.span.start();
        self.depth += 1;
        self.loop_depth += 1;
        self.check_max_depth(span_start);
        syn::visit::visit_expr_while(self, node);
        self.loop_depth -= 1;
        self.depth -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        let span_start = node.loop_token.span.start();
        self.depth += 1;
        self.loop_depth += 1;
        self.check_max_depth(span_start);
        syn::visit::visit_expr_loop(self, node);
        self.loop_depth -= 1;
        self.depth -= 1;
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        let span_start = node.or1_token.span.start();
        self.depth += 1;
        self.check_max_depth(span_start);
        syn::visit::visit_expr_closure(self, node);
        self.depth -= 1;
    }

    fn visit_attribute(&mut self, node: &'ast Attribute) {
        self.check_attribute(node);
        syn::visit::visit_attribute(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        self.check_inline_tests(node);
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.check_fn_signature(&node.sig);
        if self.item_depth == 0 {
            self.type_edges.extend(signature_edge_pairs(&node.sig));
        }
        let saved = self.save_fn_state();
        self.reset_fn_state(node.sig.ident.span().start());
        self.count_fn_params(&node.sig);
        self.record_refcounted_params(&node.sig);
        self.item_depth += 1;
        syn::visit::visit_item_fn(self, node);
        self.item_depth -= 1;
        self.check_naming_entropy();
        self.restore_fn_state(saved);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        let name: Rc<str> = Rc::from(node.ident.to_string());
        self.defined_types.insert(Rc::clone(&name));
        let edges: Vec<_> = node
            .fields
            .iter()
            .flat_map(|field| edges_from_names(&name, collect_type_names(&field.ty)))
            .collect();
        self.type_edges.extend(edges);
        self.item_depth += 1;
        syn::visit::visit_item_struct(self, node);
        self.item_depth -= 1;
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        let name: Rc<str> = Rc::from(node.ident.to_string());
        self.defined_types.insert(Rc::clone(&name));
        let edges: Vec<_> = node
            .variants
            .iter()
            .flat_map(|variant| &variant.fields)
            .flat_map(|field| edges_from_names(&name, collect_type_names(&field.ty)))
            .collect();
        self.type_edges.extend(edges);
        self.item_depth += 1;
        syn::visit::visit_item_enum(self, node);
        self.item_depth -= 1;
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let name: Rc<str> = Rc::from(node.ident.to_string());
        self.defined_types.insert(Rc::clone(&name));
        let edges: Vec<_> = node
            .items
            .iter()
            .filter_map(|item| match item {
                syn::TraitItem::Fn(method) => Some(method),
                _ => None,
            })
            .flat_map(|method| edges_from_names(&name, collect_signature_type_names(&method.sig)))
            .collect();
        self.type_edges.extend(edges);
        self.item_depth += 1;
        syn::visit::visit_item_trait(self, node);
        self.item_depth -= 1;
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let self_name: Rc<str> = Rc::from(
            collect_type_names(&node.self_ty)
                .into_iter()
                .next()
                .unwrap_or_default(),
        );
        if let Some(trait_name) = node
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .map(|seg| seg.ident.to_string())
        {
            self.type_edges
                .push((Rc::clone(&self_name), Rc::from(trait_name)));
        }
        let edges: Vec<_> = node
            .items
            .iter()
            .filter_map(|item| match item {
                syn::ImplItem::Fn(method) => Some(method),
                _ => None,
            })
            .flat_map(|method| {
                edges_from_names(&self_name, collect_signature_type_names(&method.sig))
            })
            .collect();
        self.type_edges.extend(edges);
        self.item_depth += 1;
        syn::visit::visit_item_impl(self, node);
        self.item_depth -= 1;
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

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.check_fn_signature(&node.sig);
        let saved = self.save_fn_state();
        self.reset_fn_state(node.sig.ident.span().start());
        self.count_fn_params(&node.sig);
        self.record_refcounted_params(&node.sig);
        syn::visit::visit_impl_item_fn(self, node);
        self.check_naming_entropy();
        self.restore_fn_state(saved);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.check_fn_signature(&node.sig);
        syn::visit::visit_trait_item_fn(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        self.extract_pat_names(&node.pat);
        self.record_refcounted_from_pat(&node.pat);
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(
            node.op,
            syn::BinOp::Add(_) | syn::BinOp::Sub(_) | syn::BinOp::Mul(_) | syn::BinOp::Div(_)
        ) {
            self.naming_has_arithmetic = true;
        }
        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_field(&mut self, node: &'ast syn::Field) {
        self.check_dyn_field(node);
        syn::visit::visit_field(self, node);
    }

    fn visit_type(&mut self, node: &'ast Type) {
        let span_start = get_type_span_start(node);
        self.check_type(node, span_start);
        self.check_vec_box_dyn(node, span_start);
        self.check_default_hasher(node, span_start);
        syn::visit::visit_type(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        self.check_call(node);
        self.check_clone_in_loop(node);
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        let span_start = node
            .path
            .segments
            .first()
            .map(|s| s.ident.span().start())
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 });
        self.check_macro(node, span_start);
        syn::visit::visit_macro(self, node);
    }
}

/// Parse and analyze a Rust source string, returning all detected violations.
pub fn analyze(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
) -> Result<Vec<Violation>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = NestingVisitor::new(file_path, config);
    visitor.visit_file(&syntax);
    visitor.check_mixed_concerns();
    Ok(visitor.violations())
}
