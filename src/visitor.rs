use std::collections::{HashMap, HashSet, VecDeque};

use proc_macro2::LineColumn;
use syn::visit::Visit;
use syn::{
    Attribute, Expr, ExprIf, ExprMethodCall, ExprUnsafe, FnArg, Macro, ReturnType, Signature, Type,
};

use crate::config::PatternCheck;
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
    pub max_depth: usize,
    pub check_nested_if: bool,
    pub check_if_in_match: bool,
    pub check_nested_match: bool,
    pub check_match_in_if: bool,
    pub check_else_chain: bool,
    pub else_chain_threshold: usize,
    pub forbid_attributes: PatternCheck,
    pub forbid_types: PatternCheck,
    pub forbid_calls: PatternCheck,
    pub forbid_macros: PatternCheck,
    pub forbid_else: bool,
    pub forbid_unsafe: bool,
    pub check_dyn_return: bool,
    pub check_dyn_param: bool,
    pub check_vec_box_dyn: bool,
    pub check_dyn_field: bool,
    pub check_clone_in_loop: bool,
    pub check_default_hasher: bool,
    pub check_mixed_concerns: bool,
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
        }
    }
}

/// AST visitor that collects violations during a single-pass walk.
pub struct NestingVisitor<'a> {
    file_path: &'a str,
    config: &'a CheckConfig,
    depth: usize,
    loop_depth: usize,
    branch_context: Option<BranchContext>,
    item_depth: usize,
    defined_types: HashSet<String>,
    type_edges: Vec<(String, String)>,
    violations: Vec<Violation>,
}

impl<'a> NestingVisitor<'a> {
    pub fn new(file_path: &'a str, config: &'a CheckConfig) -> Self {
        Self {
            file_path,
            config,
            depth: 0,
            loop_depth: 0,
            branch_context: None,
            item_depth: 0,
            defined_types: HashSet::new(),
            type_edges: Vec::new(),
            violations: Vec::new(),
        }
    }

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
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        for name in &self.defined_types {
            adj.entry(name.as_str()).or_default();
        }
        for (a, b) in &self.type_edges {
            if a == b || !self.defined_types.contains(a) || !self.defined_types.contains(b) {
                continue;
            }
            adj.entry(a.as_str()).or_default().push(b.as_str());
            adj.entry(b.as_str()).or_default().push(a.as_str());
        }

        let mut visited: HashSet<&str> = HashSet::new();
        let mut components: Vec<Vec<&str>> = Vec::new();

        for name in &self.defined_types {
            if visited.contains(name.as_str()) {
                continue;
            }
            components.push(bfs_component(name.as_str(), &adj, &mut visited));
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
    adj: &HashMap<&'a str, Vec<&'a str>>,
    visited: &mut HashSet<&'a str>,
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
                && first_type_arg(seg)
                    .is_some_and(|inner| matches!(inner, Type::TraitObject(_)))
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
        Type::Path(tp) => tp.path.segments.first()
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
        Type::TraitObject(to) => to.bounds.first()
            .map(get_type_param_bound_span)
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 }),
        Type::BareFn(bf) => bf.fn_token.span.start(),
        Type::Never(tn) => tn.bang_token.span.start(),
        Type::Infer(ti) => ti.underscore_token.span.start(),
        Type::Macro(tm) => tm.mac.path.segments.first()
            .map(|s| s.ident.span().start())
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 }),
        _ => LineColumn { line: 1, column: 0 },
    }
}

fn get_type_param_bound_span(bound: &syn::TypeParamBound) -> LineColumn {
    match bound {
        syn::TypeParamBound::Trait(tb) => tb.path.segments.first()
            .map(|s| s.ident.span().start())
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 }),
        syn::TypeParamBound::Lifetime(lt) => lt.apostrophe.start(),
        _ => LineColumn { line: 1, column: 0 },
    }
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

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.check_fn_signature(&node.sig);
        if self.item_depth == 0 {
            let names: Vec<String> = collect_signature_type_names(&node.sig);
            for i in 0..names.len() {
                for j in (i + 1)..names.len() {
                    self.type_edges.push((names[i].clone(), names[j].clone()));
                }
            }
        }
        self.item_depth += 1;
        syn::visit::visit_item_fn(self, node);
        self.item_depth -= 1;
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        let name = node.ident.to_string();
        self.defined_types.insert(name.clone());
        for field in &node.fields {
            for type_name in collect_type_names(&field.ty) {
                self.type_edges.push((name.clone(), type_name));
            }
        }
        self.item_depth += 1;
        syn::visit::visit_item_struct(self, node);
        self.item_depth -= 1;
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        let name = node.ident.to_string();
        self.defined_types.insert(name.clone());
        for variant in &node.variants {
            for field in &variant.fields {
                for type_name in collect_type_names(&field.ty) {
                    self.type_edges.push((name.clone(), type_name));
                }
            }
        }
        self.item_depth += 1;
        syn::visit::visit_item_enum(self, node);
        self.item_depth -= 1;
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let name = node.ident.to_string();
        self.defined_types.insert(name.clone());
        for item in &node.items {
            if let syn::TraitItem::Fn(method) = item {
                for type_name in collect_signature_type_names(&method.sig) {
                    self.type_edges.push((name.clone(), type_name));
                }
            }
        }
        self.item_depth += 1;
        syn::visit::visit_item_trait(self, node);
        self.item_depth -= 1;
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let self_name = collect_type_names(&node.self_ty)
            .into_iter()
            .next()
            .unwrap_or_default();
        if let Some(trait_name) = node.trait_.as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .map(|seg| seg.ident.to_string())
        {
            self.type_edges.push((self_name.clone(), trait_name));
        }
        for item in &node.items {
            if let syn::ImplItem::Fn(method) = item {
                for type_name in collect_signature_type_names(&method.sig) {
                    self.type_edges.push((self_name.clone(), type_name));
                }
            }
        }
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
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.check_fn_signature(&node.sig);
        syn::visit::visit_trait_item_fn(self, node);
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
        let span_start = node.path.segments.first()
            .map(|s| s.ident.span().start())
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 });
        self.check_macro(node, span_start);
        syn::visit::visit_macro(self, node);
    }
}

/// Parse and analyze a Rust source string, returning all detected violations.
pub fn analyze(file_path: &str, source: &str, config: &CheckConfig) -> Result<Vec<Violation>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = NestingVisitor::new(file_path, config);
    visitor.visit_file(&syntax);
    visitor.check_mixed_concerns();
    Ok(visitor.violations())
}
