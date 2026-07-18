//! AST traversal: the `syn::visit::Visit` dispatch that drives [`IrExtractor`].
//!
//! Each override records the facts its node carries, then delegates to the
//! default `syn::visit::visit_*` to continue the walk. Nodes that open a scope
//! (functions, loops, branches, impls) bracket that delegation with the
//! extractor's scaffolding so nesting state unwinds correctly.

use std::rc::Rc;

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{ExprIf, Signature, Type};

use crate::graph::extend_edges_from_names;
use crate::ir::type_introspection::{
    collect_signature_type_names_into, collect_type_names_into, first_type_name,
    for_each_pat_ident, get_type_span_start, iter_expr_ident,
};
use crate::pattern::{extract_attribute_text, extract_macro_text, extract_method_call_text};

use crate::ir::facts::{
    AttributeFact, BranchContext, ControlFlowKind, ElseInfo, ExternBlockFact, ImplFact, MacroFact,
    MethodCallFact, ModuleFact, StringLitFact, TypeDefKind, TypeRefContext, UnsafeFact, UnsafeKind,
};

use super::extractor::IrExtractor;
use super::syn_helpers::{
    count_else_chain, for_each_pat_ident_span, is_cfg_test_attr, is_pure_forwarder,
    normalize_visibility, span_from,
};

impl<'ast> Visit<'ast> for IrExtractor {
    fn visit_signature(&mut self, node: &'ast Signature) {
        self.in_non_body_type = true;
        syn::visit::visit_signature(self, node);
        self.in_non_body_type = false;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.record_unsafe_fn(&node.sig);
        self.with_cfg_gates(&node.attrs, |this| {
            let fn_index = this.visit_fn_body(&node.sig, &node.block, false, true, |inner| {
                syn::visit::visit_item_fn(inner, node);
            });
            this.functions[fn_index].visibility = normalize_visibility(&node.vis);
        });
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.record_unsafe_fn(&node.sig);
        self.with_cfg_gates(&node.attrs, |this| {
            let fn_index = this.visit_fn_body(&node.sig, &node.block, true, false, |inner| {
                syn::visit::visit_impl_item_fn(inner, node);
            });
            this.functions[fn_index].visibility = normalize_visibility(&node.vis);
            // Only inherent impls (is_trait_impl == false) contribute to a type's
            // own method surface.
            if let Some((self_type, false)) = &this.current_impl {
                this.functions[fn_index].inherent_method_of = Some(Rc::clone(self_type));
            }
            this.functions[fn_index].is_pure_forwarder = is_pure_forwarder(&node.block);
        });
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        match &node.default {
            Some(body) => {
                self.record_unsafe_fn(&node.sig);
                self.visit_fn_body(&node.sig, body, true, false, |this| {
                    syn::visit::visit_trait_item_fn(this, node);
                });
            }
            None => {
                let fn_index = self.push_fn(&node.sig, true);
                self.emit_signature_type_refs(&node.sig, fn_index);
                syn::visit::visit_trait_item_fn(self, node);
            }
        }
    }

    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        let span = span_from(node.if_token.span.start());

        let else_info = node.else_branch.as_ref().map(|(else_token, _)| {
            let chain_len = match self.branch_context {
                Some(BranchContext::If) => None,
                _ => Some(count_else_chain(node)),
            };
            ElseInfo {
                chain_len,
                span: Some(span_from(else_token.span.start())),
            }
        });

        self.push_control_flow(ControlFlowKind::If, span, self.depth + 1, else_info);

        self.depth += 1;
        let old_context = self.branch_context;
        self.branch_context = Some(BranchContext::If);
        syn::visit::visit_expr_if(self, node);
        self.branch_context = old_context;
        self.depth -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let span = span_from(node.match_token.span.start());

        self.push_control_flow(ControlFlowKind::Match, span, self.depth + 1, None);

        self.depth += 1;
        let old_context = self.branch_context;
        self.branch_context = Some(BranchContext::Match);
        syn::visit::visit_expr_match(self, node);
        self.branch_context = old_context;
        self.depth -= 1;
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        let span = span_from(node.for_token.span.start());
        self.visit_loop_body(ControlFlowKind::ForLoop, span, |s| {
            // Record pat names for naming check
            for_each_pat_ident(&node.pat, &mut |name| {
                s.push_binding_fact(name, None, false, false, false, None);
            });
            s.fn_scope
                .record_refcounted_loop_bindings(&node.pat, &node.expr);
            syn::visit::visit_expr_for_loop(s, node);
        });
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        let span = span_from(node.while_token.span.start());
        self.visit_loop_body(ControlFlowKind::WhileLoop, span, |s| {
            syn::visit::visit_expr_while(s, node);
        });
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        let span = span_from(node.loop_token.span.start());
        self.visit_loop_body(ControlFlowKind::Loop, span, |s| {
            syn::visit::visit_expr_loop(s, node);
        });
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        let span = span_from(node.or1_token.span.start());

        // A closure is a value, not a control-flow nesting level: a combinator
        // chain like `.or_else(|| …).map(|pos| …)` is flat code. Record the fact
        // at the current depth so structural fingerprints still see the closure,
        // but don't increment — control flow *inside* the body counts from here.
        self.push_control_flow(ControlFlowKind::Closure, span, self.depth, None);
        syn::visit::visit_expr_closure(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        let start = node.unsafe_token.span.start();
        self.unsafe_sites.push(UnsafeFact {
            kind: UnsafeKind::Block,
            span: span_from(start),
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
                span: span_from(start),
                evidence: "unsafe impl".into(),
            });
        }

        let span = span_from(get_type_span_start(&node.self_ty));

        let Some(self_name) = first_type_name(&node.self_ty) else {
            self.item_depth += 1;
            self.with_cfg_gates(&node.attrs, |this| {
                syn::visit::visit_item_impl(this, node);
            });
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

        let is_trait_impl = trait_name.is_some();
        // The block's own attributes are not on the gate stack yet.
        let cfg_predicates = self.cfg_predicates_with(&node.attrs);
        self.impl_blocks.push(ImplFact {
            self_type: Rc::clone(&self_name),
            trait_name,
            span,
            cfg_predicates,
            edges: edges.into_boxed_slice(),
        });

        let saved_impl = self.current_impl.replace((self_name, is_trait_impl));
        self.item_depth += 1;
        self.with_cfg_gates(&node.attrs, |this| {
            syn::visit::visit_item_impl(this, node);
        });
        self.item_depth -= 1;
        self.current_impl = saved_impl;
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.visit_type_def(
            &node.ident,
            TypeDefKind::Struct,
            &node.vis,
            &node.attrs,
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
            &node.vis,
            &node.attrs,
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
            &node.vis,
            &node.attrs,
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

    fn visit_item_union(&mut self, node: &'ast syn::ItemUnion) {
        self.visit_type_def(
            &node.ident,
            TypeDefKind::Union,
            &node.vis,
            &node.attrs,
            |name| {
                let mut edges = Vec::new();
                let mut type_names = Vec::new();
                for field in &node.fields.named {
                    type_names.clear();
                    collect_type_names_into(&field.ty, &mut type_names);
                    extend_edges_from_names(name, &type_names, &mut edges);
                }
                edges.into_boxed_slice()
            },
            |s| syn::visit::visit_item_union(s, node),
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
        let span = span_from(node.use_token.span.start());
        self.use_paths.collect_use_tree(&node.tree, span);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        self.use_paths.emit_multi_segment_path(&node.path);
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        self.fn_scope.record_string_binding(&node.pat);
        self.fn_scope.record_refcounted_from_pat(&node.pat);

        // Wildcard binding
        if let syn::Pat::Wild(w) = &node.pat {
            let init_is_write = node
                .init
                .as_ref()
                .map(|init| self.fn_scope.is_write_macro_to_string(&init.expr))
                .unwrap_or(false);

            let span = span_from(w.underscore_token.span.start());
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
        for_each_pat_ident_span(&node.pat, None, &mut |name, span, type_ann_span| {
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
        if let (true, Some(fn_idx)) = (is_arithmetic, self.fn_scope.current()) {
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
        let span = span_from(node.pound_token.spans[0].start());
        let name: Box<str> = last_seg.ident.to_string().into_boxed_str();

        self.attributes.push(AttributeFact { text, span, name });

        syn::visit::visit_attribute(self, node);
    }

    fn visit_type(&mut self, node: &'ast Type) {
        if !self.in_non_body_type {
            self.push_type_ref(node, TypeRefContext::Body, self.fn_scope.current());
        }
        // Body type collection is scoped to items nested inside a function.
        match (self.item_depth, node) {
            (0, _) => {}
            (_, Type::Path(tp)) => self.fn_scope.collect_body_type(&tp.path),
            _ => {}
        }
        syn::visit::visit_type(self, node);
    }

    fn visit_field(&mut self, node: &'ast syn::Field) {
        self.push_type_ref(&node.ty, TypeRefContext::Field, self.fn_scope.current());
        self.in_non_body_type = true;
        syn::visit::visit_field(self, node);
        self.in_non_body_type = false;
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        match self.item_depth {
            0 => {}
            _ => self.fn_scope.collect_body_type(&node.path),
        }
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let text = extract_method_call_text(node);
        let span = span_from(node.dot_token.span.start());
        let receiver_span = span_from(node.receiver.span().start());
        let method_name: Box<str> = node.method.to_string().into_boxed_str();
        let recv = iter_expr_ident(&node.receiver).map(|i| i.to_string().into_boxed_str());

        self.method_calls.push(MethodCallFact {
            method_name,
            text,
            span,
            receiver_ident: recv,
            receiver_span,
            loop_depth: self.loop_depth,
            containing_fn: self.fn_scope.current(),
            receiver_type: None,
            is_copy_receiver: false,
        });

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let Some(first_seg) = node.path.segments.first() else {
            return;
        };
        let span = span_from(first_seg.ident.span().start());
        let text = extract_macro_text(node);

        self.macro_invocations.push(MacroFact { text, span });

        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_lit(&mut self, node: &'ast syn::ExprLit) {
        if let syn::Lit::Str(ref lit_str) = node.lit {
            let value: Box<str> = lit_str.value().into_boxed_str();
            self.string_literals.push(StringLitFact {
                value,
                span: span_from(lit_str.span().start()),
            });
        }
        syn::visit::visit_expr_lit(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let start = node.abi.extern_token.span.start();
        self.extern_blocks.push(ExternBlockFact {
            span: span_from(start),
        });
        syn::visit::visit_item_foreign_mod(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let has_cfg_test = node.attrs.iter().any(is_cfg_test_attr);
        let span = span_from(node.mod_token.span.start());
        self.modules.push(ModuleFact {
            name: node.ident.to_string().into_boxed_str(),
            span,
            is_cfg_test: has_cfg_test,
            cfg_predicates: self.cfg_predicates_with(&node.attrs),
        });
        self.with_cfg_gates(&node.attrs, |this| {
            syn::visit::visit_item_mod(this, node);
        });
    }
}
