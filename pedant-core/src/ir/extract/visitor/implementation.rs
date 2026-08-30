use std::sync::Arc;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{ExprIf, Signature, Type};

use crate::ir::type_introspection::{
    first_type_name, for_each_pat_ident, get_type_span_start, iter_expr_ident,
};
use pedant_types::SymbolKind;

use crate::pattern::{extract_attribute_text, extract_macro_text, extract_method_call_text};

use crate::ir::facts::{
    AttributeFact, BranchContext, ControlFlowKind, ElseInfo, ExternBlockFact, MacroFact,
    MethodCallFact, ModuleFact, StringLitFact, TypeAliasFact, TypeDefKind, TypeRefContext,
};

use super::super::extent::DeclarationExtent;
use super::super::extractor::{IrExtractor, TypeDefinition, ValueItem};
use super::super::impls::impl_fact;
use super::super::locals::record_binding;
use super::super::site_visitor::{
    current_self_type, current_trait, enter_function, enter_module, leave_function,
    record_expression_path, record_implementation, record_import, record_macro, record_method_call,
    record_struct_literal, record_type_path, type_scope,
};
use super::super::syn_helpers::{
    count_else_chain, is_cfg_test_attr, is_pure_forwarder, normalize_visibility, span_from,
};
use super::super::type_edges::{alias_edges, enum_edges, struct_edges, trait_edges, union_edges};
use super::super::unsafe_sites::{record_unsafe_block, record_unsafe_fn, record_unsafe_impl};

/// Define one type-definition visit per row.
///
/// Every row is `visit_fn(SynType) => Kind via edges`, and every body is the
/// same: state the identifier, its rendered name, the kind, visibility,
/// attributes, and whole extent the source writes, compute that type's
/// relationship edges, then walk what it holds. The trait row is written out
/// below, because a trait also carries its own name into the items it declares.
macro_rules! type_definitions {
    ($($visit:ident($item:ty) => $kind:ident via $edges:ident;)*) => {
        $(
            fn $visit(&mut self, node: &'ast $item) {
                self.visit_type_def(
                    TypeDefinition {
                        ident: &node.ident,
                        name: type_scope(&node.ident),
                        kind: TypeDefKind::$kind,
                        visibility: &node.vis,
                        attrs: &node.attrs,
                        declaration: node.extent(),
                    },
                    |name| $edges(node, name),
                    |s| syn::visit::$visit(s, node),
                );
            }
        )*
    };
}

/// Define one value-item visit per row.
///
/// Two groups, because the owner is the only difference. A `free` row expands
/// with a literal `None`: a method body sitting in an `impl` does not make a
/// `const` declared beside it an associated one. An `owned` row names a reader
/// of the traversal state — the enclosing `impl` self type or trait — as a
/// function rather than an expression, because a row cannot name `self`: macro
/// hygiene binds that to the call site, not to the body it expands into.
///
/// Only the free type alias is written out below, because it states
/// relationship edges as well as a site.
macro_rules! value_items {
    (free { $($free:ident($free_item:ty) => $free_kind:ident;)* }
     owned { $($owned:ident($owned_item:ty) => $owned_kind:ident owned_by $owner:path;)* }) => {
        $(value_items!(@row $free($free_item) => $free_kind,);)*
        $(value_items!(@row $owned($owned_item) => $owned_kind, $owner);)*
    };
    (@row $visit:ident($item:ty) => $kind:ident, $($owner:path)?) => {
        fn $visit(&mut self, node: &'ast $item) {
            let associated_with = value_items!(@owner $($owner(self))?);
            self.visit_value_item(
                ValueItem {
                    ident: &node.ident,
                    kind: SymbolKind::$kind,
                    attrs: &node.attrs,
                    associated_with,
                    declaration: node.extent(),
                },
                |this| syn::visit::$visit(this, node),
            );
        }
    };
    (@owner) => { None };
    (@owner $stated:expr) => { $stated };
}

impl<'ast> Visit<'ast> for IrExtractor {
    fn visit_signature(&mut self, node: &'ast Signature) {
        self.in_non_body_type = true;
        syn::visit::visit_signature(self, node);
        self.in_non_body_type = false;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        record_unsafe_fn(self, &node.sig);
        self.with_cfg_gates(&node.attrs, |this| {
            let entry = enter_function(this, &node.sig, None, node.extent());
            let fn_index = this.visit_fn_body(&node.sig, &node.block, false, true, |inner| {
                syn::visit::visit_item_fn(inner, node);
            });
            this.functions[fn_index].visibility = normalize_visibility(&node.vis);
            leave_function(this, entry);
        });
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        record_unsafe_fn(self, &node.sig);
        self.with_cfg_gates(&node.attrs, |this| {
            let owner = current_self_type(this);
            let entry = enter_function(this, &node.sig, owner, node.extent());
            let fn_index = this.visit_fn_body(&node.sig, &node.block, true, false, |inner| {
                syn::visit::visit_impl_item_fn(inner, node);
            });
            this.functions[fn_index].visibility = normalize_visibility(&node.vis);
            // Only inherent impls (is_trait_impl == false) contribute to a type's
            // own method surface.
            if let Some((self_type, false)) = &this.current_impl {
                this.functions[fn_index].inherent_method_of = Some(Arc::clone(self_type));
            }
            this.functions[fn_index].is_pure_forwarder = is_pure_forwarder(&node.block);
            leave_function(this, entry);
        });
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.with_cfg_gates(&node.attrs, |this| {
            let owner = current_trait(this);
            let entry = enter_function(this, &node.sig, owner, node.extent());
            match &node.default {
                Some(body) => {
                    record_unsafe_fn(this, &node.sig);
                    this.visit_fn_body(&node.sig, body, true, false, |inner| {
                        syn::visit::visit_trait_item_fn(inner, node);
                    });
                }
                // A bodiless declaration is still a callable in the inventory,
                // so its own attributes and signature name it as their owner
                // exactly as a defaulted method's do.
                None => {
                    let fn_index = this.push_fn(&node.sig, true);
                    this.emit_signature_type_refs(&node.sig, fn_index);
                    let saved = this.fn_scope.enter(fn_index);
                    syn::visit::visit_trait_item_fn(this, node);
                    this.fn_scope.leave(saved);
                }
            }
            leave_function(this, entry);
        });
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
        record_unsafe_block(self, node.unsafe_token.span.start());
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        record_unsafe_impl(self, node.unsafety);

        let span = span_from(get_type_span_start(&node.self_ty));

        let Some(self_name) = first_type_name(&node.self_ty) else {
            self.within_impl_block(node, |this| {
                syn::visit::visit_item_impl(this, node);
            });
            return;
        };

        // The block's own attributes are not on the gate stack yet.
        let cfg_predicates = self.cfg_predicates_with(&node.attrs);
        let fact = impl_fact(node, (&self_name, span, cfg_predicates));
        let is_trait_impl = fact.trait_name.is_some();
        self.impl_blocks.push(fact);

        let saved_impl = self.current_impl.replace((self_name, is_trait_impl));
        self.within_impl_block(node, |this| {
            record_implementation(this, node);
            syn::visit::visit_item_impl(this, node);
        });
        self.current_impl = saved_impl;
    }

    type_definitions! {
        visit_item_struct(syn::ItemStruct) => Struct via struct_edges;
        visit_item_enum(syn::ItemEnum) => Enum via enum_edges;
        visit_item_union(syn::ItemUnion) => Union via union_edges;
    }

    /// A trait carries its own name into the items it declares, so the row
    /// scaffolding is wrapped rather than written out a fourth time.
    ///
    /// The scope and fact table share one name handle.
    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let name = type_scope(&node.ident);
        let saved_trait = self.current_trait.replace(Arc::clone(&name));
        self.visit_type_def(
            TypeDefinition {
                ident: &node.ident,
                name,
                kind: TypeDefKind::Trait,
                visibility: &node.vis,
                attrs: &node.attrs,
                declaration: node.extent(),
            },
            |name| trait_edges(node, name),
            |s| syn::visit::visit_item_trait(s, node),
        );
        self.current_trait = saved_trait;
    }

    value_items! {
        free {
            visit_item_const(syn::ItemConst) => Constant;
            visit_item_static(syn::ItemStatic) => Static;
        }
        owned {
            visit_impl_item_const(syn::ImplItemConst) => Constant owned_by current_self_type;
            visit_impl_item_type(syn::ImplItemType) => TypeAlias owned_by current_self_type;
            visit_trait_item_const(syn::TraitItemConst) => Constant owned_by current_trait;
            visit_trait_item_type(syn::TraitItemType) => TypeAlias owned_by current_trait;
        }
    }

    /// A free type alias states relationship edges before it states a site, so
    /// it carries that one extra line rather than joining the table above.
    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        let name = type_scope(&node.ident);
        self.type_aliases.push(TypeAliasFact {
            edges: alias_edges(node, &name),
            name,
        });
        self.visit_value_item(
            ValueItem {
                ident: &node.ident,
                kind: SymbolKind::TypeAlias,
                attrs: &node.attrs,
                associated_with: None,
                declaration: node.extent(),
            },
            |this| syn::visit::visit_item_type(this, node),
        );
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        record_import(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let callee = match node.func.as_ref() {
            syn::Expr::Path(path) => {
                record_expression_path(self, &path.path, true);
                true
            }
            _ => false,
        };
        let saved = std::mem::replace(&mut self.in_callee, callee);
        syn::visit::visit_expr_call(self, node);
        self.in_callee = saved;
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        match self.in_callee {
            true => self.in_callee = false,
            false => record_expression_path(self, &node.path, false),
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        record_type_path(self, node);
        syn::visit::visit_type_path(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        self.with_cfg_gates(&node.attrs, |this| {
            record_binding(this, node);
            syn::visit::visit_local(this, node);
        });
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

        self.attributes.push(AttributeFact {
            text,
            span,
            name,
            containing_fn: self.fn_scope.current(),
        });

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
        record_struct_literal(self, node);
        match self.item_depth {
            0 => {}
            _ => self.fn_scope.collect_body_type(&node.path),
        }
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        record_method_call(self, node);
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

        record_macro(self, node);
        self.macro_invocations.push(MacroFact { text, span });

        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_lit(&mut self, node: &'ast syn::ExprLit) {
        if let syn::Lit::Str(ref lit_str) = node.lit {
            let value: Box<str> = lit_str.value().into_boxed_str();
            self.string_literals.push(StringLitFact {
                value,
                span: span_from(lit_str.span().start()),
                containing_fn: self.fn_scope.current(),
            });
        }
        syn::visit::visit_expr_lit(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let start = node.abi.extern_token.span.start();
        self.extern_blocks.push(ExternBlockFact {
            span: span_from(start),
            containing_fn: self.fn_scope.current(),
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
            let saved = enter_module(this, node, node.extent());
            syn::visit::visit_item_mod(this, node);
            this.sites.restore(saved);
        });
    }
}
