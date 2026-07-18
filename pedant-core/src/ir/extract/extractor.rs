//! The extractor: fact storage, traversal context, and the emit helpers the
//! visitor drives.
//!
//! [`IrExtractor`] owns the fact vectors and the position of the traversal
//! (nesting depths, the enclosing `impl`, the active `cfg` gates). Two
//! sub-responsibilities live in their own types: [`FnScope`] classifies
//! bindings within the body under traversal, and [`UsePathCollector`] gathers
//! qualified paths. The `syn::visit::Visit` implementation that calls into all
//! of this is in [`super::visitor`].

use std::rc::Rc;
use std::sync::Arc;

use syn::visit::Visit;
use syn::{FnArg, ReturnType, Signature, Type};

use crate::ir::type_introspection::{
    classify_type_ref, collect_signature_type_names_into, first_pat_ident, for_each_pat_ident,
    get_type_span_start,
};
use crate::pattern::extract_type_text;

use crate::ir::facts::{
    AttributeFact, BindingFact, BranchContext, ControlFlowFact, ControlFlowKind, ElseInfo,
    ExternBlockFact, FileIr, FnFact, ImplFact, IrSpan, MacroFact, MethodCallFact, ModuleFact,
    ParamFact, StringLitFact, TypeDefFact, TypeDefKind, TypeInfo, TypeRefContext, TypeRefFact,
    UnsafeFact, UnsafeKind, Visibility,
};

use super::fn_scope::FnScope;
use super::syn_helpers::{
    block_line_count, cfg_feature_name, cfg_predicate, normalize_visibility, span_from,
};
use super::use_paths::UsePathCollector;

/// Single-pass AST visitor that populates a [`FileIr`] from a parsed source file.
///
/// When `semantic` is `Some`, a second enrichment pass resolves type aliases
/// and marks `Copy` receivers.
pub fn extract(
    file_path: &str,
    syntax: &syn::File,
    semantic: Option<&crate::ir::semantic::SemanticContext>,
) -> FileIr {
    let mut extractor = IrExtractor::new(file_path);
    extractor.visit_file(syntax);
    #[cfg(feature = "semantic")]
    {
        let mut ir = extractor.finalize();
        if let Some(ctx) = semantic {
            super::enrich::enrich_ir(&mut ir, ctx);
        }
        ir
    }
    #[cfg(not(feature = "semantic"))]
    {
        _ = semantic;
        extractor.finalize()
    }
}

pub(super) struct IrExtractor {
    file_path: Arc<str>,
    pub(super) functions: Vec<FnFact>,
    type_defs: Vec<TypeDefFact>,
    pub(super) impl_blocks: Vec<ImplFact>,
    control_flow: Vec<ControlFlowFact>,
    bindings: Vec<BindingFact>,
    type_refs: Vec<TypeRefFact>,
    pub(super) method_calls: Vec<MethodCallFact>,
    pub(super) macro_invocations: Vec<MacroFact>,
    pub(super) attributes: Vec<AttributeFact>,
    pub(super) string_literals: Vec<StringLitFact>,
    pub(super) unsafe_sites: Vec<UnsafeFact>,
    pub(super) extern_blocks: Vec<ExternBlockFact>,
    pub(super) modules: Vec<ModuleFact>,

    // Traversal state
    pub(super) depth: usize,
    pub(super) loop_depth: usize,
    pub(super) branch_context: Option<BranchContext>,
    pub(super) item_depth: usize,

    /// Enclosing impl context: (self type, is_trait_impl). Set while visiting an
    /// `impl` block so methods can be tagged with their type and inherent-ness.
    pub(super) current_impl: Option<(Rc<str>, bool)>,

    /// `#[cfg(…)]` gates currently in scope, pushed on entry to a gated
    /// item/module and popped on exit.
    cfg_gates: Vec<CfgGate>,

    /// Suppresses Body-context emission inside signature/field type visits.
    pub(super) in_non_body_type: bool,

    /// Classification state for the function body under traversal.
    pub(super) fn_scope: FnScope,

    /// Qualified paths referenced by this file.
    pub(super) use_paths: UsePathCollector,
}

/// One `#[cfg(…)]` gate in scope during traversal.
pub(super) struct CfgGate {
    /// Rendered predicate text: the identity of a build alternative.
    predicate: Rc<str>,
    /// Feature name when the predicate is exactly `feature = "…"`.
    feature: Option<Rc<str>>,
}

/// Build a gate from an attribute, or `None` when it is not a `#[cfg(…)]`.
fn cfg_gate(attr: &syn::Attribute) -> Option<CfgGate> {
    Some(CfgGate {
        predicate: cfg_predicate(attr)?,
        feature: cfg_feature_name(attr),
    })
}

impl IrExtractor {
    pub(super) fn new(file_path: &str) -> Self {
        Self {
            file_path: Arc::from(file_path),
            functions: Vec::new(),
            type_defs: Vec::new(),
            impl_blocks: Vec::new(),
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
            current_impl: None,
            cfg_gates: Vec::new(),
            in_non_body_type: false,
            fn_scope: FnScope::new(),
            use_paths: UsePathCollector::new(),
        }
    }

    pub(super) fn finalize(self) -> FileIr {
        FileIr {
            file_path: self.file_path,
            source_line_count: 0,
            functions: self.functions.into_boxed_slice(),
            type_defs: self.type_defs.into_boxed_slice(),
            impl_blocks: self.impl_blocks.into_boxed_slice(),
            use_paths: self.use_paths.finish(),
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
            data_flows: Arc::from([]),
        }
    }

    /// Record a function signature as a [`FnFact`], returning its index. Body
    /// derived fields are filled in later by the caller.
    pub(super) fn push_fn(&mut self, sig: &Signature, is_associated: bool) -> usize {
        let name: Box<str> = sig.ident.to_string().into_boxed_str();
        let span = span_from(sig.ident.span().start());
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
            body_line_count: 0,
            is_associated,
            inherent_method_of: None,
            is_pure_forwarder: false,
            visibility: Visibility::Private,
            cfg_feature_gates: self.cfg_feature_gates(),
            cfg_predicates: self.cfg_predicates(),
        });
        index
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

    /// Record a binding, stamping it with the current loop depth and function.
    pub(super) fn push_binding_fact(
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
            containing_fn: self.fn_scope.current(),
            type_annotation_span,
            resolved_type: None,
        });
    }

    /// Record a type reference, classifying it for the dispatch/hasher checks.
    pub(super) fn push_type_ref(
        &mut self,
        ty: &Type,
        context: TypeRefContext,
        containing_fn: Option<usize>,
    ) {
        let span = span_from(get_type_span_start(ty));
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

    /// Record a control-flow construct at `depth`, stamping it with the
    /// surrounding loop depth, branch context, and function.
    pub(super) fn push_control_flow(
        &mut self,
        kind: ControlFlowKind,
        span: IrSpan,
        depth: usize,
        else_info: Option<ElseInfo>,
    ) {
        self.control_flow.push(ControlFlowFact {
            kind,
            span,
            depth,
            loop_depth: self.loop_depth,
            parent_branch: self.branch_context,
            else_info,
            containing_fn: self.fn_scope.current(),
        });
    }

    pub(super) fn emit_signature_type_refs(&mut self, sig: &Signature, fn_index: usize) {
        if let ReturnType::Type(_, ty) = &sig.output {
            self.push_type_ref(ty, TypeRefContext::Return, Some(fn_index));
        }
        for input in &sig.inputs {
            let FnArg::Typed(pt) = input else { continue };
            self.push_type_ref(&pt.ty, TypeRefContext::Param, Some(fn_index));
        }
    }

    pub(super) fn record_unsafe_fn(&mut self, sig: &Signature) {
        if let Some(token) = sig.unsafety {
            self.unsafe_sites.push(UnsafeFact {
                kind: UnsafeKind::Fn,
                span: span_from(token.span.start()),
                evidence: "unsafe fn".into(),
            });
        }
    }

    /// Push any `#[cfg(feature = "…")]` gates from `attrs`, run `body`, then pop.
    /// Items recorded inside `body` snapshot the active gate stack.
    pub(super) fn with_cfg_gates<R>(
        &mut self,
        attrs: &[syn::Attribute],
        body: impl FnOnce(&mut Self) -> R,
    ) -> R {
        let start = self.cfg_gates.len();
        self.cfg_gates.extend(attrs.iter().filter_map(cfg_gate));
        let result = body(self);
        self.cfg_gates.truncate(start);
        result
    }

    /// Feature names of the `#[cfg(feature = "…")]` gates in scope.
    pub(super) fn cfg_feature_gates(&self) -> Box<[Rc<str>]> {
        self.cfg_gates
            .iter()
            .filter_map(|gate| gate.feature.clone())
            .collect()
    }

    /// Predicates of every `#[cfg(…)]` gate in scope, of any kind.
    pub(super) fn cfg_predicates(&self) -> Box<[Rc<str>]> {
        self.cfg_gates
            .iter()
            .map(|gate| Rc::clone(&gate.predicate))
            .collect()
    }

    /// [`Self::cfg_predicates`] plus those on `attrs`, for facts recorded
    /// before the traversal has pushed the item's own gates.
    pub(super) fn cfg_predicates_with(&self, attrs: &[syn::Attribute]) -> Box<[Rc<str>]> {
        self.cfg_gates
            .iter()
            .map(|gate| Rc::clone(&gate.predicate))
            .chain(attrs.iter().filter_map(cfg_predicate))
            .collect()
    }

    fn register_type_with_edges(
        &mut self,
        name: Rc<str>,
        kind: TypeDefKind,
        span: IrSpan,
        visibility: Visibility,
        edges: Box<[(Rc<str>, Rc<str>)]>,
    ) {
        self.type_defs.push(TypeDefFact {
            name,
            span,
            kind,
            visibility,
            cfg_feature_gates: self.cfg_feature_gates(),
            edges,
        });
    }

    /// Shared scaffolding for type-def visitors: extract name/span from ident,
    /// compute edges via the provided closure, register the type def, and wrap
    /// the syn visit dispatch in item_depth guards.
    pub(super) fn visit_type_def(
        &mut self,
        ident: &syn::Ident,
        kind: TypeDefKind,
        vis: &syn::Visibility,
        attrs: &[syn::Attribute],
        compute_edges: impl FnOnce(&Rc<str>) -> Box<[(Rc<str>, Rc<str>)]>,
        visit: impl FnOnce(&mut Self),
    ) {
        let name: Rc<str> = Rc::from(ident.to_string());
        let span = span_from(ident.span().start());
        let edges = compute_edges(&name);
        let visibility = normalize_visibility(vis);
        self.with_cfg_gates(attrs, |this| {
            this.register_type_with_edges(name, kind, span, visibility, edges);
            this.item_depth += 1;
            visit(this);
            this.item_depth -= 1;
        });
    }

    /// Shared scaffolding for loop visitors: increment depth + loop_depth,
    /// push a control flow fact, run the body callback, then decrement.
    pub(super) fn visit_loop_body(
        &mut self,
        kind: ControlFlowKind,
        span: IrSpan,
        body: impl FnOnce(&mut Self),
    ) {
        self.depth += 1;
        self.loop_depth += 1;
        self.push_control_flow(kind, span, self.depth, None);
        body(self);
        self.loop_depth -= 1;
        self.depth -= 1;
    }

    /// Shared scaffolding for function-body visitors: record the signature,
    /// swap in a fresh [`FnScope`], run the body callback, then resolve the
    /// body-derived fields before restoring the enclosing scope.
    pub(super) fn visit_fn_body(
        &mut self,
        sig: &Signature,
        body: &syn::Block,
        is_associated: bool,
        increment_depth: bool,
        visit: impl FnOnce(&mut Self),
    ) -> usize {
        let fn_index = self.push_fn(sig, is_associated);
        self.functions[fn_index].body_line_count = block_line_count(body);
        self.emit_signature_type_refs(sig, fn_index);

        let saved = self.fn_scope.enter(fn_index);
        let binding_start = self.bindings.len();

        self.record_fn_param_bindings(sig);
        self.fn_scope.record_refcounted_params(sig);

        if increment_depth {
            self.item_depth += 1;
        }

        visit(self);

        // Store body type edges for mixed-concerns analysis.
        if self.item_depth == 1 {
            self.functions[fn_index].body_type_edges = self.fn_scope.body_type_edges();
        }

        // Resolve is_refcounted from the scope's classification sets.
        for binding in &mut self.bindings[binding_start..] {
            if binding.is_wildcard {
                continue;
            }
            binding.is_refcounted = self.fn_scope.is_refcounted(&binding.name);
        }

        if increment_depth {
            self.item_depth -= 1;
        }

        self.fn_scope.leave(saved);
        fn_index
    }
}
