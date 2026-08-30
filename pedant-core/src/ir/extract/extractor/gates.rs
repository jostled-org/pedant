//! The `#[cfg(…)]` gates in scope while the traversal walks.

use std::sync::Arc;

use crate::ir::cfg::{cfg_list, predicate_text};

/// One `#[cfg(…)]` gate in scope during traversal.
pub(in crate::ir::extract) struct CfgGate {
    /// Rendered predicate text: the identity of a build alternative.
    pub(in crate::ir::extract) predicate: Arc<str>,
    /// Feature name when the predicate is exactly `feature = "…"`.
    pub(in crate::ir::extract) feature: Option<Arc<str>>,
}

/// Build a gate from an attribute, or `None` when it is not a `#[cfg(…)]`.
///
/// The attribute is recognized once and both fields come off the one list it
/// yields. Asking twice — a render here and a fresh `parse_args` there — let the
/// two fields describe different attributes, since each test stood on its own.
pub(in crate::ir::extract) fn cfg_gate(attr: &syn::Attribute) -> Option<CfgGate> {
    let list = cfg_list(attr)?;
    Some(CfgGate {
        predicate: predicate_text(list),
        feature: feature_name(list),
    })
}

/// The feature a predicate names when it is exactly `feature = "…"`.
///
/// The direct form alone: a nested `all(…)` or `any(…)` states more than one
/// alternative, and this field answers for a single feature gate.
fn feature_name(list: &syn::MetaList) -> Option<Arc<str>> {
    let name_value = list.parse_args::<syn::MetaNameValue>().ok()?;
    match (name_value.path.is_ident("feature"), &name_value.value) {
        (
            true,
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(feature),
                ..
            }),
        ) => Some(Arc::from(feature.value())),
        _ => None,
    }
}
