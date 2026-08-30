//! Normalized conditional-compilation predicates carried by IR sites.
//!
//! A condition is the unevaluated conjunction of every `#[cfg(…)]` predicate,
//! and every `cfg_attr` branch able to add one, that guards a site or any
//! lexical owner above it. Predicates are sorted and deduplicated, so two
//! traversals of the same source produce the same condition. Nothing here
//! decides whether a predicate holds: this tier chooses no feature or platform
//! universe, so it records structure and never evaluates satisfiability.

use std::sync::Arc;

use quote::ToTokens;

/// The conjunction of the predicates guarding one site. Empty is unconditional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustCfgCondition {
    predicates: Arc<[Arc<str>]>,
}

impl Default for RustCfgCondition {
    fn default() -> Self {
        Self {
            predicates: Arc::from(Vec::<Arc<str>>::new()),
        }
    }
}

impl RustCfgCondition {
    /// The condition one already-rendered predicate states.
    pub(crate) fn stated(predicate: &str) -> Self {
        Self::normalized(vec![Arc::from(predicate)])
    }

    /// This condition conjoined with the one `attrs` states.
    pub(crate) fn with(&self, attrs: &[syn::Attribute]) -> Self {
        let stated = predicates_of(attrs);
        match stated.is_empty() {
            true => self.clone(),
            false => Self::normalized(self.predicates.iter().cloned().chain(stated).collect()),
        }
    }

    /// This condition conjoined with `other`.
    pub(crate) fn and(&self, other: &Self) -> Self {
        match (self.is_empty(), other.is_empty()) {
            (true, _) => other.clone(),
            (_, true) => self.clone(),
            _ => Self::normalized(
                self.predicates
                    .iter()
                    .chain(other.predicates.iter())
                    .cloned()
                    .collect(),
            ),
        }
    }

    /// Whether the site this condition guards is in every build of its source.
    pub(crate) fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }

    fn normalized(mut predicates: Vec<Arc<str>>) -> Self {
        predicates.sort();
        predicates.dedup();
        Self {
            predicates: Arc::from(predicates),
        }
    }
}

/// The predicate list one `#[cfg(…)]` attribute writes, or `None` for any other
/// attribute.
///
/// Recognizing the attribute and reaching its predicate is one step, so a reader
/// wanting both the rendered text and something parsed out of the same tokens
/// asks once and derives both from the list it gets back. Two readers each
/// starting from the attribute could disagree about which one they were reading.
pub(crate) fn cfg_list(attr: &syn::Attribute) -> Option<&syn::MetaList> {
    match attr.path().is_ident("cfg") {
        true => attr.meta.require_list().ok(),
        false => None,
    }
}

/// The rendered predicate one `#[cfg(…)]` list states (`unix`,
/// `feature = "x"`, …).
///
/// The text is the identity of a build alternative: items under the same
/// predicate compile together, items under different ones may not. It is kept
/// verbatim, so two predicates that differ only in spelling read as distinct
/// alternatives — which can only cost a detection, never invent one.
pub(crate) fn predicate_text(list: &syn::MetaList) -> Arc<str> {
    Arc::from(list.tokens.to_string().as_str())
}

/// The rendered predicate of a `#[cfg(…)]` attribute, or `None` for any other.
pub(crate) fn cfg_predicate(attr: &syn::Attribute) -> Option<Arc<str>> {
    cfg_list(attr).map(predicate_text)
}

fn predicates_of(attrs: &[syn::Attribute]) -> Vec<Arc<str>> {
    attrs
        .iter()
        .flat_map(|attr| match attr.path().is_ident("cfg_attr") {
            true => conditional_predicates(attr),
            false => cfg_predicate(attr).into_iter().collect(),
        })
        .collect()
}

/// `#[cfg_attr(P, cfg(Q), …)]` adds `cfg(Q)` when `P` holds, so each added
/// `cfg` contributes the conjunction `all(P, Q)`.
fn conditional_predicates(attr: &syn::Attribute) -> Vec<Arc<str>> {
    let Some((gate, applied)) = conditional_attribute(attr) else {
        return Vec::new();
    };
    let rendered = gate.to_token_stream().to_string();
    applied
        .iter()
        .filter_map(added_cfg)
        .map(|added| Arc::from(format!("all({rendered}, {added})").as_str()))
        .collect()
}

/// Split one `#[cfg_attr(P, …)]` into the predicate that gates it and the
/// attributes it would apply, or `None` when the argument list does not parse
/// or states no predicate at all.
///
/// The "first element is the predicate, the rest are attributes" rule is stated
/// here alone. Its two readers ask different questions of the same `cfg_attr` —
/// the conjunction an added `cfg` contributes, and the `#[path]` override a
/// `mod` selects — and a second parse is a second chance to disagree about
/// where the predicate ends. The gate comes back unrendered, because only the
/// condition reader wants it as text.
pub(crate) fn conditional_attribute(
    attr: &syn::Attribute,
) -> Option<(syn::Meta, Box<[syn::Meta]>)> {
    let metas = attr
        .parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
        .ok()?;
    let mut stated = metas.into_iter();
    let gate = stated.next()?;
    Some((gate, stated.collect()))
}

fn added_cfg(meta: &syn::Meta) -> Option<String> {
    let syn::Meta::List(list) = meta else {
        return None;
    };
    list.path.is_ident("cfg").then(|| list.tokens.to_string())
}
