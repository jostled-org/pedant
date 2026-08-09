//! Normalized conditional-compilation predicates carried by IR sites.
//!
//! A condition is the unevaluated conjunction of every `#[cfg(…)]` predicate,
//! and every `cfg_attr` branch able to add one, that guards a site or any
//! lexical owner above it. Predicates are sorted and deduplicated, so two
//! traversals of the same source produce the same condition. Nothing here
//! decides whether a predicate holds: this tier chooses no feature or platform
//! universe, so it records structure and never evaluates satisfiability.

use std::rc::Rc;

use quote::ToTokens;

/// The conjunction of the predicates guarding one site. Empty is unconditional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustCfgCondition {
    predicates: Rc<[Rc<str>]>,
}

impl Default for RustCfgCondition {
    fn default() -> Self {
        Self {
            predicates: Rc::from(Vec::<Rc<str>>::new()),
        }
    }
}

impl RustCfgCondition {
    /// The condition one already-rendered predicate states.
    pub(crate) fn stated(predicate: &str) -> Self {
        Self::normalized(vec![Rc::from(predicate)])
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

    fn normalized(mut predicates: Vec<Rc<str>>) -> Self {
        predicates.sort();
        predicates.dedup();
        Self {
            predicates: Rc::from(predicates),
        }
    }
}

/// The rendered predicate of a `#[cfg(…)]` attribute (`unix`,
/// `feature = "x"`, …), or `None` for any other attribute.
///
/// The text is the identity of a build alternative: items under the same
/// predicate compile together, items under different ones may not. It is kept
/// verbatim, so two predicates that differ only in spelling read as distinct
/// alternatives — which can only cost a detection, never invent one.
pub(crate) fn cfg_predicate(attr: &syn::Attribute) -> Option<Rc<str>> {
    match attr.path().is_ident("cfg") {
        true => attr
            .meta
            .require_list()
            .ok()
            .map(|list| Rc::from(list.tokens.to_string().as_str())),
        false => None,
    }
}

fn predicates_of(attrs: &[syn::Attribute]) -> Vec<Rc<str>> {
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
fn conditional_predicates(attr: &syn::Attribute) -> Vec<Rc<str>> {
    let parsed = attr.parse_args_with(
        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
    );
    let Ok(metas) = parsed else {
        return Vec::new();
    };
    let mut stated = metas.into_iter();
    let Some(gate) = stated.next().map(|meta| meta.to_token_stream().to_string()) else {
        return Vec::new();
    };
    stated
        .filter_map(|meta| added_cfg(&meta))
        .map(|added| Rc::from(format!("all({gate}, {added})").as_str()))
        .collect()
}

fn added_cfg(meta: &syn::Meta) -> Option<String> {
    let syn::Meta::List(list) = meta else {
        return None;
    };
    list.path.is_ident("cfg").then(|| list.tokens.to_string())
}
