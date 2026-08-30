//! What one `impl` block contributes to the fact tables.

use std::sync::Arc;

use crate::graph::extend_edges_from_names;
use crate::ir::facts::{ImplFact, IrSpan};
use crate::ir::type_introspection::collect_signature_type_names_into;

/// Record one `impl` block: the trait it names, and the pairwise type edges its
/// methods create for mixed-concerns analysis.
pub(super) fn impl_fact(
    node: &syn::ItemImpl,
    position: (&Arc<str>, IrSpan, Box<[Arc<str>]>),
) -> ImplFact {
    let (self_name, span, cfg_predicates) = position;
    let trait_name = trait_name(node);
    ImplFact {
        self_type: Arc::clone(self_name),
        edges: edges(node, self_name, trait_name.as_deref()),
        trait_name,
        span,
        cfg_predicates,
    }
}

fn trait_name(node: &syn::ItemImpl) -> Option<Box<str>> {
    node.trait_
        .as_ref()
        .and_then(|(_, path, _)| path.segments.last())
        .map(|segment| segment.ident.to_string().into_boxed_str())
}

fn edges(
    node: &syn::ItemImpl,
    self_name: &Arc<str>,
    trait_name: Option<&str>,
) -> Box<[(Arc<str>, Arc<str>)]> {
    let mut edges: Vec<(Arc<str>, Arc<str>)> = trait_name
        .map(|named| (Arc::clone(self_name), Arc::from(named)))
        .into_iter()
        .collect();
    let mut names = Vec::new();
    for item in &node.items {
        let syn::ImplItem::Fn(method) = item else {
            continue;
        };
        names.clear();
        collect_signature_type_names_into(&method.sig, &mut names);
        extend_edges_from_names(self_name, &names, &mut edges);
    }
    edges.into_boxed_slice()
}
