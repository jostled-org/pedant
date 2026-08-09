//! Pairwise type-relationship edges one type definition contributes.

use std::rc::Rc;

use crate::graph::extend_edges_from_names;
use crate::ir::type_introspection::{collect_signature_type_names_into, collect_type_names_into};

/// Edges from a struct to the types of its fields.
pub(super) fn struct_edges(node: &syn::ItemStruct, name: &Rc<str>) -> Box<[(Rc<str>, Rc<str>)]> {
    field_edges(node.fields.iter(), name)
}

/// Edges from an enum to the types of every variant's fields.
pub(super) fn enum_edges(node: &syn::ItemEnum, name: &Rc<str>) -> Box<[(Rc<str>, Rc<str>)]> {
    field_edges(
        node.variants.iter().flat_map(|variant| &variant.fields),
        name,
    )
}

/// Edges from a union to the types of its named fields.
pub(super) fn union_edges(node: &syn::ItemUnion, name: &Rc<str>) -> Box<[(Rc<str>, Rc<str>)]> {
    field_edges(node.fields.named.iter(), name)
}

/// Edges from a free alias to every type named by its target and arguments.
pub(super) fn alias_edges(node: &syn::ItemType, name: &Rc<str>) -> Box<[(Rc<str>, Rc<str>)]> {
    let mut names = Vec::new();
    collect_type_names_into(&node.ty, &mut names);
    let mut edges = Vec::new();
    extend_edges_from_names(name, &names, &mut edges);
    edges.into_boxed_slice()
}

/// Edges from a trait to the types in its methods' signatures.
pub(super) fn trait_edges(node: &syn::ItemTrait, name: &Rc<str>) -> Box<[(Rc<str>, Rc<str>)]> {
    let mut edges = Vec::new();
    let mut names = Vec::new();
    for item in &node.items {
        let syn::TraitItem::Fn(method) = item else {
            continue;
        };
        names.clear();
        collect_signature_type_names_into(&method.sig, &mut names);
        extend_edges_from_names(name, &names, &mut edges);
    }
    edges.into_boxed_slice()
}

fn field_edges<'a>(
    fields: impl Iterator<Item = &'a syn::Field>,
    name: &Rc<str>,
) -> Box<[(Rc<str>, Rc<str>)]> {
    let mut edges = Vec::new();
    let mut names = Vec::new();
    for field in fields {
        names.clear();
        collect_type_names_into(&field.ty, &mut names);
        extend_edges_from_names(name, &names, &mut edges);
    }
    edges.into_boxed_slice()
}
