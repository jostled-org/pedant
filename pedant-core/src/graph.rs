use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use syn::{FnArg, ReturnType, Signature, Type};

pub(crate) fn bfs_component<'a>(
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

/// Calls `emit(i, j)` for every unique pair of indices in `0..len`.
pub(crate) fn for_each_pair(len: usize, mut emit: impl FnMut(usize, usize)) {
    (0..len).for_each(|i| {
        ((i + 1)..len).for_each(|j| {
            emit(i, j);
        });
    });
}

pub(crate) fn pairwise_edges(names: &[Rc<str>]) -> Vec<(Rc<str>, Rc<str>)> {
    let len = names.len();
    let mut pairs = Vec::with_capacity(len * len.saturating_sub(1) / 2);
    for_each_pair(len, |i, j| {
        pairs.push((Rc::clone(&names[i]), Rc::clone(&names[j])));
    });
    pairs
}

pub(crate) fn edges_from_names(
    owner: &Rc<str>,
    type_names: Vec<Rc<str>>,
) -> Vec<(Rc<str>, Rc<str>)> {
    type_names
        .into_iter()
        .map(|tn| (Rc::clone(owner), tn))
        .collect()
}

/// Returns the first type name from a type (the first path segment), without
/// allocating the full list of recursively collected names.
pub(crate) fn first_type_name(ty: &Type) -> Option<Rc<str>> {
    match ty {
        Type::Path(tp) => tp
            .path
            .segments
            .first()
            .map(|seg| Rc::from(seg.ident.to_string())),
        Type::Reference(r) => first_type_name(&r.elem),
        Type::Tuple(t) => t.elems.iter().find_map(first_type_name),
        Type::Slice(s) => first_type_name(&s.elem),
        Type::Array(a) => first_type_name(&a.elem),
        _ => None,
    }
}

pub(crate) fn collect_type_names(ty: &Type) -> Vec<Rc<str>> {
    match ty {
        Type::Path(tp) => {
            let mut names: Vec<Rc<str>> = tp
                .path
                .segments
                .iter()
                .map(|seg| Rc::from(seg.ident.to_string()))
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

pub(crate) fn collect_signature_type_names(sig: &Signature) -> Vec<Rc<str>> {
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
