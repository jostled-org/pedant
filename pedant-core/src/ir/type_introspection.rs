use proc_macro2::LineColumn;
use syn::{Expr, Type};

/// Classifies a single-character binding name. Returns `Some(true)` if generic,
/// `Some(false)` if contextually allowed, `None` if the name is multi-character.
pub(crate) fn classify_single_char(
    name: &str,
    loop_depth: usize,
    has_arithmetic: bool,
) -> Option<bool> {
    match name {
        "i" | "j" | "k" | "n" => Some(loop_depth == 0),
        "x" | "y" | "z" => Some(!has_arithmetic),
        _ => None,
    }
}

pub(crate) fn collect_pat_idents(pat: &syn::Pat) -> Vec<Box<str>> {
    match pat {
        syn::Pat::Ident(pi) => vec![pi.ident.to_string().into_boxed_str()],
        syn::Pat::Tuple(pt) => pt.elems.iter().flat_map(collect_pat_idents).collect(),
        syn::Pat::TupleStruct(pts) => pts.elems.iter().flat_map(collect_pat_idents).collect(),
        syn::Pat::Struct(ps) => ps
            .fields
            .iter()
            .flat_map(|fp| collect_pat_idents(&fp.pat))
            .collect(),
        syn::Pat::Slice(psl) => psl.elems.iter().flat_map(collect_pat_idents).collect(),
        syn::Pat::Or(po) => po.cases.iter().flat_map(collect_pat_idents).collect(),
        syn::Pat::Reference(pr) => collect_pat_idents(&pr.pat),
        syn::Pat::Type(pt) => collect_pat_idents(&pt.pat),
        _ => vec![],
    }
}

/// Returns the first identifier in a pattern, without allocating the full list.
pub(crate) fn first_pat_ident(pat: &syn::Pat) -> Option<Box<str>> {
    match pat {
        syn::Pat::Ident(pi) => Some(pi.ident.to_string().into_boxed_str()),
        syn::Pat::Tuple(pt) => pt.elems.iter().find_map(first_pat_ident),
        syn::Pat::TupleStruct(pts) => pts.elems.iter().find_map(first_pat_ident),
        syn::Pat::Struct(ps) => ps.fields.iter().find_map(|fp| first_pat_ident(&fp.pat)),
        syn::Pat::Slice(psl) => psl.elems.iter().find_map(first_pat_ident),
        syn::Pat::Or(po) => po.cases.iter().find_map(first_pat_ident),
        syn::Pat::Reference(pr) => first_pat_ident(&pr.pat),
        syn::Pat::Type(pt) => first_pat_ident(&pt.pat),
        _ => None,
    }
}

pub(crate) fn receiver_ident(expr: &Expr) -> Option<&syn::Ident> {
    let Expr::Path(ep) = expr else {
        return None;
    };
    match ep.path.segments.len() {
        1 => Some(&ep.path.segments[0].ident),
        _ => None,
    }
}

pub(crate) fn iter_expr_ident(expr: &Expr) -> Option<&syn::Ident> {
    match expr {
        Expr::Path(ep) if ep.path.segments.len() == 1 => Some(&ep.path.segments[0].ident),
        Expr::Reference(er) => iter_expr_ident(&er.expr),
        _ => None,
    }
}

pub(crate) fn is_refcounted_type(ty: &Type) -> bool {
    let ty = match ty {
        Type::Reference(r) => &r.elem,
        _ => ty,
    };
    type_path_last_segment(ty)
        .map(|seg| seg.ident == "Arc" || seg.ident == "Rc")
        .unwrap_or(false)
}

pub(crate) fn contains_refcounted_type(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => path_contains_refcounted(tp),
        Type::Reference(r) => contains_refcounted_type(&r.elem),
        Type::Slice(s) => contains_refcounted_type(&s.elem),
        Type::Array(a) => contains_refcounted_type(&a.elem),
        Type::Tuple(t) => t.elems.iter().any(contains_refcounted_type),
        _ => false,
    }
}

fn path_contains_refcounted(tp: &syn::TypePath) -> bool {
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    if seg.ident == "Arc" || seg.ident == "Rc" {
        return true;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return false;
    };
    args.args.iter().any(
        |arg| matches!(arg, syn::GenericArgument::Type(inner) if contains_refcounted_type(inner)),
    )
}

pub(crate) fn is_string_type(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => tp
            .path
            .segments
            .last()
            .map(|seg| seg.ident == "String")
            .unwrap_or(false),
        Type::Reference(r) => r.mutability.is_some() && is_string_type(&r.elem),
        _ => false,
    }
}

pub(crate) fn type_path_last_segment(ty: &Type) -> Option<&syn::PathSegment> {
    match ty {
        Type::Path(tp) => tp.path.segments.last(),
        _ => None,
    }
}

pub(crate) fn first_type_arg(seg: &syn::PathSegment) -> Option<&Type> {
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

pub(crate) fn involves_dyn_dispatch(ty: &Type) -> bool {
    match ty {
        Type::TraitObject(_) => true,
        Type::Reference(r) => matches!(r.elem.as_ref(), Type::TraitObject(_)),
        _ => {
            let Some(seg) = type_path_last_segment(ty) else {
                return false;
            };
            (seg.ident == "Box" || seg.ident == "Arc" || seg.ident == "Rc")
                && first_type_arg(seg).is_some_and(|inner| matches!(inner, Type::TraitObject(_)))
        }
    }
}

pub(crate) fn is_vec_box_dyn(ty: &Type) -> bool {
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

pub(crate) fn is_default_hasher(ty: &Type) -> bool {
    let Some(seg) = type_path_last_segment(ty) else {
        return false;
    };
    match () {
        () if seg.ident == "HashMap" => count_type_args(seg) == 2,
        () if seg.ident == "HashSet" => count_type_args(seg) == 1,
        () => false,
    }
}

pub(crate) fn get_type_span_start(ty: &Type) -> LineColumn {
    match ty {
        Type::Path(tp) => tp
            .path
            .segments
            .first()
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
        Type::TraitObject(to) => to
            .bounds
            .first()
            .map(get_type_param_bound_span)
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 }),
        Type::BareFn(bf) => bf.fn_token.span.start(),
        Type::Never(tn) => tn.bang_token.span.start(),
        Type::Infer(ti) => ti.underscore_token.span.start(),
        Type::Macro(tm) => tm
            .mac
            .path
            .segments
            .first()
            .map(|s| s.ident.span().start())
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 }),
        _ => LineColumn { line: 1, column: 0 },
    }
}

fn get_type_param_bound_span(bound: &syn::TypeParamBound) -> LineColumn {
    match bound {
        syn::TypeParamBound::Trait(tb) => tb
            .path
            .segments
            .first()
            .map(|s| s.ident.span().start())
            .unwrap_or_else(|| LineColumn { line: 1, column: 0 }),
        syn::TypeParamBound::Lifetime(lt) => lt.apostrophe.start(),
        _ => LineColumn { line: 1, column: 0 },
    }
}
