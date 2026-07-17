//! Stateless queries and normalizations over the `syn` AST.
//!
//! Nothing here touches extractor state — these are pure functions from AST
//! nodes to IR vocabulary, shared by the extractor and its visitor.

use std::rc::Rc;

use syn::{Expr, ExprIf, Type};

use crate::ir::facts::{IrSpan, Visibility};
use crate::ir::type_introspection::get_type_span_start;

/// Convert a `proc_macro2` line/column pair into an [`IrSpan`].
pub(super) fn span_from(lc: proc_macro2::LineColumn) -> IrSpan {
    IrSpan {
        line: lc.line,
        column: lc.column,
    }
}

/// Check if an attribute is `#[cfg(test)]` without allocating.
pub(super) fn is_cfg_test_attr(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("cfg")
        && attr.meta.require_list().ok().is_some_and(|list| {
            let mut iter = list.tokens.clone().into_iter();
            let first = iter.next();
            matches!(
                (&first, iter.next()),
                (Some(proc_macro2::TokenTree::Ident(ident)), None) if ident == "test"
            )
        })
}

/// Physical source lines spanned by a function body block, inclusive of both
/// braces. syn's `span-locations` feature gives exact line positions, so this
/// is immune to the brace-in-string / comment ambiguity a lexer would hit.
pub(super) fn block_line_count(block: &syn::Block) -> usize {
    let span = block.brace_token.span.join();
    span.end().line.saturating_sub(span.start().line) + 1
}

/// `true` when a function body is exactly one delegating call of the form
/// `self.<field>.<method>(<args>)`, allowing a trailing `?` and/or `.await`.
///
/// A pure forwarder carries no responsibility of its own, so it should not
/// count toward a type's method surface in `high-method-count`.
pub(super) fn is_pure_forwarder(block: &syn::Block) -> bool {
    let [syn::Stmt::Expr(expr, _)] = &block.stmts[..] else {
        return false;
    };
    // Peel any trailing `?` and `.await` before inspecting the call.
    let mut inner = expr;
    loop {
        match inner {
            Expr::Try(try_expr) => inner = &try_expr.expr,
            Expr::Await(await_expr) => inner = &await_expr.base,
            _ => break,
        }
    }
    let Expr::MethodCall(call) = inner else {
        return false;
    };
    let Expr::Field(field) = call.receiver.as_ref() else {
        return false;
    };
    matches!(field.base.as_ref(), Expr::Path(path) if path.path.is_ident("self"))
}

/// Normalize a `syn::Visibility` into the [`Visibility`] vocabulary.
pub(super) fn normalize_visibility(vis: &syn::Visibility) -> Visibility {
    match vis {
        syn::Visibility::Inherited => Visibility::Private,
        syn::Visibility::Public(_) => Visibility::Public,
        syn::Visibility::Restricted(restricted) => normalize_restricted(restricted),
    }
}

fn normalize_restricted(restricted: &syn::VisRestricted) -> Visibility {
    let path = restricted_path_string(&restricted.path);
    match (restricted.in_token.is_some(), path.as_str()) {
        (false, "crate") => Visibility::Crate,
        (false, "super") => Visibility::Super,
        _ => Visibility::Restricted(path.into_boxed_str()),
    }
}

fn restricted_path_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|seg| seg.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Return the feature name if `attr` is `#[cfg(feature = "…")]` (the direct
/// form; nested `all(...)`/`any(...)` combinators are not decomposed).
pub(super) fn cfg_feature_name(attr: &syn::Attribute) -> Option<Rc<str>> {
    if !attr.path().is_ident("cfg") {
        return None;
    }
    let name_value = attr.parse_args::<syn::MetaNameValue>().ok()?;
    match (name_value.path.is_ident("feature"), &name_value.value) {
        (
            true,
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(feature),
                ..
            }),
        ) => Some(Rc::from(feature.value())),
        _ => None,
    }
}

/// Visit binding identifiers with their spans and optional type annotation spans.
pub(super) fn for_each_pat_ident_span(
    pat: &syn::Pat,
    type_span: Option<IrSpan>,
    f: &mut impl FnMut(Box<str>, IrSpan, Option<IrSpan>),
) {
    match pat {
        syn::Pat::Ident(pi) => {
            let name: Box<str> = pi.ident.to_string().into_boxed_str();
            let span = span_from(pi.ident.span().start());
            f(name, span, type_span);
        }
        syn::Pat::Type(pt) => {
            let ty_span = span_from(get_type_span_start(&pt.ty));
            for_each_pat_ident_span(&pt.pat, Some(ty_span), f);
        }
        syn::Pat::Tuple(pt) => {
            for inner_pat in &pt.elems {
                for_each_pat_ident_span(inner_pat, None, f);
            }
        }
        syn::Pat::TupleStruct(pts) => {
            for field_pat in &pts.elems {
                for_each_pat_ident_span(field_pat, None, f);
            }
        }
        syn::Pat::Struct(ps) => {
            for field in &ps.fields {
                for_each_pat_ident_span(&field.pat, None, f);
            }
        }
        syn::Pat::Slice(psl) => {
            for slice_pat in &psl.elems {
                for_each_pat_ident_span(slice_pat, None, f);
            }
        }
        syn::Pat::Or(po) => {
            for case in &po.cases {
                for_each_pat_ident_span(case, None, f);
            }
        }
        syn::Pat::Reference(pr) => for_each_pat_ident_span(&pr.pat, type_span, f),
        _ => {}
    }
}

/// Destructure a `pat: Type` pattern into its identifier and annotated type.
pub(super) fn typed_ident_from_pat(pat: &syn::Pat) -> Option<(&syn::Ident, &Type)> {
    let syn::Pat::Type(pt) = pat else { return None };
    let syn::Pat::Ident(pi) = pt.pat.as_ref() else {
        return None;
    };
    Some((&pi.ident, &pt.ty))
}

/// Length of an `if`/`else if`/`else` chain, counting the leading `if`.
pub(super) fn count_else_chain(expr: &ExprIf) -> usize {
    let mut count = 1;
    let mut current = expr;
    while let Some(ref else_branch) = current.else_branch {
        match else_branch.1.as_ref() {
            Expr::If(next_if) => {
                count += 1;
                current = next_if;
            }
            Expr::Block(_) => {
                count += 1;
                break;
            }
            _ => break,
        }
    }
    count
}
