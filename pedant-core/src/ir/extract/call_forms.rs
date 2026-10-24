//! Method calls in every form they are written: a method-call expression, a
//! `Type::method` path, or tokens inside a macro's arguments.
//!
//! `syn` leaves a macro's arguments as tokens, so the walk never reaches them.
//! Where the arguments read as expressions, the extractor walks them like any
//! other code. Where they do not, a token scan still finds the method calls and
//! the nested macros they hold.

use std::sync::Arc;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::parse::ParseStream;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, Token};

use crate::ir::IrSpan;
use crate::ir::facts::MethodCallFact;
use crate::ir::type_introspection::iter_expr_ident;
use crate::pattern::method_call_text;

use super::extractor::IrExtractor;
use super::parse::parse_macro_invocation;
use super::site_visitor::type_name;
use super::syn_helpers::span_from;

/// One call to a named method, whatever form states it.
pub(super) struct CallSite<'a> {
    pub(super) method: &'a syn::Ident,
    /// Where the call is reported.
    pub(super) span: IrSpan,
    pub(super) receiver_ident: Option<Box<str>>,
    pub(super) receiver_span: IrSpan,
    /// The type a `Type::method` path states the method on.
    pub(super) receiver_type: Option<Arc<str>>,
}

/// Record one method call in the enclosing function and loop.
pub(super) fn push_method_call(extractor: &mut IrExtractor, site: CallSite<'_>) {
    extractor.method_calls.push(MethodCallFact {
        method_name: site.method.to_string().into_boxed_str(),
        text: method_call_text(site.method),
        span: site.span,
        receiver_ident: site.receiver_ident,
        receiver_span: site.receiver_span,
        loop_depth: extractor.loop_depth,
        containing_fn: extractor.fn_scope.current(),
        receiver_type: site.receiver_type,
        is_copy_receiver: false,
    });
}

/// The receiver identifier of a call, when the receiver is a plain binding.
pub(super) fn receiver_ident(receiver: &Expr) -> Option<Box<str>> {
    iter_expr_ident(receiver).map(|ident| ident.to_string().into_boxed_str())
}

/// Record a path that names a method as a call to it: `Option::unwrap`, as a
/// value or a callee. A callee's first argument is the receiver.
pub(super) fn record_method_path(
    extractor: &mut IrExtractor,
    path: &syn::ExprPath,
    receiver: Option<&Expr>,
) {
    let Some((owner, method)) = method_path(path) else {
        return;
    };
    push_method_call(
        extractor,
        CallSite {
            method,
            span: span_from(method.span().start()),
            receiver_ident: receiver.and_then(receiver_ident),
            receiver_span: span_from(receiver.map_or(path.span(), Spanned::span).start()),
            receiver_type: Some(owner),
        },
    );
}

/// The type a path qualifies its last segment with, and that segment, when the
/// path names a method: `Option::unwrap`, `Self::helper`, `<T as Trait>::call`.
///
/// Rust spells types in `UpperCamelCase` and methods in `snake_case`, and
/// nothing else is available before name resolution. A path through modules,
/// `std::mem::take`, names a free function, and a capitalized last segment,
/// `Kind::Variant`, names a variant or constant. Neither is a method.
fn method_path(path: &syn::ExprPath) -> Option<(Arc<str>, &syn::Ident)> {
    let mut segments = path.path.segments.iter().rev();
    let method = &segments.next()?.ident;
    let owner = match &path.qself {
        Some(qself) => type_name(&qself.ty)?,
        None => segments
            .next()
            .map(|segment| &segment.ident)
            .filter(|ident| starts_with(ident, char::is_uppercase))
            .map(|ident| Arc::from(ident.to_string().as_str()))?,
    };
    starts_with(method, |first| first.is_lowercase() || first == '_').then_some((owner, method))
}

fn starts_with(ident: &syn::Ident, test: impl Fn(char) -> bool) -> bool {
    ident.to_string().chars().next().is_some_and(test)
}

/// Walk the arguments of one macro invocation.
pub(super) fn visit_macro_arguments(extractor: &mut IrExtractor, mac: &syn::Macro) {
    match macro_arguments(mac) {
        Ok(arguments) => arguments
            .iter()
            .for_each(|argument| extractor.visit_expr(argument)),
        Err(_) => scan_tokens(extractor, mac.tokens.clone()),
    }
}

/// A macro body that reads as expressions: comma-separated, as `format!` and
/// `assert!` take them, or `element; length`, as `vec!` repeats one.
fn macro_arguments(mac: &syn::Macro) -> syn::Result<Vec<Expr>> {
    mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
        .map(|arguments| arguments.into_iter().collect())
        .or_else(|_| mac.parse_body_with(repeat_operands))
}

fn repeat_operands(input: ParseStream) -> syn::Result<Vec<Expr>> {
    let element: Expr = input.parse()?;
    input.parse::<Token![;]>()?;
    let length: Expr = input.parse()?;
    Ok(vec![element, length])
}

/// Find the calls in tokens that do not read as expressions.
fn scan_tokens(extractor: &mut IrExtractor, tokens: TokenStream) {
    let trees: Box<[TokenTree]> = tokens.into_iter().collect();
    let mut index = 0;
    while index < trees.len() {
        index += scan_at(extractor, &trees, index);
    }
}

/// Record what the tree at `index` begins, and answer how many trees it spans.
///
/// `. name (` and `. name ::` are method calls. `path ! group` is a nested
/// macro, handed back to the walk whole, so its arguments are read once.
fn scan_at(extractor: &mut IrExtractor, trees: &[TokenTree], index: usize) -> usize {
    match &trees[index] {
        TokenTree::Group(group) => {
            scan_tokens(extractor, group.stream());
            1
        }
        TokenTree::Punct(punct) if punct.as_char() == '.' => {
            record_scanned_call(extractor, trees, index);
            1
        }
        TokenTree::Punct(punct) if punct.as_char() == '!' => {
            visit_scanned_macro(extractor, trees, index)
        }
        _ => 1,
    }
}

/// Record the method call a lone `.` begins, if it begins one.
///
/// The second dot of a range, `0..len(k)`, is no call: it follows another dot.
fn record_scanned_call(extractor: &mut IrExtractor, trees: &[TokenTree], dot: usize) {
    let previous = dot.checked_sub(1).map(|before| &trees[before]);
    let follows_dot = matches!(previous, Some(TokenTree::Punct(punct)) if punct.as_char() == '.');
    let (Some(TokenTree::Ident(method)), Some(next)) = (trees.get(dot + 1), trees.get(dot + 2))
    else {
        return;
    };
    let opens_call = match next {
        TokenTree::Group(group) => group.delimiter() == Delimiter::Parenthesis,
        TokenTree::Punct(punct) => punct.as_char() == ':',
        _ => false,
    };
    if follows_dot || !opens_call {
        return;
    }
    let receiver = previous.unwrap_or(&trees[dot]);
    push_method_call(
        extractor,
        CallSite {
            method,
            span: span_from(trees[dot].span().start()),
            receiver_ident: match receiver {
                TokenTree::Ident(ident) => Some(ident.to_string().into_boxed_str()),
                _ => None,
            },
            receiver_span: span_from(receiver.span().start()),
            receiver_type: None,
        },
    );
}

/// Walk the macro a `!` closes the path of, and answer how many trees it spans.
///
/// `!` between a path and a group invokes a macro. Anything else, `!=` or a
/// negation such as `if !(..)`, fails to parse as one and spans the `!` alone.
fn visit_scanned_macro(extractor: &mut IrExtractor, trees: &[TokenTree], bang: usize) -> usize {
    let Some(TokenTree::Group(_)) = trees.get(bang + 1) else {
        return 1;
    };
    let invocation: TokenStream = trees[path_start(trees, bang)..=bang + 1]
        .iter()
        .cloned()
        .collect();
    match parse_macro_invocation(invocation) {
        Some(expr_macro) => {
            extractor.visit_macro(&expr_macro.mac);
            2
        }
        None => 1,
    }
}

/// The index of the first tree of the `a::b::name` path that ends before `bang`.
fn path_start(trees: &[TokenTree], bang: usize) -> usize {
    let mut start = bang;
    while start > 0 && matches!(trees[start - 1], TokenTree::Ident(_)) {
        start -= 1;
        let separated = start >= 3
            && is_colon(&trees[start - 1])
            && is_colon(&trees[start - 2])
            && matches!(trees[start - 3], TokenTree::Ident(_));
        if !separated {
            break;
        }
        start -= 2;
    }
    start
}

fn is_colon(tree: &TokenTree) -> bool {
    matches!(tree, TokenTree::Punct(punct) if punct.as_char() == ':')
}
