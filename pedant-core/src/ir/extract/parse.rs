//! The one route from Rust source text to the tree the extractor consumes.
//!
//! This is the crate's single parse route: every parse in `pedant-core` goes
//! through here, so an observed parse count is how many times a source was
//! parsed by any caller in this crate rather than by one loader. A consumer
//! that reparsed a source instead of reusing its stored `FileIr` is therefore
//! visible even when it reparses through the lint pipeline. Other crates own
//! their own trees and cannot reach this route, which is `pub(crate)`.

use proc_macro2::{Group, Ident, TokenStream, TokenTree};

use crate::observe::{Observation, record};

/// Which Rust editions can consume a successfully parsed tree.
pub(crate) enum ParseCompatibility {
    /// The source parsed without compatibility repair.
    AllEditions,
    /// The source required `dyn` insertion at a pre-2021 bare callable trait.
    LegacyCallableTraits { strict_error: Box<str> },
}

/// A parsed file beside the compatibility fact needed by a shared source
/// store that may be reached from packages on different editions.
pub(crate) struct ParsedSource {
    pub(crate) file: syn::File,
    pub(crate) compatibility: ParseCompatibility,
}

/// Parse `source` into the syntax tree [`extract`](super::extract) consumes,
/// recording the parse against `file_path`.
#[cfg(feature = "checks")]
pub(crate) fn parse_source(file_path: &str, source: &str) -> Result<syn::File, syn::Error> {
    parse_source_for_edition(file_path, source, false).map(|parsed| parsed.file)
}

/// Parse one Cargo source, admitting the pre-2021 spelling of callable trait
/// objects only when the resolved package edition permits it.
pub(crate) fn parse_source_for_edition(
    file_path: &str,
    source: &str,
    permits_bare_callable_traits: bool,
) -> Result<ParsedSource, syn::Error> {
    record(Observation::SourceParse(file_path));
    match syn::parse_file(source) {
        Ok(file) => Ok(ParsedSource {
            file,
            compatibility: ParseCompatibility::AllEditions,
        }),
        Err(error) if permits_bare_callable_traits => repair_legacy_callable_traits(source, error),
        Err(error) => Err(error),
    }
}

fn repair_legacy_callable_traits(
    source: &str,
    strict_error: syn::Error,
) -> Result<ParsedSource, syn::Error> {
    if strict_error.to_string() != "expected `;`" {
        return Err(strict_error);
    }
    let strict_message = strict_error.to_string().into_boxed_str();
    let tokens = match source.parse::<TokenStream>() {
        Ok(tokens) => tokens,
        Err(_) => return Err(strict_error),
    };
    let repaired = match repair_stream(tokens) {
        Some(tokens) => tokens,
        None => return Err(strict_error),
    };
    syn::parse2(repaired).map(|file| ParsedSource {
        file,
        compatibility: ParseCompatibility::LegacyCallableTraits {
            strict_error: strict_message,
        },
    })
}

fn repair_stream(tokens: TokenStream) -> Option<TokenStream> {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let positions: Vec<bool> = trees
        .iter()
        .enumerate()
        .map(|(index, tree)| repairable(trees.as_slice(), index, tree))
        .collect();
    let mut changed = positions.iter().any(|position| *position);
    let mut repaired = TokenStream::new();
    for (index, tree) in trees.into_iter().enumerate() {
        if positions[index] {
            repaired.extend([TokenTree::Ident(Ident::new("dyn", tree.span()))]);
        }
        let (tree, nested_changed) = repair_group(tree);
        changed |= nested_changed;
        repaired.extend([tree]);
    }
    changed.then_some(repaired)
}

fn repairable(trees: &[TokenTree], index: usize, tree: &TokenTree) -> bool {
    match tree {
        TokenTree::Ident(ident) => is_callable(ident) && follows_alias_equals(trees, index),
        TokenTree::Group(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    }
}

fn is_callable(ident: &Ident) -> bool {
    matches!(ident.to_string().as_str(), "Fn" | "FnMut" | "FnOnce")
}

fn follows_alias_equals(trees: &[TokenTree], index: usize) -> bool {
    let directly_follows_equals = index
        .checked_sub(1)
        .and_then(|previous| trees.get(previous))
        .is_some_and(|tree| matches!(tree, TokenTree::Punct(punct) if punct.as_char() == '='));
    directly_follows_equals && current_statement_is_type_alias(&trees[..index])
}

fn current_statement_is_type_alias(prefix: &[TokenTree]) -> bool {
    prefix
        .iter()
        .rev()
        .take_while(|tree| !matches!(tree, TokenTree::Punct(punct) if punct.as_char() == ';'))
        .any(|tree| matches!(tree, TokenTree::Ident(ident) if ident == "type"))
}

fn repair_group(tree: TokenTree) -> (TokenTree, bool) {
    let TokenTree::Group(original) = tree else {
        return (tree, false);
    };
    let stream = match repair_stream(original.stream()) {
        Some(stream) => stream,
        None => return (TokenTree::Group(original), false),
    };
    let mut group = Group::new(original.delimiter(), stream);
    group.set_span(original.span());
    (TokenTree::Group(group), true)
}
