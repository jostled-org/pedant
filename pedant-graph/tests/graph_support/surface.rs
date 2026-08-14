//! The declared surface one parsed production source states.
//!
//! [`super::scan`] answers with text and parsed files; the readers here answer
//! with the items, derives, fields, and constructors those files declare. Every
//! ownership case reads the surface through this module, so one walk decides
//! what "declared" means and a record moved into an inline `mod` cannot escape
//! two cases by escaping one walk.

use std::collections::{BTreeMap, BTreeSet};

use super::scan::{self, parsed};

/// Every trait one item's `derive` attributes name, across all of them.
pub fn derived_paths(attributes: &[syn::Attribute]) -> BTreeSet<String> {
    attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("derive"))
        .flat_map(|attribute| {
            attribute
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                )
                .unwrap_or_else(|error| panic!("a derive attribute parses: {error}"))
        })
        .map(|path| {
            path.segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_else(|| panic!("a derive attribute names a trait"))
        })
        .collect()
}

/// Every item one file declares, including those inside inline modules.
///
/// A record moved into an inline `mod` is still this crate's public surface, so
/// the walk descends rather than reading the file's top level alone.
pub fn declared_items(items: &[syn::Item]) -> Vec<&syn::Item> {
    let mut found: Vec<&syn::Item> = Vec::new();
    for item in items {
        found.push(item);
        let inner = match item {
            syn::Item::Mod(module) => module.content.as_ref().map(|(_, declared)| declared),
            _ => None,
        };
        found.extend(
            inner
                .into_iter()
                .flat_map(|declared| declared_items(declared)),
        );
    }
    found
}

/// Every variant `GraphBuildError` declares.
///
/// Read from the enum rather than written down twice, so a refusal added
/// without an owner entry fails the model comparison instead of passing
/// unexamined.
pub fn declared_error_variants() -> BTreeSet<String> {
    parsed("src/error.rs")
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Enum(declared) if declared.ident == "GraphBuildError" => Some(declared),
            _ => None,
        })
        .unwrap_or_else(|| panic!("src/error.rs declares no GraphBuildError enum"))
        .variants
        .iter()
        .map(|variant| variant.ident.to_string())
        .collect()
}

/// Every name one source publicly re-exports, optionally from one module.
///
/// Read from the `use` trees rather than from the file's text, so a re-export
/// wrapped differently by the formatter still answers with the same names.
pub fn public_use_leaves(path: &str, root: Option<&str>) -> BTreeSet<String> {
    parsed(path)
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Use(declared) if is_public(&declared.vis) => Some(&declared.tree),
            _ => None,
        })
        .flat_map(|tree| use_leaves(tree, root))
        .collect()
}

/// The leaf names one `use` tree states, beneath `root` when one is stated.
fn use_leaves(tree: &syn::UseTree, root: Option<&str>) -> Vec<String> {
    match tree {
        syn::UseTree::Path(path) => entered(path, root),
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .flat_map(|inner| use_leaves(inner, root))
            .collect(),
        syn::UseTree::Name(name) => named_leaf(name.ident.to_string(), root),
        syn::UseTree::Rename(rename) => named_leaf(rename.rename.to_string(), root),
        syn::UseTree::Glob(_) => vec!["*".to_owned()],
    }
}

/// The leaves beneath one path segment, unless a stated root was not entered.
fn entered(path: &syn::UsePath, root: Option<&str>) -> Vec<String> {
    match root {
        Some(name) if path.ident != name => Vec::new(),
        _ => use_leaves(&path.tree, None),
    }
}

/// One leaf, unless a stated root was never entered.
fn named_leaf(name: String, root: Option<&str>) -> Vec<String> {
    match root {
        Some(_) => Vec::new(),
        None => vec![name],
    }
}

/// Every public function one source declares, as `Subject::signature`.
pub fn public_signatures(path: &str) -> Vec<String> {
    let file = parsed(path);
    declared_items(&file.items)
        .into_iter()
        .flat_map(declared_signatures)
        .collect()
}

/// The public signatures one declared item states.
fn declared_signatures(item: &syn::Item) -> Vec<String> {
    match item {
        syn::Item::Impl(block) => impl_signatures(block),
        syn::Item::Fn(function) if is_public(&function.vis) => {
            vec![normalized(&scan::token_text(&function.sig))]
        }
        _ => Vec::new(),
    }
}

/// The public signatures one `impl` block states, qualified by its subject.
fn impl_signatures(block: &syn::ItemImpl) -> Vec<String> {
    let subject = subject_name(&block.self_ty);
    block
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(function) if is_public(&function.vis) => Some(format!(
                "{subject}::{}",
                normalized(&scan::token_text(&function.sig)).replacen("fn ", "", 1)
            )),
            _ => None,
        })
        .collect()
}

/// One token rendering with the spacing a reader would not write.
///
/// The parser answers with one space between every token, which turns an
/// ordinary signature into an unreadable model. The delimiters below take
/// their conventional spacing back; `->` is held aside first, because the rules
/// that tighten `>` would otherwise consume it.
fn normalized(text: &str) -> String {
    let held = text.replace(" -> ", "\u{1}");
    held.replace(" :: ", "::")
        .replace(" :", ":")
        .replace(" < ", "<")
        .replace(" <", "<")
        .replace(" > ", ">")
        .replace(" >", ">")
        .replace(" ,", ",")
        .replace(" (", "(")
        .replace("( ", "(")
        .replace(" )", ")")
        .replace("& ", "&")
        .replace(",)", ")")
        .replace('\u{1}', " -> ")
}

/// Every field one named struct declares, in declaration order.
///
/// Read whatever its visibility is: a private coordinate field is still a
/// coordinate the crate decided to hold.
pub fn declared_fields(items: &[&syn::Item], name: &str) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(declared) if declared.ident == name => Some(declared),
            _ => None,
        })
        .flat_map(|declared| declared.fields.iter())
        .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
        .collect()
}

/// Every public struct field a graph record exposes, if any does.
pub fn public_fields(items: &[&syn::Item], path: &str) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(declared) if is_public(&declared.vis) => Some(declared),
            _ => None,
        })
        .flat_map(|declared| {
            declared
                .fields
                .iter()
                .filter(|field| is_public(&field.vis))
                .map(move |field| {
                    let name = field
                        .ident
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "0".to_owned());
                    format!("{path}: {}.{name} is public", declared.ident)
                })
        })
        .collect()
}

/// Every public associated function that would manufacture a record or an
/// identity, which only the projection may do.
///
/// A function qualifies by shape rather than by name: an allow-list of `new`
/// and `with_limits` would admit a third spelling that returns exactly the same
/// record.
pub fn public_constructors(items: &[&syn::Item], path: &str) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(block) => Some(block),
            _ => None,
        })
        .filter(|block| is_closed_type(block))
        .flat_map(|block| block_constructors(block, path))
        .collect()
}

/// Every public associated function of one `impl` block that manufactures the
/// block's own subject.
fn block_constructors(block: &syn::ItemImpl, path: &str) -> Vec<String> {
    let subject = subject_name(&block.self_ty);
    block
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(function) if is_public(&function.vis) => Some(function),
            _ => None,
        })
        .filter(|function| manufactures(&function.sig, &subject))
        .map(|function| {
            format!(
                "{path}: {subject}::{} is a public constructor",
                function.sig.ident
            )
        })
        .collect()
}

/// Whether one signature manufactures the type its `impl` block is for.
///
/// A constructor takes no receiver and answers with the subject or with `Self`.
/// An accessor takes `&self`, so no borrowed view of a record is read as a way
/// to build one.
fn manufactures(signature: &syn::Signature, subject: &str) -> bool {
    let returned = match &signature.output {
        syn::ReturnType::Default => return false,
        syn::ReturnType::Type(_, declared) => scan::token_text(declared),
    };
    signature.receiver().is_none() && names_type(&returned, subject)
}

/// Whether one rendered type names `subject` or `Self` as a whole token.
fn names_type(text: &str, subject: &str) -> bool {
    text.split(|character: char| !character.is_alphanumeric() && character != '_')
        .any(|token| token == subject || token == "Self")
}

/// The base name of one `impl` block's subject, without its generics.
fn subject_name(subject: &syn::Type) -> String {
    let text = scan::token_text(subject);
    text.split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("an impl block states no subject type: {text:?}"))
        .to_owned()
}

/// The types a caller is deliberately allowed to state.
///
/// Ceilings, an edge selection, and the analysis view over a graph it already
/// holds are all caller policy. Every other type is a record or a result whose
/// invariants this crate establishes, so a public constructor for one would be
/// a second way to state it.
const CALLER_CONSTRUCTED: &[&str] = &[
    "GraphAnalysis",
    "GraphAnalysisLimits",
    "GraphEdgeSelection",
    "GraphLimits",
    "GraphRecords",
];

/// Whether an `impl` block belongs to a record, a result, or an identity.
///
/// The subject is compared by name rather than by substring: a type spelled
/// `GraphAnalysisError` is not the analysis view, and reading it as one would
/// exempt every future type that starts with an exempted name.
fn is_closed_type(block: &syn::ItemImpl) -> bool {
    let subject = subject_name(&block.self_ty);
    !CALLER_CONSTRUCTED.iter().any(|allowed| subject == *allowed)
}

fn is_public(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Public(_))
}

/// Every function one source declares, beside the declared functions its body
/// calls.
///
/// Names are the whole model: two functions declared with one name — an
/// accessor each of two records states — merge into one entry, so the answer
/// over-approximates rather than losing a call. An over-approximated call graph
/// can only reject a shape a real one would accept, never accept one it would
/// reject.
pub fn declared_call_graph(path: &str) -> BTreeMap<String, BTreeSet<String>> {
    let file = parsed(path);
    let bodies = declared_bodies(&declared_items(&file.items));
    let declared: BTreeSet<&str> = bodies.keys().map(String::as_str).collect();
    bodies
        .iter()
        .map(|(name, body)| (name.clone(), calls(body, &declared)))
        .collect()
}

/// Every free function and method one source declares, beside its body text
/// with every space dropped.
fn declared_bodies(items: &[&syn::Item]) -> BTreeMap<String, String> {
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    for item in items {
        for (name, body) in item_bodies(item) {
            found.entry(name).or_default().push_str(&body);
        }
    }
    found
}

/// The functions one declared item states, as name and compacted body.
fn item_bodies(item: &syn::Item) -> Vec<(String, String)> {
    match item {
        syn::Item::Fn(function) => vec![compacted(&function.sig, &function.block)],
        syn::Item::Impl(block) => block.items.iter().filter_map(impl_body).collect(),
        _ => Vec::new(),
    }
}

/// One implementation member's name beside its body, when it is a method.
fn impl_body(item: &syn::ImplItem) -> Option<(String, String)> {
    match item {
        syn::ImplItem::Fn(method) => Some(compacted(&method.sig, &method.block)),
        _ => None,
    }
}

/// One function's name beside its body with every space dropped.
fn compacted(signature: &syn::Signature, body: &syn::Block) -> (String, String) {
    (
        signature.ident.to_string(),
        scan::token_text(body).split_whitespace().collect(),
    )
}

/// Every declared function one body calls.
fn calls(body: &str, declared: &BTreeSet<&str>) -> BTreeSet<String> {
    declared
        .iter()
        .filter(|name| is_called(body, name))
        .map(|name| (*name).to_owned())
        .collect()
}

/// Whether one body calls one declared function by name.
///
/// The name must start where no identifier character precedes it, so a call to
/// `index_of` is not read as a call to a function named `of`.
fn is_called(body: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    body.match_indices(&needle)
        .any(|(at, _)| at == 0 || !is_name_char(body.as_bytes()[at - 1]))
}

fn is_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Every function that sits on, or reaches, a cycle of calls.
///
/// Functions with no remaining outgoing call are dropped in turn; whatever
/// cannot be dropped can still reach a call that returns to it.
pub fn recursive_functions(calls: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    let mut remaining: BTreeSet<&str> = calls.keys().map(String::as_str).collect();
    loop {
        let settled: Vec<&str> = remaining
            .iter()
            .copied()
            .filter(|name| reaches_none(calls, name, &remaining))
            .collect();
        match settled.is_empty() {
            true => return remaining.iter().map(|name| (*name).to_owned()).collect(),
            false => remaining.retain(|name| !settled.contains(name)),
        }
    }
}

/// Whether one function calls nothing that is still remaining.
fn reaches_none(
    calls: &BTreeMap<String, BTreeSet<String>>,
    name: &str,
    remaining: &BTreeSet<&str>,
) -> bool {
    calls
        .get(name)
        .into_iter()
        .flatten()
        .all(|called| !remaining.contains(called.as_str()))
}
