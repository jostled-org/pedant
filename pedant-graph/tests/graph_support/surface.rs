//! The declared surface one parsed production source states.
//!
//! [`super::scan`] answers with text and parsed files; the readers here answer
//! with the items, derives, fields, and constructors those files declare. Every
//! ownership case reads the surface through this module, so one walk decides
//! what "declared" means and a record moved into an inline `mod` cannot escape
//! two cases by escaping one walk.
//!
//! What those declarations call is a separate question, answered by
//! [`super::call_graph`] over the same walk.

use std::collections::BTreeSet;

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

/// Whether one item names a module or a re-export and nothing else.
///
/// Read as parsed items rather than as forbidden spellings. A list of keywords
/// has to name every way Rust states a definition, and whatever it misses — a
/// trait, a static, a union, a `macro_rules!` — passes. Two item kinds are
/// admitted here, so everything else fails whether or not the case that calls
/// this has heard of it. A module with a body is a definition site too, so only
/// the file declarations are admitted.
pub fn declares_only(item: &syn::Item) -> bool {
    match item {
        syn::Item::Mod(module) => module.content.is_none(),
        syn::Item::Use(_) => true,
        _ => false,
    }
}

/// One declared item, named by the kind and the name it states.
///
/// The kinds are spelled out so a failure names the offender rather than
/// printing its tokens. `syn::Item` grows, so an unnamed kind still answers,
/// with the source it was written as.
pub fn item_label(item: &syn::Item) -> String {
    match item {
        syn::Item::Const(entry) => format!("const {}", entry.ident),
        syn::Item::Enum(entry) => format!("enum {}", entry.ident),
        syn::Item::ExternCrate(entry) => format!("extern crate {}", entry.ident),
        syn::Item::Fn(entry) => format!("fn {}", entry.sig.ident),
        syn::Item::ForeignMod(entry) => format!("extern block {}", scan::token_text(&entry.abi)),
        syn::Item::Impl(entry) => format!("impl {}", scan::token_text(&entry.self_ty)),
        syn::Item::Macro(entry) => format!("macro {}", scan::token_text(&entry.mac.path)),
        syn::Item::Mod(entry) => format!("inline mod {}", entry.ident),
        syn::Item::Static(entry) => format!("static {}", entry.ident),
        syn::Item::Struct(entry) => format!("struct {}", entry.ident),
        syn::Item::Trait(entry) => format!("trait {}", entry.ident),
        syn::Item::TraitAlias(entry) => format!("trait alias {}", entry.ident),
        syn::Item::Type(entry) => format!("type {}", entry.ident),
        syn::Item::Union(entry) => format!("union {}", entry.ident),
        syn::Item::Use(entry) => format!("use {}", scan::token_text(&entry.tree)),
        other => scan::token_text(other),
    }
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

/// The one renaming rule [`serialized_tags`] applies, as the parsed attribute
/// renders it.
const SNAKE_CASE: &str = "rename_all = \"snake_case\"";

/// Every tag one declared enum serializes its variants to.
///
/// Read from the declaration rather than written down a second time. A written
/// tag list is an upper bound on its own: a variant that stopped existing would
/// leave the list admitting a token the wire can no longer carry, and no
/// selection over real bytes would ever fail. Comparing the list with this set
/// is what makes it the set.
///
/// Exactly one renaming rule is admitted and no per-variant renaming at all,
/// because exactly that is what the graph's own vocabulary states. A type that
/// grew a second rule fails here rather than being read under the wrong one.
pub fn serialized_tags(path: &str, name: &str) -> BTreeSet<String> {
    let file = parsed(path);
    let declared = declared_items(&file.items)
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Enum(found) if found.ident == name => Some(found),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{path} declares no {name} enum"));
    let stated: Vec<String> = declared.attrs.iter().map(scan::token_text).collect();
    assert!(
        stated
            .iter()
            .any(|attribute| attribute.contains(SNAKE_CASE)),
        "{name} must state {SNAKE_CASE}, stating {stated:?}"
    );
    let renamed: Vec<String> = declared
        .variants
        .iter()
        .filter(|variant| {
            variant
                .attrs
                .iter()
                .any(|attribute| attribute.path().is_ident("serde"))
        })
        .map(|variant| variant.ident.to_string())
        .collect();
    assert!(
        renamed.is_empty(),
        "{name} renames a variant of its own, which this reader does not apply: {renamed:?}"
    );
    declared
        .variants
        .iter()
        .map(|variant| snake_case(&variant.ident.to_string()))
        .collect()
}

/// One declared name under the `snake_case` renaming rule.
fn snake_case(name: &str) -> String {
    let mut written = String::new();
    for character in name.chars() {
        if character.is_uppercase() && !written.is_empty() {
            written.push('_');
        }
        written.extend(character.to_lowercase());
    }
    written
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
/// Ceilings, an edge selection, a retention budget, the cache that budget
/// bounds, and the analysis view over a graph a caller already holds are all
/// caller policy. Every other type is a record or a result whose
/// invariants this crate establishes, so a public constructor for one would be
/// a second way to state it.
const CALLER_CONSTRUCTED: &[&str] = &[
    "GraphAnalysis",
    "GraphAnalysisLimits",
    "GraphCache",
    "GraphCacheLimits",
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
