//! The declared surface one parsed production source states.
//!
//! [`super::scan`] answers with text and parsed files; the readers here answer
//! with the items, derives, fields, and constructors those files declare. Every
//! ownership case reads the surface through this module, so one walk decides
//! what "declared" means and a record moved into an inline `mod` cannot escape
//! two cases by escaping one walk.

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
        .filter(|block| is_closed_type(block, path))
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
        syn::ReturnType::Type(_, declared) => scan::type_text(declared),
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
    let text = scan::type_text(subject);
    text.split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("an impl block states no subject type: {text:?}"))
        .to_owned()
}

/// Whether an `impl` block belongs to a record or identity type. `GraphLimits`
/// is deliberately caller-constructible, so it is not one.
fn is_closed_type(block: &syn::ItemImpl, path: &str) -> bool {
    let text = scan::type_text(&block.self_ty);
    path != "src/limits.rs" && !text.contains("GraphRecords") && !text.contains("GraphLimits")
}

fn is_public(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Public(_))
}
