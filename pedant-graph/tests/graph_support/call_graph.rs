//! Which declared function reaches which, in one parsed production source.
//!
//! [`super::surface`] answers what a source declares; this answers what those
//! declarations call. The two are separate questions — a bounds case reads the
//! call structure and never the fields, an ownership case the reverse — and one
//! walk decides what "calls" means for both.

use std::collections::{BTreeMap, BTreeSet};

use super::scan::{self, parsed};
use super::surface::declared_items;

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
