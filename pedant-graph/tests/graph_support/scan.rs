//! Readers over the sources [`super::inventory`] holds.
//!
//! One responsibility: turning a written-down source into the text, the parsed
//! items, or the single body a structural case reads. What may be read is the
//! inventory's to state; nothing here adds to it.
//!
//! The tree is listed at runtime in exactly one place, so a discovered set can
//! be compared with the inventory and reject a module that appeared without an
//! entry.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::inventory::SOURCES;

/// This crate's directory.
pub fn crate_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Every `.rs` file beneath `src`, manifest-relative and `/`-separated.
pub fn discovered_sources() -> BTreeSet<String> {
    discovered_beneath("src")
}

/// Every `.rs` file beneath `tests`, manifest-relative and `/`-separated.
pub fn discovered_test_sources() -> BTreeSet<String> {
    discovered_beneath("tests")
}

/// Every `.rs` file beneath one directory of this crate.
fn discovered_beneath(directory: &str) -> BTreeSet<String> {
    let root = crate_path(directory);
    let mut found = BTreeSet::new();
    collect(&root, &crate_path("."), &mut found);
    found
}

fn collect(directory: &Path, base: &Path, found: &mut BTreeSet<String>) {
    let listing = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
    for entry in listing {
        let listed = entry.unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
        let path = listed.path();
        // Read the kind rather than asking the path: an unreadable entry must
        // fail naming itself, and a symlink read as a directory would recurse
        // until the stack overflowed.
        let kind = listed
            .file_type()
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let is_rust = path.extension().is_some_and(|extension| extension == "rs");
        match (kind.is_dir(), is_rust) {
            (true, _) => collect(&path, base, found),
            (false, true) => {
                found.insert(relative_text(base, &path));
            }
            (false, false) => (),
        }
    }
}

fn relative_text(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or_else(|error| panic!("{} is outside {}: {error}", path.display(), base.display()))
        .to_str()
        .unwrap_or_else(|| panic!("{} is not valid UTF-8", path.display()))
        .replace('\\', "/")
}

/// One source with every comment line removed.
///
/// Ownership scans compare what the crate *does*, so prose that names a
/// forbidden entry point or a rejected derive must not read as the thing it
/// describes.
pub fn code_only(text: &str) -> String {
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with("# ")
        })
        .collect();
    kept.join("\n")
}

/// One source with every comment removed and every space dropped.
///
/// A call the formatter split across three lines is the same call, so a
/// structural case that names a receiver and its accessor compares a spelling
/// rather than a layout.
pub fn compact(text: &str) -> String {
    code_only(text).split_whitespace().collect()
}

/// The text of one modelled production source.
pub fn source(path: &str) -> &'static str {
    SOURCES
        .iter()
        .find(|source| source.path == path)
        .map(|source| source.text)
        .unwrap_or_else(|| panic!("{path} is not a modelled production source"))
}

/// One parsed production source.
pub fn parsed(path: &str) -> syn::File {
    syn::parse_file(source(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// The exact body text of one free function declared at a file's top level.
pub fn function_body(path: &str, name: &str) -> String {
    let file = parsed(path);
    let found = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{path} declares no fn {name}"));
    token_text(&found.block)
}

/// One method as the file declares it: on which subject, under which
/// visibility, with which body.
pub struct DeclaredMethod {
    /// The type the `impl` block states, shared by every method declared on it.
    pub subject: Arc<str>,
    /// The method's own name.
    pub name: String,
    /// The visibility token the declaration carries, empty when private.
    pub visibility: String,
    /// The exact body text.
    pub body: String,
}

/// Every method one source declares, in declaration order.
///
/// Inherent and trait `impl` blocks alike, each entry carrying the subject it
/// was declared on: a name alone does not identify a method, because one file
/// may state the same name on two types.
pub fn declared_methods(path: &str) -> Vec<DeclaredMethod> {
    let file = parsed(path);
    let mut found = Vec::new();
    for item in &file.items {
        let syn::Item::Impl(block) = item else {
            continue;
        };
        let subject: Arc<str> = Arc::from(token_text(&block.self_ty));
        for member in &block.items {
            if let syn::ImplItem::Fn(function) = member {
                found.push(DeclaredMethod {
                    subject: Arc::clone(&subject),
                    name: function.sig.ident.to_string(),
                    visibility: token_text(&function.vis),
                    body: token_text(&function.block),
                });
            }
        }
    }
    found
}

/// Every method one subject of one source declares, in declaration order.
pub fn subject_methods(path: &str, subject: &str) -> Vec<DeclaredMethod> {
    let found: Vec<DeclaredMethod> = declared_methods(path)
        .into_iter()
        .filter(|method| method.subject.as_ref() == subject)
        .collect();
    assert!(
        !found.is_empty(),
        "{path} declares no impl block for {subject}"
    );
    found
}

/// The exact body text of the one method one file declares under `name`.
///
/// A name that two subjects of one file both state is refused rather than
/// resolved. Binding to whichever `impl` was written first would let a case
/// examine a method it did not name, and leave the one it meant unread.
pub fn method_body(path: &str, name: &str) -> String {
    let found: Vec<DeclaredMethod> = declared_methods(path)
        .into_iter()
        .filter(|method| method.name == name)
        .collect();
    match found.len() {
        1 => single_body(found, path, name),
        0 => panic!("{path} declares no method {name}"),
        _ => {
            let subjects: Vec<Arc<str>> = found.into_iter().map(|method| method.subject).collect();
            panic!("{path} declares {name} on {subjects:?}: name the subject that owns it")
        }
    }
}

/// The exact body text of one method one named subject declares.
pub fn method_body_of(path: &str, subject: &str, name: &str) -> String {
    let found: Vec<DeclaredMethod> = subject_methods(path, subject)
        .into_iter()
        .filter(|method| method.name == name)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "{path} declares {subject}::{name} exactly once"
    );
    single_body(found, path, name)
}

/// The body of the one method a resolved lookup found.
fn single_body(found: Vec<DeclaredMethod>, path: &str, name: &str) -> String {
    found
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{path} declares no method {name}"))
        .body
}

/// One parsed item as the exact tokens it is written with.
///
/// Bodies, types, and signatures all render through here, so every structural
/// case compares one spelling of what the source states.
pub fn token_text<T: quote::ToTokens>(value: &T) -> String {
    value.to_token_stream().to_string()
}

/// Where `needle` first occurs in `haystack`, or a failure naming both.
pub fn position_of(haystack: &str, needle: &str, subject: &str) -> usize {
    haystack
        .find(needle)
        .unwrap_or_else(|| panic!("{subject} does not contain {needle:?}"))
}
