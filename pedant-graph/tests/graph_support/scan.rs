//! Readers over this crate's own production sources.
//!
//! The structural predicates compare a written-down model with the tree, so the
//! discovered set is checked against a fixed inventory before anything is
//! scanned: a discovered-only set would agree with whatever the crate happens
//! to contain and could never reject a module that appeared.
//!
//! `include_str!` reads at compile time, so no case here performs a runtime
//! file read or gives the graph crate a feature.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Every production source of this crate, repository-relative to its manifest.
///
/// Written down, never discovered. `graph_projection_uses_only_supplied_resolution_facts`
/// compares it with the tree and fails on a missing or an extra entry.
pub const PRODUCTION_SOURCES: &[&str] = &[
    "src/containment.rs",
    "src/edge.rs",
    "src/error.rs",
    "src/graph.rs",
    "src/id.rs",
    "src/lib.rs",
    "src/limits.rs",
    "src/node.rs",
    "src/reference.rs",
    "src/rust/entry.rs",
    "src/rust/index.rs",
    "src/rust/mapping.rs",
    "src/rust/mod.rs",
    "src/rust/projection.rs",
    "src/rust/validation.rs",
];

/// One production source and its exact text.
pub struct Source {
    /// The manifest-relative path.
    pub path: &'static str,
    /// The exact file contents.
    pub text: &'static str,
}

/// Every production source with its compile-time contents.
///
/// The array and [`PRODUCTION_SOURCES`] are compared against each other and
/// against the tree, so a file that stopped being scanned fails rather than
/// silently narrows the search set.
pub const SOURCES: &[Source] = &[
    Source {
        path: "src/containment.rs",
        text: include_str!("../../src/containment.rs"),
    },
    Source {
        path: "src/edge.rs",
        text: include_str!("../../src/edge.rs"),
    },
    Source {
        path: "src/error.rs",
        text: include_str!("../../src/error.rs"),
    },
    Source {
        path: "src/graph.rs",
        text: include_str!("../../src/graph.rs"),
    },
    Source {
        path: "src/id.rs",
        text: include_str!("../../src/id.rs"),
    },
    Source {
        path: "src/lib.rs",
        text: include_str!("../../src/lib.rs"),
    },
    Source {
        path: "src/limits.rs",
        text: include_str!("../../src/limits.rs"),
    },
    Source {
        path: "src/node.rs",
        text: include_str!("../../src/node.rs"),
    },
    Source {
        path: "src/reference.rs",
        text: include_str!("../../src/reference.rs"),
    },
    Source {
        path: "src/rust/entry.rs",
        text: include_str!("../../src/rust/entry.rs"),
    },
    Source {
        path: "src/rust/index.rs",
        text: include_str!("../../src/rust/index.rs"),
    },
    Source {
        path: "src/rust/mapping.rs",
        text: include_str!("../../src/rust/mapping.rs"),
    },
    Source {
        path: "src/rust/mod.rs",
        text: include_str!("../../src/rust/mod.rs"),
    },
    Source {
        path: "src/rust/projection.rs",
        text: include_str!("../../src/rust/projection.rs"),
    },
    Source {
        path: "src/rust/validation.rs",
        text: include_str!("../../src/rust/validation.rs"),
    },
];

/// This crate's directory.
pub fn crate_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Every `.rs` file beneath `src`, manifest-relative and `/`-separated.
pub fn discovered_sources() -> BTreeSet<String> {
    let root = crate_path("src");
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
    quote_text(&found.block)
}

/// The exact body text of one method declared in an inherent or trait `impl`.
pub fn method_body(path: &str, name: &str) -> String {
    let file = parsed(path);
    let found = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(block) => Some(block),
            _ => None,
        })
        .flat_map(|block| &block.items)
        .find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{path} declares no method {name}"));
    quote_text(&found.block)
}

fn quote_text(block: &syn::Block) -> String {
    use quote::ToTokens;
    block.to_token_stream().to_string()
}

/// One type as its token text, for an `impl` block's subject.
pub fn type_text(subject: &syn::Type) -> String {
    use quote::ToTokens;
    subject.to_token_stream().to_string()
}

/// Where `needle` first occurs in `haystack`, or a failure naming both.
pub fn position_of(haystack: &str, needle: &str, subject: &str) -> usize {
    haystack
        .find(needle)
        .unwrap_or_else(|| panic!("{subject} does not contain {needle:?}"))
}
