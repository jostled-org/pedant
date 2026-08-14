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
    "src/analysis/betweenness.rs",
    "src/analysis/components.rs",
    "src/analysis/degree.rs",
    "src/analysis/divergence.rs",
    "src/analysis/error.rs",
    "src/analysis/index.rs",
    "src/analysis/layout.rs",
    "src/analysis/limits.rs",
    "src/analysis/mod.rs",
    "src/analysis/partition.rs",
    "src/analysis/selection.rs",
    "src/analysis/traversal.rs",
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
        path: "src/analysis/betweenness.rs",
        text: include_str!("../../src/analysis/betweenness.rs"),
    },
    Source {
        path: "src/analysis/components.rs",
        text: include_str!("../../src/analysis/components.rs"),
    },
    Source {
        path: "src/analysis/degree.rs",
        text: include_str!("../../src/analysis/degree.rs"),
    },
    Source {
        path: "src/analysis/divergence.rs",
        text: include_str!("../../src/analysis/divergence.rs"),
    },
    Source {
        path: "src/analysis/error.rs",
        text: include_str!("../../src/analysis/error.rs"),
    },
    Source {
        path: "src/analysis/index.rs",
        text: include_str!("../../src/analysis/index.rs"),
    },
    Source {
        path: "src/analysis/layout.rs",
        text: include_str!("../../src/analysis/layout.rs"),
    },
    Source {
        path: "src/analysis/limits.rs",
        text: include_str!("../../src/analysis/limits.rs"),
    },
    Source {
        path: "src/analysis/mod.rs",
        text: include_str!("../../src/analysis/mod.rs"),
    },
    Source {
        path: "src/analysis/partition.rs",
        text: include_str!("../../src/analysis/partition.rs"),
    },
    Source {
        path: "src/analysis/selection.rs",
        text: include_str!("../../src/analysis/selection.rs"),
    },
    Source {
        path: "src/analysis/traversal.rs",
        text: include_str!("../../src/analysis/traversal.rs"),
    },
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

/// The registered test root, read at compile time.
///
/// Every `#[test]` wrapper this crate registers is declared there, so the
/// structural cases can hold each production module to a predicate that names
/// it without reading a file at run time.
pub const TEST_ROOT: &str = include_str!("../graph.rs");

/// This crate's tracked manifest, read at compile time.
///
/// The dependency and feature boundary is a property of the published package,
/// so the case that holds it to a model reads the manifest itself rather than a
/// lifecycle file describing it.
pub const MANIFEST: &str = include_str!("../../Cargo.toml");

/// One support module beside its compile-time contents.
///
/// Written as a list of module names: the path a case reports and the text it
/// reads are one entry, so a module cannot be scanned under a name the tree does
/// not hold.
macro_rules! support_sources {
    ($($name:literal),* $(,)?) => {
        &[$(Source {
            path: concat!("tests/graph_support/", $name, ".rs"),
            text: include_str!(concat!($name, ".rs")),
        }),*]
    };
}

/// Every support module beneath the one registered root.
///
/// The root owns every libtest identity this crate registers; these declare
/// fixtures, cases, and scanners. The inventory is compared with the tree, so a
/// module that appeared without an entry fails rather than escaping the scan.
pub const TEST_SUPPORT_SOURCES: &[Source] = support_sources![
    "analysis_centrality",
    "analysis_components",
    "analysis_derived_bounds",
    "analysis_derived_determinism",
    "analysis_determinism",
    "analysis_divergence",
    "analysis_divergence_model",
    "analysis_fixture",
    "analysis_layout",
    "analysis_oracle",
    "analysis_ownership",
    "analysis_ownership_bounds",
    "analysis_ownership_model",
    "analysis_partition",
    "analysis_perturbation",
    "analysis_selection",
    "analysis_source_boundary",
    "analysis_traversal",
    "contract",
    "corpus",
    "corpus_analysis",
    "corpus_generated",
    "defensive",
    "evidence",
    "fixture",
    "isolation",
    "mod",
    "ownership",
    "promotion",
    "render",
    "scan",
    "surface",
    "topology",
    "wire",
];

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
    token_text(&found.block)
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
