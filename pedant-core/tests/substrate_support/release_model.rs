//! The published release graph, written down, and the readings taken of the
//! `release-plz.toml` it is compared against.
//!
//! The model sits beside its cases rather than inside them, the way
//! `packaged_workspace_claims` sits beside `packaged_workspace`.
//! [`crate::release_contract`] holds the claims and this holds what a claim is
//! about. How a manifest is read belongs to
//! [`crate::resolution::manifest_reader`], which every structural claim in this
//! repository shares — including which tables a requirement can be stated in.

use crate::resolution::manifest_reader::DEPENDENCY_KINDS;

/// Every published package, in the order `release-plz.toml` must publish them.
///
/// The names and their order are written down rather than derived: a topological
/// sort of the manifests would agree with any order the manifests happen to have,
/// which is the fact under test.
///
/// The versions are not written down. release-plz owns every version in this
/// workspace and bumps them in a `chore: release` commit that never consults
/// this module, so a pinned version here asserts only that a copy of a manifest
/// matches the manifest, and goes stale on the release after every edit. The
/// load-bearing facts — a requirement equals the version its dependency
/// declares, and a dependency is released first — hold against the versions this
/// module reads.
pub(crate) const PUBLISHED: [&str; 8] = [
    "pedant-types",
    "pedant-syntax",
    "pedant-core",
    "pedant-graph",
    "pedant-snippet",
    "pedant-lang",
    "pedant-mcp",
    "pedant",
];

/// How a consumer takes one first-party edge.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Selection {
    /// Every build of the consumer links it.
    Always,
    /// Only a build that turns on the gating feature links it.
    Gated,
}

use Selection::{Always, Gated};

/// Every first-party requirement the published workspace states: the consumer,
/// the manifest table that carries it, the package required, and how the
/// consumer takes it.
///
/// Written down rather than derived. A set taken from the manifests would agree
/// with whatever the manifests hold, and the failure this rejects is a new edge
/// nobody noticed — an unconditional one that makes an unreleased package a
/// registry requirement, or a second gated one that quietly widens what a
/// default build links. The versions are deliberately absent for the reason
/// [`PUBLISHED`] states.
pub(crate) const FIRST_PARTY_EDGES: &[(&str, &str, &str, Selection)] = &[
    ("pedant-syntax", "dependencies", "pedant-types", Always),
    ("pedant-core", "dependencies", "pedant-types", Always),
    ("pedant-core", "dependencies", "pedant-syntax", Gated),
    ("pedant-graph", "dependencies", "pedant-core", Always),
    ("pedant-graph", "dependencies", "pedant-types", Always),
    ("pedant-graph", "dev-dependencies", "pedant-core", Always),
    ("pedant-snippet", "dependencies", "pedant-syntax", Always),
    ("pedant-snippet", "dependencies", "pedant-types", Always),
    ("pedant-snippet", "dependencies", "pedant-core", Gated),
    ("pedant-snippet", "dependencies", "pedant-graph", Gated),
    ("pedant-lang", "dependencies", "pedant-syntax", Always),
    ("pedant-lang", "dependencies", "pedant-types", Always),
    ("pedant-mcp", "dependencies", "pedant-core", Always),
    ("pedant-mcp", "dependencies", "pedant-lang", Always),
    ("pedant-mcp", "dependencies", "pedant-types", Always),
    ("pedant", "dependencies", "pedant-core", Always),
    ("pedant", "dependencies", "pedant-graph", Always),
    ("pedant", "dependencies", "pedant-lang", Always),
    ("pedant", "dependencies", "pedant-types", Always),
];

/// One optional first-party edge, and the features that select it.
pub(crate) struct GatedEdge {
    /// The package whose manifest declares the edge.
    pub(crate) consumer: &'static str,
    /// The published package it requires.
    pub(crate) dependency: &'static str,
    /// Every feature that selects it, in name order.
    ///
    /// The whole set is the claim. A second feature nobody wrote down is a
    /// second way to link the dependency, and a membership check would agree
    /// with it.
    pub(crate) selectors: &'static [&'static str],
    /// Whether the consumer's own default selection turns it on.
    pub(crate) default_on: bool,
}

impl GatedEdge {
    /// How [`FIRST_PARTY_EDGES`] must state this same edge.
    ///
    /// A gate is an `optional` dependency, so the row it owes is a [`Gated`]
    /// one. The selection lives with the type that implies it rather than in a
    /// literal beside the comparison: the two tables describe one manifest from
    /// two directions, and a caller free to name the selection itself is a
    /// caller free to name the wrong one.
    pub(crate) fn selection(&self) -> Selection {
        Gated
    }
}

/// Every gated first-party edge in the published workspace.
///
/// The Go resolution surface is why `pedant-syntax` releases before
/// `pedant-core`, and the two code-intelligence edges are why `pedant-core` and
/// `pedant-graph` release before `pedant-snippet`. Cargo replaces a path edge
/// with a registry edge while packaging, and it does that for an optional
/// dependency exactly as it does for an unconditional one — so the release
/// order these edges force is owed whether or not a consumer turns the feature
/// on.
///
/// `default_on` is the difference between the two kinds of gate. `pedant-core`
/// keeps the Go grammar off unless a consumer asks, because a build that asked
/// for something else must not link a parser. `pedant-snippet` is an installed
/// application whose whole job is answering for a mixed repository, so its
/// default turns both graph producers on and a library consumer opts down.
pub(crate) const GATED_EDGES: &[GatedEdge] = &[
    GatedEdge {
        consumer: "pedant-core",
        dependency: "pedant-syntax",
        selectors: &["go-resolution"],
        default_on: false,
    },
    GatedEdge {
        consumer: "pedant-snippet",
        dependency: "pedant-core",
        selectors: &["graph-go", "graph-rust"],
        default_on: true,
    },
    GatedEdge {
        consumer: "pedant-snippet",
        dependency: "pedant-graph",
        selectors: &["graph-go", "graph-rust"],
        default_on: true,
    },
];

/// One first-party requirement, as the manifest that states it spells it.
pub(crate) struct StatedRequirement {
    /// The manifest table it sits in, which decides whether a consumer of the
    /// published archive receives it.
    pub(crate) kind: Box<str>,
    /// The published package required.
    pub(crate) dependency: Box<str>,
    /// The version required, which packaging turns into a registry requirement.
    pub(crate) version: Box<str>,
    /// How the consumer takes it.
    pub(crate) selection: Selection,
}

/// Every first-party requirement a manifest states, across dependency kinds.
pub(crate) fn stated_requirements(manifest: &toml::Table, name: &str) -> Box<[StatedRequirement]> {
    DEPENDENCY_KINDS
        .iter()
        .filter_map(|kind| {
            manifest
                .get(*kind)
                .and_then(toml::Value::as_table)
                .map(|table| (*kind, table))
        })
        .flat_map(|(kind, table)| table.iter().map(move |(name, spec)| (kind, name, spec)))
        .filter(|(_, dependency, _)| PUBLISHED.contains(&dependency.as_str()))
        .map(|(kind, dependency, spec)| StatedRequirement {
            kind: kind.into(),
            dependency: dependency.as_str().into(),
            version: spec
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("{name} requires {dependency} without a version"))
                .into(),
            selection: match spec.get("optional").and_then(toml::Value::as_bool) {
                Some(true) => Gated,
                _ => Always,
            },
        })
        .collect()
}

/// One edge as both the model and the manifests are compared as.
pub(crate) fn edge_line(
    consumer: &str,
    kind: &str,
    dependency: &str,
    selection: Selection,
) -> Box<str> {
    let taken = match selection {
        Always => "always",
        Gated => "gated",
    };
    format!("{consumer} {kind} {dependency} {taken}").into()
}

/// Every package `release-plz.toml` names, in the order it releases them.
pub(crate) fn release_entries(release: &toml::Table) -> Box<[&str]> {
    release_packages(release)
        .map(|entry| {
            entry
                .get("name")
                .and_then(toml::Value::as_str)
                .expect("every release-plz entry names a package")
        })
        .collect()
}

/// Where release-plz writes one package's changelog: the path its entry states,
/// or the per-package default it uses when the entry states none.
pub(crate) fn changelog_path(release: &toml::Table, package: &str) -> Box<str> {
    release_entry(release, package)
        .and_then(|entry| entry.get("changelog_path"))
        .and_then(toml::Value::as_str)
        .map_or_else(
            || format!("{package}/CHANGELOG.md").into(),
            |declared| declared.into(),
        )
}

/// The `release-plz.toml` entry that names one package, if it has one.
pub(crate) fn release_entry<'a>(
    release: &'a toml::Table,
    package: &str,
) -> Option<&'a toml::Value> {
    release_packages(release)
        .find(|entry| entry.get("name").and_then(toml::Value::as_str) == Some(package))
}

/// Every entry of the release table, in the order it holds them.
fn release_packages(release: &toml::Table) -> impl Iterator<Item = &toml::Value> {
    release
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("release-plz.toml declares a package array")
        .iter()
}

/// The version a manifest's `[package]` declares.
pub(crate) fn declared_version(manifest: &toml::Table, name: &str) -> Box<str> {
    manifest
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("{name} declares no package version"))
        .into()
}
