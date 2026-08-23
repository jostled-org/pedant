//! The published release graph, written down, and the readers that take the
//! tracked manifests it is compared against.
//!
//! The model sits beside its cases rather than inside them, the way
//! `packaged_workspace_claims` sits beside `packaged_workspace`.
//! [`crate::release_contract`] holds the claims; this holds what a claim is
//! about and how a manifest is read.

use crate::resolution::authority_scan::read_text;

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
#[derive(Clone, Copy, PartialEq, Eq)]
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

/// The one gated edge: its consumer, the package it requires, and the feature
/// that has to select it.
///
/// The Go resolution surface is why `pedant-syntax` releases before
/// `pedant-core`. Cargo replaces the path edge with a registry edge while
/// packaging, and it does that for an optional dependency exactly as it does
/// for an unconditional one — so the release order this edge forces is owed
/// whether or not a consumer turns the feature on.
pub(crate) const GATED_EDGE: (&str, &str, &str) = ("pedant-core", "pedant-syntax", "go-resolution");

/// The manifest tables a first-party requirement may be stated in.
const DEPENDENCY_KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

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

/// One tracked manifest, parsed.
pub(crate) fn parse_toml(relative: &str) -> toml::Table {
    toml::from_str(&read_text(relative)).unwrap_or_else(|error| panic!("{relative}: {error}"))
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

/// One manifest's features, as the name and the list each selects.
pub(crate) fn features(manifest: &toml::Table) -> impl Iterator<Item = (&str, Box<[Box<str>]>)> {
    manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|table| table.iter())
        .map(|(name, selects)| (name.as_str(), string_list(selects)))
}

/// What a manifest's `default` feature selects, empty when it declares none.
pub(crate) fn default_selection(manifest: &toml::Table) -> Box<[Box<str>]> {
    features(manifest)
        .find(|(name, _)| *name == "default")
        .map(|(_, selects)| selects)
        .unwrap_or_default()
}

fn string_list(value: &toml::Value) -> Box<[Box<str>]> {
    value
        .as_array()
        .expect("a feature selects a list")
        .iter()
        .map(|entry| entry.as_str().expect("a feature entry is a string").into())
        .collect()
}
