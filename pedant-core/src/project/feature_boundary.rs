use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use crate::check_config::{CheckConfig, FeatureBoundaryRule};
use crate::violation::{Violation, ViolationType};

use super::ProjectContext;
use super::cargo_meta::{CargoDependency, CargoMetadata, CargoPackage};

/// Enforce configured Cargo feature-boundary invariants against `cargo metadata`.
///
/// The model is a bounded traversal of declared features and dependency edges.
/// It captures the mainstream ways a feature is enabled (intra-package chains,
/// `dep/feat` cross edges, and default-feature propagation through normal/build
/// edges); exotic cases (weak-dep gating, target-cfg-specific unification) are
/// approximated conservatively.
pub(super) fn check_feature_boundary(
    ctx: &ProjectContext<'_>,
    config: &CheckConfig,
    violations: &mut Vec<Violation>,
) {
    if !config.check_feature_boundary {
        return;
    }
    let Some(metadata) = ctx.metadata else {
        return;
    };
    for rule in config.feature_boundaries.iter() {
        match rule.rule.as_ref() {
            "dev-only" => check_dev_only(metadata, rule, violations),
            "no-default" => check_no_default(metadata, rule, violations),
            _ => {}
        }
    }
}

fn emit(violations: &mut Vec<Violation>, message: String) {
    violations.push(Violation::new(
        ViolationType::FeatureBoundary,
        Arc::from("Cargo.toml"),
        1,
        1,
        message,
    ));
}

/// Flag any normal or build dependency edge that enables the constrained feature.
fn check_dev_only(
    meta: &CargoMetadata,
    rule: &FeatureBoundaryRule,
    violations: &mut Vec<Violation>,
) {
    let Some(target) = meta
        .packages
        .iter()
        .find(|p| p.name.as_str() == &*rule.package)
    else {
        return;
    };
    for pkg in &meta.packages {
        for dep in &pkg.dependencies {
            if dep.name.as_str() != &*rule.package || dep.kind.as_deref() == Some("dev") {
                continue;
            }
            if !edge_enables(target, dep, &rule.feature) {
                continue;
            }
            let kind = dep.kind.as_deref().unwrap_or("normal");
            emit(
                violations,
                format!(
                    "`{}` enables feature `{}` on `{}` through a {kind} dependency; `{}` must be enabled only via dev-dependencies",
                    pkg.name, rule.feature, rule.package, rule.feature
                ),
            );
        }
    }
}

/// Whether a single dependency edge requests the constrained feature.
fn edge_enables(target: &CargoPackage, dep: &CargoDependency, feature: &str) -> bool {
    let mut seeds: Vec<&str> = dep.features.iter().map(String::as_str).collect();
    if dep.uses_default_features {
        seeds.push("default");
    }
    feature_closure_contains(&target.features, &seeds, feature)
}

/// Whether `target` is reachable from `seeds` following only same-package,
/// plain-named feature edges (cross-package `dep/feat` items are ignored here).
fn feature_closure_contains(
    features: &BTreeMap<String, Vec<String>>,
    seeds: &[&str],
    target: &str,
) -> bool {
    let mut stack: Vec<&str> = seeds.to_vec();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    while let Some(feature) = stack.pop() {
        if feature == target {
            return true;
        }
        if !seen.insert(feature) {
            continue;
        }
        let Some(items) = features.get(feature) else {
            continue;
        };
        stack.extend(
            items
                .iter()
                .filter(|i| is_plain_feature(i))
                .map(String::as_str),
        );
    }
    false
}

fn is_plain_feature(item: &str) -> bool {
    !item.contains('/') && !item.contains(':')
}

/// Flag when the constrained feature is reachable from a workspace default build.
fn check_no_default(
    meta: &CargoMetadata,
    rule: &FeatureBoundaryRule,
    violations: &mut Vec<Violation>,
) {
    if default_reaches(meta, &rule.package, &rule.feature) {
        emit(
            violations,
            format!(
                "feature `{}` on `{}` is reachable from a crate default feature; it must not be default-enabled",
                rule.feature, rule.package
            ),
        );
    }
}

/// Fixpoint over `(package, feature)` activation from the workspace default
/// members' default features. An empty feature string marks a package as active.
fn default_reaches(meta: &CargoMetadata, target_pkg: &str, target_feat: &str) -> bool {
    let by_name: BTreeMap<&str, &CargoPackage> =
        meta.packages.iter().map(|p| (p.name.as_str(), p)).collect();

    let mut queue: VecDeque<(&str, &str)> = VecDeque::new();
    for id in root_member_ids(meta) {
        let Some(pkg) = meta.packages.iter().find(|p| &p.id == id) else {
            continue;
        };
        queue.push_back((pkg.name.as_str(), ""));
        queue.push_back((pkg.name.as_str(), "default"));
    }

    let mut active: BTreeSet<(&str, &str)> = BTreeSet::new();
    while let Some((pkg_name, feature)) = queue.pop_front() {
        if pkg_name == target_pkg && feature == target_feat {
            return true;
        }
        if !active.insert((pkg_name, feature)) {
            continue;
        }
        let Some(pkg) = by_name.get(pkg_name) else {
            continue;
        };
        match feature.is_empty() {
            true => enqueue_active_deps(pkg, &mut queue),
            false => enqueue_feature_items(pkg, feature, &mut queue),
        }
    }
    false
}

/// Workspace members built by default, falling back to all members.
fn root_member_ids(meta: &CargoMetadata) -> &[String] {
    match meta.workspace_default_members.is_empty() {
        false => &meta.workspace_default_members,
        true => &meta.workspace_members,
    }
}

/// An active package pulls in its non-dev, non-optional dependencies.
fn enqueue_active_deps<'a>(pkg: &'a CargoPackage, queue: &mut VecDeque<(&'a str, &'a str)>) {
    for dep in &pkg.dependencies {
        if dep.kind.as_deref() == Some("dev") || dep.optional {
            continue;
        }
        enqueue_dep(dep, queue);
    }
}

/// A feature enables plain same-package features, and features on dependencies
/// via `dep:name`, `name/feat`, and `name?/feat` items.
fn enqueue_feature_items<'a>(
    pkg: &'a CargoPackage,
    feature: &str,
    queue: &mut VecDeque<(&'a str, &'a str)>,
) {
    let Some(items) = pkg.features.get(feature) else {
        return;
    };
    for item in items {
        enqueue_feature_item(pkg, item, queue);
    }
}

fn enqueue_feature_item<'a>(
    pkg: &'a CargoPackage,
    item: &'a str,
    queue: &mut VecDeque<(&'a str, &'a str)>,
) {
    match parse_feature_item(item) {
        FeatureItem::Plain(name) => queue.push_back((pkg.name.as_str(), name)),
        FeatureItem::DepFeature { dep, feature } => enqueue_dep_feature(pkg, dep, feature, queue),
        FeatureItem::DepOnly(dep) => enqueue_dep_only(pkg, dep, queue),
    }
}

fn enqueue_dep_feature<'a>(
    pkg: &'a CargoPackage,
    dep: &str,
    feature: &'a str,
    queue: &mut VecDeque<(&'a str, &'a str)>,
) {
    let Some(declaration) = resolve_dep(pkg, dep) else {
        return;
    };
    enqueue_dep(declaration, queue);
    queue.push_back((declaration.name.as_str(), feature));
}

fn enqueue_dep_only<'a>(
    pkg: &'a CargoPackage,
    dep: &str,
    queue: &mut VecDeque<(&'a str, &'a str)>,
) {
    let Some(declaration) = resolve_dep(pkg, dep) else {
        return;
    };
    enqueue_dep(declaration, queue);
}

/// Activate a dependency: mark it present, enable its default features (when
/// requested), and enable the features the edge names.
fn enqueue_dep<'a>(dep: &'a CargoDependency, queue: &mut VecDeque<(&'a str, &'a str)>) {
    queue.push_back((dep.name.as_str(), ""));
    if dep.uses_default_features {
        queue.push_back((dep.name.as_str(), "default"));
    }
    for feature in &dep.features {
        queue.push_back((dep.name.as_str(), feature));
    }
}

fn resolve_dep<'a>(pkg: &'a CargoPackage, local: &str) -> Option<&'a CargoDependency> {
    pkg.dependencies.iter().find(|d| d.local_name() == local)
}

enum FeatureItem<'a> {
    Plain(&'a str),
    DepOnly(&'a str),
    DepFeature { dep: &'a str, feature: &'a str },
}

fn parse_feature_item(item: &str) -> FeatureItem<'_> {
    if let Some(rest) = item.strip_prefix("dep:") {
        return FeatureItem::DepOnly(rest);
    }
    match item.split_once('/') {
        Some((dep, feature)) => FeatureItem::DepFeature {
            dep: dep.trim_end_matches('?'),
            feature,
        },
        None => FeatureItem::Plain(item),
    }
}
