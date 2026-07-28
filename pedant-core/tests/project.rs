#![cfg(feature = "checks")]
use std::path::Path;

use pedant_core::check_config::{CheckConfig, FlatModuleFamily};
use pedant_core::project::{ProjectContext, check_project};
use pedant_core::violation::Violation;
use pedant_core::violation::ViolationType;

fn conflicting_config() -> CheckConfig {
    CheckConfig {
        check_conflicting_module_root: true,
        ..CheckConfig::default()
    }
}

fn paths(root: &Path, rels: &[&str]) -> Vec<String> {
    rels.iter()
        .map(|rel| root.join(rel).to_string_lossy().into_owned())
        .collect()
}

fn conflicts(files: &[String], root: &Path, config: &CheckConfig) -> Vec<String> {
    let ctx = ProjectContext {
        rust_files: files,
        workspace_root: root,
        metadata: None,
        file_shapes: &[],
    };
    project_violations(&ctx, config)
        .into_iter()
        .filter(|v| matches!(v.violation_type, ViolationType::ConflictingModuleRoot))
        .map(|v| v.file_path.to_string())
        .collect()
}

#[test]
fn test_conflicting_module_root_flags_stem_beside_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src/foo")).unwrap();
    std::fs::write(root.join("src/foo.rs"), "").unwrap();
    std::fs::write(root.join("src/foo/mod.rs"), "").unwrap();
    std::fs::write(root.join("src/bar.rs"), "").unwrap();

    let files = paths(root, &["src/foo.rs", "src/bar.rs", "src/foo/mod.rs"]);
    let hits = conflicts(&files, root, &conflicting_config());
    // foo.rs conflicts with foo/; bar.rs has no sibling dir; mod.rs is exempt.
    assert_eq!(hits.len(), 1);
    assert!(hits[0].ends_with("foo.rs"));
}

#[test]
fn test_conflicting_module_root_exempts_mod_and_lib() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src/lib")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "").unwrap();
    std::fs::create_dir_all(root.join("nested/mod")).unwrap();
    std::fs::write(root.join("nested/mod.rs"), "").unwrap();

    let files = paths(root, &["src/lib.rs", "nested/mod.rs"]);
    assert!(conflicts(&files, root, &conflicting_config()).is_empty());
}

#[test]
fn test_conflicting_module_root_disabled_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src/foo")).unwrap();
    std::fs::write(root.join("src/foo.rs"), "").unwrap();

    let files = paths(root, &["src/foo.rs"]);
    assert!(conflicts(&files, root, &CheckConfig::default()).is_empty());
}

fn flat_family_hits(root: &Path, config: &CheckConfig) -> Vec<String> {
    let ctx = ProjectContext {
        rust_files: &[],
        workspace_root: root,
        metadata: None,
        file_shapes: &[],
    };
    project_violations(&ctx, config)
        .into_iter()
        .filter(|v| matches!(v.violation_type, ViolationType::FlatModuleFamily))
        .map(|v| v.file_path.to_string())
        .collect()
}

fn engine_family() -> Vec<FlatModuleFamily> {
    vec![FlatModuleFamily {
        parent: "src".into(),
        package_root: "engine".into(),
        prefix: "engine".into(),
    }]
}

fn make_engine_tree(root: &Path) {
    std::fs::create_dir_all(root.join("src/engine")).unwrap();
    std::fs::write(root.join("src/engine/mod.rs"), "").unwrap();
    std::fs::write(root.join("src/engine.rs"), "").unwrap(); // prefix.rs
    std::fs::write(root.join("src/engine_util.rs"), "").unwrap(); // prefix_*.rs
    std::fs::create_dir_all(root.join("src/engine_helpers")).unwrap(); // prefix_*/
    std::fs::write(root.join("src/other.rs"), "").unwrap(); // unrelated
    std::fs::write(root.join("src/enginex.rs"), "").unwrap(); // not prefix_ and not exact
}

#[test]
fn test_flat_module_family_flags_flat_members() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    make_engine_tree(root);

    let config = CheckConfig {
        flat_module_families: engine_family().into(),
        ..CheckConfig::default()
    };
    let hits = flat_family_hits(root, &config);
    // engine.rs, engine_util.rs, engine_helpers/ — home dir and unrelated files clean.
    assert_eq!(hits.len(), 3, "got: {hits:?}");
    assert!(hits.iter().any(|f| f.ends_with("src/engine.rs")));
    assert!(hits.iter().any(|f| f.ends_with("src/engine_util.rs")));
    assert!(hits.iter().any(|f| f.ends_with("src/engine_helpers")));
    assert!(hits.iter().all(|f| !f.contains("other")));
    assert!(hits.iter().all(|f| !f.contains("enginex")));
}

#[test]
fn test_flat_module_family_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    make_engine_tree(root);

    let config = CheckConfig {
        check_flat_module_family: false,
        flat_module_families: engine_family().into(),
        ..CheckConfig::default()
    };
    assert!(flat_family_hits(root, &config).is_empty());
}

#[test]
fn test_flat_module_family_inert_without_rules() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    make_engine_tree(root);
    // Enabled by default, but no families configured -> nothing flagged.
    assert!(flat_family_hits(root, &CheckConfig::default()).is_empty());
}

// --- feature-boundary ---

use pedant_core::check_config::FeatureBoundaryRule;
use pedant_core::project::{CargoDependency, CargoMetadata, CargoPackage};

fn dep(name: &str, kind: Option<&str>, features: &[&str]) -> CargoDependency {
    CargoDependency {
        name: name.into(),
        kind: kind.map(String::from),
        features: features.iter().map(|s| s.to_string()).collect(),
        uses_default_features: true,
        optional: false,
        rename: None,
    }
}

fn pkg(name: &str, features: &[(&str, &[&str])], deps: Vec<CargoDependency>) -> CargoPackage {
    CargoPackage {
        name: name.into(),
        id: format!("{name}-id"),
        features: features
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect(),
        dependencies: deps,
    }
}

fn fb_rule(package: &str, feature: &str, rule: &str) -> FeatureBoundaryRule {
    FeatureBoundaryRule {
        package: package.into(),
        feature: feature.into(),
        rule: rule.into(),
    }
}

fn fb_config(rules: Vec<FeatureBoundaryRule>) -> CheckConfig {
    CheckConfig {
        feature_boundaries: rules.into(),
        ..CheckConfig::default()
    }
}

fn fb_hits(meta: &CargoMetadata, config: &CheckConfig) -> Vec<String> {
    let ctx = ProjectContext {
        rust_files: &[],
        workspace_root: Path::new("."),
        metadata: Some(meta),
        file_shapes: &[],
    };
    project_violations(&ctx, config)
        .into_iter()
        .filter(|v| matches!(v.violation_type, ViolationType::FeatureBoundary))
        .map(|v| v.message.to_string())
        .collect()
}

fn meta(packages: Vec<CargoPackage>, default_member: &str) -> CargoMetadata {
    CargoMetadata {
        packages,
        workspace_default_members: vec![format!("{default_member}-id")],
        workspace_members: vec![format!("{default_member}-id")],
    }
}

#[test]
fn test_feature_boundary_dev_only_flags_normal_edge() {
    let lib = pkg("lib", &[("test-support", &[])], vec![]);
    let consumer = pkg("consumer", &[], vec![dep("lib", None, &["test-support"])]);
    let m = meta(vec![lib, consumer], "consumer");
    let hits = fb_hits(
        &m,
        &fb_config(vec![fb_rule("lib", "test-support", "dev-only")]),
    );
    assert_eq!(hits.len(), 1, "got: {hits:?}");
    assert!(hits[0].contains("consumer") && hits[0].contains("test-support"));
}

#[test]
fn test_feature_boundary_dev_only_allows_dev_edge() {
    let lib = pkg("lib", &[("test-support", &[])], vec![]);
    let consumer = pkg(
        "consumer",
        &[],
        vec![dep("lib", Some("dev"), &["test-support"])],
    );
    let m = meta(vec![lib, consumer], "consumer");
    assert!(
        fb_hits(
            &m,
            &fb_config(vec![fb_rule("lib", "test-support", "dev-only")])
        )
        .is_empty()
    );
}

#[test]
fn test_feature_boundary_no_default_flags_default_chain() {
    let lib = pkg(
        "lib",
        &[("default", &["test-support"]), ("test-support", &[])],
        vec![],
    );
    let m = meta(vec![lib], "lib");
    let hits = fb_hits(
        &m,
        &fb_config(vec![fb_rule("lib", "test-support", "no-default")]),
    );
    assert_eq!(hits.len(), 1, "got: {hits:?}");
    assert!(hits[0].contains("default"));
}

#[test]
fn test_feature_boundary_no_default_flags_transitive_default() {
    // consumer (workspace member) --normal, default-features--> lib; lib default enables the feature.
    let lib = pkg(
        "lib",
        &[("default", &["test-support"]), ("test-support", &[])],
        vec![],
    );
    let consumer = pkg("consumer", &[], vec![dep("lib", None, &[])]);
    let m = meta(vec![lib, consumer], "consumer");
    let hits = fb_hits(
        &m,
        &fb_config(vec![fb_rule("lib", "test-support", "no-default")]),
    );
    assert_eq!(hits.len(), 1, "got: {hits:?}");
}

#[test]
fn test_feature_boundary_no_default_clean_when_unreachable() {
    let lib = pkg(
        "lib",
        &[("default", &["std"]), ("std", &[]), ("test-support", &[])],
        vec![],
    );
    let m = meta(vec![lib], "lib");
    assert!(
        fb_hits(
            &m,
            &fb_config(vec![fb_rule("lib", "test-support", "no-default")])
        )
        .is_empty()
    );
}

#[test]
fn test_feature_boundary_disabled() {
    let lib = pkg("lib", &[("test-support", &[])], vec![]);
    let consumer = pkg("consumer", &[], vec![dep("lib", None, &["test-support"])]);
    let m = meta(vec![lib, consumer], "consumer");
    let config = CheckConfig {
        check_feature_boundary: false,
        feature_boundaries: vec![fb_rule("lib", "test-support", "dev-only")].into(),
        ..CheckConfig::default()
    };
    assert!(fb_hits(&m, &config).is_empty());
}

/// `check_project` appends to a caller-owned list so a whole-crate check can
/// supersede a per-file one; these tests only care about what it adds.
fn project_violations(ctx: &ProjectContext<'_>, config: &CheckConfig) -> Vec<Violation> {
    let mut violations = Vec::new();
    check_project(ctx, config, &mut violations);
    violations
}
