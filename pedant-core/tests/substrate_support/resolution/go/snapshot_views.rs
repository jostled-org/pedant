//! Flat renderings of a completed Go resolution snapshot.
//!
//! Whole ordered lists are compared against written-down tables, so a unit,
//! edge, source, or predicate that was gained, lost, or reordered fails the
//! comparison rather than slipping past an assertion that never asked.

use pedant_core::resolution::go::{
    GoBuildCondition, GoResolutionSnapshot, GoSnapshotModule, GoSource,
};

/// `<module path>|<directory>|<manifest>|<depth>` for every snapshot module.
pub fn modules(snapshot: &GoResolutionSnapshot) -> Box<[Box<str>]> {
    snapshot.modules().iter().map(module_text).collect()
}

fn module_text(module: &GoSnapshotModule) -> Box<str> {
    format!(
        "{}|{}|{}|{}",
        module.path(),
        module.directory(),
        module.manifest(),
        module.depth()
    )
    .into_boxed_str()
}

/// `<module path>|<context>|<import path>|<package>|<directory>|<sources>` for
/// every package unit, in snapshot order.
pub fn units(snapshot: &GoResolutionSnapshot) -> Box<[Box<str>]> {
    snapshot
        .units()
        .iter()
        .map(|unit| {
            let module = snapshot
                .module(unit.module())
                .expect("a unit names a module of its own snapshot");
            let sources: Box<[&str]> = unit.sources().iter().map(|path| &**path).collect();
            format!(
                "{}|{}|{}|{}|{}|{}",
                module.path(),
                unit.context().token(),
                unit.import_path(),
                unit.package_name(),
                unit.directory(),
                sources.join(",")
            )
            .into_boxed_str()
        })
        .collect()
}

/// `<declaring module>|<required module>|<required path>|<version>` for every
/// local module edge.
pub fn edges(snapshot: &GoResolutionSnapshot) -> Box<[Box<str>]> {
    snapshot
        .edges()
        .iter()
        .map(|edge| {
            let source = snapshot
                .module(edge.source())
                .expect("an edge names a module of its own snapshot");
            let target = snapshot
                .module(edge.target())
                .expect("an edge names a module of its own snapshot");
            format!(
                "{}|{}|{}|{}",
                source.path(),
                target.path(),
                edge.module_path(),
                edge.version()
            )
            .into_boxed_str()
        })
        .collect()
}

/// The repository-relative path of every distinct stored source, in snapshot
/// order.
pub fn source_paths(snapshot: &GoResolutionSnapshot) -> Box<[Box<str>]> {
    snapshot
        .sources()
        .iter()
        .map(|source| Box::from(source.path()))
        .collect()
}

/// `<path>|<predicates>` for every stored source, in snapshot order.
pub fn source_conditions(snapshot: &GoResolutionSnapshot) -> Box<[Box<str>]> {
    snapshot
        .sources()
        .iter()
        .map(|source| {
            let stated: Box<[Box<str>]> = source.conditions().iter().map(condition_text).collect();
            let borrowed: Box<[&str]> = stated.iter().map(|text| &**text).collect();
            format!("{}|{}", source.path(), borrowed.join(",")).into_boxed_str()
        })
        .collect()
}

fn condition_text(condition: &GoBuildCondition) -> Box<str> {
    match condition {
        GoBuildCondition::Stated { kind, constraint } => {
            format!("stated:{}:{constraint}", kind_token(*kind)).into_boxed_str()
        }
        GoBuildCondition::PlatformSuffix { term } => format!("suffix:{term}").into_boxed_str(),
        GoBuildCondition::TestContext => Box::from("test"),
        GoBuildCondition::ForeignFunctions => Box::from("foreign"),
    }
}

fn kind_token(kind: pedant_core::resolution::go::GoBuildConditionKind) -> &'static str {
    match kind {
        pedant_core::resolution::go::GoBuildConditionKind::GoBuild => "directive",
        pedant_core::resolution::go::GoBuildConditionKind::LegacyBuildTag => "legacy",
    }
}

/// `<path>|<declared package>|<declarations>|<imports>` for every stored
/// source, which is what proves the retained fact inventory is the source's own.
pub fn source_facts(snapshot: &GoResolutionSnapshot) -> Box<[Box<str>]> {
    snapshot.sources().iter().map(source_fact_text).collect()
}

fn source_fact_text(source: &GoSource) -> Box<str> {
    let facts = source.facts();
    let declarations: Box<[Box<str>]> = facts
        .declarations()
        .iter()
        .map(|declaration| format!("{:?}:{}", declaration.kind(), declaration.name()).into())
        .collect();
    let imports: Box<[Box<str>]> = facts
        .imports()
        .iter()
        .map(|import| Box::from(import.path()))
        .collect();
    let declared: Box<[&str]> = declarations.iter().map(|text| &**text).collect();
    let imported: Box<[&str]> = imports.iter().map(|text| &**text).collect();
    format!(
        "{}|{}|{}|{}",
        source.path(),
        facts.package_name().unwrap_or(""),
        declared.join(","),
        imported.join(",")
    )
    .into_boxed_str()
}
