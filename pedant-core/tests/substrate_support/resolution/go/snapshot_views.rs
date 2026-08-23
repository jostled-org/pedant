//! Flat renderings of a completed Go resolution snapshot.
//!
//! Whole ordered lists are compared against written-down tables, so a unit,
//! edge, source, or predicate that was gained, lost, or reordered fails the
//! comparison rather than slipping past an assertion that never asked.

/// Named only by the module rendering, which the package-walk case alone reads.
#[cfg(feature = "resolution-test-support")]
use pedant_core::resolution::go::GoSnapshotModule;
use pedant_core::resolution::go::{
    GoBindingRecord, GoBuildCondition, GoDeclarationRecord, GoInitializerForm,
    GoResolutionSnapshot, GoSource,
};

/// `<module path>|<directory>|<manifest>|<depth>` for every snapshot module.
///
/// Read by the package-walk case alone, which carries the observation probe.
#[cfg(feature = "resolution-test-support")]
pub fn modules(snapshot: &GoResolutionSnapshot) -> Box<[Box<str>]> {
    snapshot.modules().iter().map(module_text).collect()
}

#[cfg(feature = "resolution-test-support")]
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
///
/// Read by the package-walk case alone, which carries the observation probe.
#[cfg(feature = "resolution-test-support")]
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

/// `<path>|<name>|<form>|<qualifier>|<type>|<pointer>` for every name a stored
/// source binds, in snapshot order, with `none` where the binding states no
/// initializer.
///
/// The retained initializer is the only evidence of what a short variable
/// declaration binds, and every receiver a method call is resolved from reads
/// it. Rendering every binding rather than the ones that carry one is what makes
/// a fabricated initializer as visible as a dropped one.
pub fn source_initializers(snapshot: &GoResolutionSnapshot) -> Box<[Box<str>]> {
    snapshot
        .sources()
        .iter()
        .flat_map(|source| {
            source
                .facts()
                .bindings()
                .iter()
                .map(|bound| initializer_text(source.path(), bound))
        })
        .collect()
}

fn initializer_text(path: &str, bound: &GoBindingRecord) -> Box<str> {
    match bound.initializer() {
        None => format!("{path}|{}|none", bound.name()).into_boxed_str(),
        Some(stated) => format!(
            "{path}|{}|{}|{}|{}|{}",
            bound.name(),
            form_token(stated.form()),
            stated.qualifier().unwrap_or("-"),
            stated.name(),
            stated.pointer()
        )
        .into_boxed_str(),
    }
}

/// The spelling one initializer form is written down as.
///
/// Spelled out rather than derived from `Debug`, so a form added to the closed
/// set is a table the cases must revise rather than a row whose text changes
/// under them.
fn form_token(form: GoInitializerForm) -> &'static str {
    match form {
        GoInitializerForm::CompositeLiteral => "literal",
        GoInitializerForm::CompositeLiteralAddress => "literal-address",
        GoInitializerForm::Call => "call",
    }
}

/// `<path>|<name>|<qualifier>|<type>|<pointer>` for every name a stored source
/// binds, in snapshot order, with `-` where the binding writes no type.
///
/// A receiver, a parameter, a result, and a `var` state their type directly, and
/// the package that type belongs to is the qualifier beside it. A retention that
/// kept the name and dropped the qualifier would leave `var n pkg.T` looking
/// exactly like `var n T`, so the two parts are rendered together over every
/// binding rather than over the ones that write a qualifier.
pub fn source_declared_types(snapshot: &GoResolutionSnapshot) -> Box<[Box<str>]> {
    snapshot
        .sources()
        .iter()
        .flat_map(|source| {
            source
                .facts()
                .bindings()
                .iter()
                .map(|bound| declared_type_text(source.path(), bound))
        })
        .collect()
}

fn declared_type_text(path: &str, bound: &GoBindingRecord) -> Box<str> {
    format!(
        "{path}|{}|{}|{}|{}",
        bound.name(),
        bound.type_qualifier().unwrap_or("-"),
        bound.type_name().unwrap_or("-"),
        bound.pointer()
    )
    .into_boxed_str()
}

/// `<path>|<name>|<qualifier>|<result>|<pointer>` for every declaration a stored
/// source states, in snapshot order, with `-` where it names no single result
/// type.
///
/// A callable's declared result is the only evidence a call's value carries a
/// type, and every receiver read from a call is resolved through it. Rendering
/// every declaration rather than the callables is what makes a fabricated result
/// as visible as one the retention dropped.
pub fn source_results(snapshot: &GoResolutionSnapshot) -> Box<[Box<str>]> {
    snapshot
        .sources()
        .iter()
        .flat_map(|source| {
            source
                .facts()
                .declarations()
                .iter()
                .map(|declared| result_text(source.path(), declared))
        })
        .collect()
}

fn result_text(path: &str, declared: &GoDeclarationRecord) -> Box<str> {
    format!(
        "{path}|{}|{}|{}|{}",
        declared.name(),
        declared.result_qualifier().unwrap_or("-"),
        declared.result_name().unwrap_or("-"),
        declared.result_pointer()
    )
    .into_boxed_str()
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
