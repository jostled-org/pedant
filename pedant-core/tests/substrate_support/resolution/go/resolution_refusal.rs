//! Reports the production resolver never writes, handed to the published
//! wrapper anyway.
//!
//! A wrapper that only ever saw its own producer's output would prove nothing
//! about a report handed to it, so every disagreement it must refuse is stated
//! here directly: a foreign unit key, a Rust-only kind, a file the snapshot does
//! not hold, and a coordinate outside the exact snapshotted bytes.

use std::sync::Arc;

use pedant_core::resolution::go::{
    GoProject, GoProjectResolution, GoResolutionError, GoResolutionLimits,
};
use pedant_types::{
    Language, ReferenceKind, ResolutionReport, ResolutionReportBuilder, ResolutionReportLimits,
    ResolutionTier, SourcePosition, SourceSpan, SymbolKind,
};

use crate::resolution::fixture::{build_repository, repository_root};
use crate::resolution::go::resolution_fixtures::BOUND_CONTEXTS;

/// A report the resolver did not write is refused for every disagreement it
/// states, and the same shape stating only admitted facts is accepted.
///
/// `keys` are the report unit keys the snapshot of [`BOUND_CONTEXTS`] holds.
pub fn assert_reports_it_did_not_write_are_refused(keys: &[&str]) {
    let tree = build_repository(BOUND_CONTEXTS, false);
    let project = GoProject::load(&repository_root(&tree), GoResolutionLimits::default())
        .expect("the fixture should load");
    let snapshot = project
        .snapshot_resolution()
        .expect("the fixture should snapshot");
    drop(project);

    let keys: Box<[Arc<str>]> = keys.iter().map(|key| Arc::from(*key)).collect();
    let file: Arc<str> = Arc::from("app.go");

    assert!(
        matches!(
            GoProjectResolution::try_new(&snapshot, stated(&keys, &file, Row::ForeignKey)),
            Err(GoResolutionError::UnitMapping { .. })
        ),
        "a report unit no snapshot unit keys is refused"
    );
    assert!(
        matches!(
            GoProjectResolution::try_new(&snapshot, stated(&keys, &file, Row::RustKind)),
            Err(GoResolutionError::UnsupportedDefinitionKind {
                kind: SymbolKind::Trait,
                ..
            })
        ),
        "a Rust-only definition kind is refused"
    );
    assert!(
        matches!(
            GoProjectResolution::try_new(&snapshot, stated(&keys, &file, Row::RustReference)),
            Err(GoResolutionError::UnsupportedReferenceKind {
                kind: ReferenceKind::Module,
                ..
            })
        ),
        "a Rust-only reference kind is refused"
    );
    assert!(
        matches!(
            GoProjectResolution::try_new(&snapshot, stated(&keys, &file, Row::UnknownFile)),
            Err(GoResolutionError::UnknownFile { .. })
        ),
        "a site naming a file the snapshot does not hold is refused"
    );
    assert!(
        matches!(
            GoProjectResolution::try_new(&snapshot, stated(&keys, &file, Row::BadCoordinate)),
            Err(GoResolutionError::InvalidCoordinate { .. })
        ),
        "a coordinate outside the exact snapshotted source is refused"
    );
    assert!(
        GoProjectResolution::try_new(&snapshot, stated(&keys, &file, Row::Valid)).is_ok(),
        "the same shape stating only admitted facts is accepted"
    );

    drop(snapshot);
    drop(tree);
}

/// Which disagreement one stated report carries.
#[derive(Clone, Copy)]
enum Row {
    Valid,
    ForeignKey,
    RustKind,
    RustReference,
    UnknownFile,
    BadCoordinate,
}

/// One report stating every snapshot unit and a single definition, perturbed by
/// exactly the row under test.
fn stated(keys: &[Arc<str>], file: &Arc<str>, row: Row) -> ResolutionReport {
    let mut builder =
        ResolutionReportBuilder::new(ResolutionTier::Syntactic, ResolutionReportLimits::default());
    let named: Box<[Arc<str>]> = match row {
        Row::ForeignKey => foreign_first(keys),
        _ => keys.to_vec().into_boxed_slice(),
    };
    let units: Box<[_]> = named
        .iter()
        .map(|key| {
            builder
                .add_unit(Language::Go, Arc::clone(key), Arc::clone(key))
                .expect("a unit is stated")
        })
        .collect();
    let unit = units.last().expect("the report states its units");
    let path = match row {
        Row::UnknownFile => Arc::from("absent.go"),
        _ => Arc::clone(file),
    };
    let span = match row {
        Row::BadCoordinate => SourceSpan::new(
            path,
            SourcePosition::new(4_096, 0),
            SourcePosition::new(4_096, 1),
        ),
        _ => SourceSpan::new(path, SourcePosition::new(0, 0), SourcePosition::new(0, 7)),
    };
    let kind = match row {
        Row::RustKind => SymbolKind::Trait,
        _ => SymbolKind::Package,
    };
    builder
        .add_definition(unit, kind, Arc::from("util"), span.clone(), None)
        .expect("a definition is stated");
    let reference = builder
        .add_reference(
            unit,
            match row {
                Row::RustReference => ReferenceKind::Module,
                _ => ReferenceKind::Import,
            },
            Arc::from("x/util"),
            span,
            None,
        )
        .expect("a reference is stated");
    builder
        .set_resolution(
            &reference,
            Box::from([]),
            Box::from([pedant_types::ResolutionGap::ExternalDefinition]),
        )
        .expect("a record is stated");
    builder.finish().expect("the stated report is valid")
}

/// The same keys with the first one replaced by a key no snapshot unit holds.
fn foreign_first(keys: &[Arc<str>]) -> Box<[Arc<str>]> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| match index {
            0 => Arc::from("x#nowhere"),
            _ => Arc::clone(key),
        })
        .collect()
}
