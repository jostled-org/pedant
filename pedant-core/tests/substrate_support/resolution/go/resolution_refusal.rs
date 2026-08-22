//! Reports the production resolver never writes, handed to the published
//! wrapper anyway.
//!
//! A wrapper that only ever saw its own producer's output would prove nothing
//! about a report handed to it, so every disagreement it must refuse is stated
//! here directly: a foreign unit key, a Rust-only kind, a file the snapshot does
//! not hold, and a coordinate outside the exact snapshotted bytes.
//!
//! Every row is answered before anything is asserted. A validation claim the
//! wrapper stopped proving moves each row that claim owns, and a fail-fast
//! sequence would report only the first of them.

use std::sync::Arc;

use pedant_core::resolution::go::{
    GoProject, GoProjectResolution, GoResolutionError, GoResolutionLimits, GoResolutionSnapshot,
};
use pedant_types::{
    Language, ReferenceKind, ResolutionReport, ResolutionReportBuilder, ResolutionReportLimits,
    ResolutionTier, SourcePosition, SourceSpan, SymbolKind,
};

use crate::resolution::fixture::{build_repository, repository_root};
use crate::resolution::go::resolution_fixtures::BOUND_CONTEXTS;
use crate::resolution::go::views::borrowed;

/// Every stated report and what the wrapper does with it.
const ANSWERS: &[&str] = &[
    "valid|accepted",
    "foreign key|UnitMapping",
    "rust definition kind|UnsupportedDefinitionKind(Trait)",
    "rust reference kind|UnsupportedReferenceKind(Module)",
    "unknown file|UnknownFile",
    "bad coordinate|InvalidCoordinate",
];

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
    let answered: Box<[Box<str>]> = Row::ALL
        .iter()
        .map(|row| answer(&snapshot, (&keys, &file), *row))
        .collect();

    assert_eq!(
        &*borrowed(&answered),
        ANSWERS,
        "each disagreement is refused by the claim that owns it, and the admitted shape is accepted"
    );

    drop(snapshot);
    drop(tree);
}

/// What the wrapper does with one stated report, under the row's own label.
fn answer(snapshot: &GoResolutionSnapshot, named: (&[Arc<str>], &Arc<str>), row: Row) -> Box<str> {
    let (keys, file) = named;
    let verdict = match GoProjectResolution::try_new(snapshot, stated(keys, file, row)) {
        Ok(_) => Box::from("accepted"),
        Err(error) => refusal(&error),
    };
    format!("{}|{verdict}", row.label()).into_boxed_str()
}

/// Which claim refused one report, and the value it refused on.
///
/// The kind is stated because a wrapper that refused a Go kind would otherwise
/// read the same as one that refused the Rust kind the row carries.
fn refusal(error: &GoResolutionError) -> Box<str> {
    match error {
        GoResolutionError::UnitMapping { .. } => Box::from("UnitMapping"),
        GoResolutionError::UnsupportedDefinitionKind { kind, .. } => {
            format!("UnsupportedDefinitionKind({kind:?})").into_boxed_str()
        }
        GoResolutionError::UnsupportedReferenceKind { kind, .. } => {
            format!("UnsupportedReferenceKind({kind:?})").into_boxed_str()
        }
        GoResolutionError::UnknownFile { .. } => Box::from("UnknownFile"),
        GoResolutionError::InvalidCoordinate { .. } => Box::from("InvalidCoordinate"),
        other => format!("Other({other})").into_boxed_str(),
    }
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

impl Row {
    /// Every row, in the order [`ANSWERS`] states them.
    const ALL: &'static [Self] = &[
        Self::Valid,
        Self::ForeignKey,
        Self::RustKind,
        Self::RustReference,
        Self::UnknownFile,
        Self::BadCoordinate,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ForeignKey => "foreign key",
            Self::RustKind => "rust definition kind",
            Self::RustReference => "rust reference kind",
            Self::UnknownFile => "unknown file",
            Self::BadCoordinate => "bad coordinate",
        }
    }
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
