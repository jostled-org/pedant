//! The snapshot-bound Go resolution result, and the one validation boundary
//! that produces it.
//!
//! A report is only meaningful beside the snapshot it describes, so the
//! resolver entry point returns this wrapper and nothing else. Construction
//! rebinds the report's units to snapshot package contexts by their stable
//! keys, proves every site names a kind a Go resolution emits, and proves every
//! site coordinate exists in the exact snapshotted source; a report built
//! against another snapshot cannot pass.
//!
//! The kind check is what makes the shared report vocabulary safe to widen. It
//! is one closed set across every language a report can carry, and each
//! language's wrapper states its own subset of it, so a kind added for one
//! language cannot quietly become a kind another one accepts.

use std::sync::Arc;

use pedant_types::{ReferenceKind, ResolutionReport, ResolutionUnit, ResolutionUnitId, SymbolKind};

use crate::resolution::binding::{self, BindingFault};
use crate::resolution::go::fingerprint::GoSnapshotFingerprint;
use crate::resolution::go::snapshot::GoResolutionSnapshot;
use crate::resolution::go::snapshot_module::GoSnapshotModuleId;
use crate::resolution::go::unit::{GoPackageContext, GoResolutionUnit, GoSnapshotUnitId};
use crate::resolution::line_index::source_lines;
use crate::resolution::sites::{self, SiteError};

use super::error::GoResolutionError;

/// The stable key one snapshot package context is identified by across reports.
///
/// The import path names the directory and the context names which of the three
/// builds compiles it, which is exactly what makes two units of one directory
/// different. The module path is not in it, because an import path already
/// opens with the module path that owns it.
pub(super) fn unit_key(unit: &GoResolutionUnit) -> Arc<str> {
    Arc::from(format!("{}#{}", unit.import_path(), unit.context().token()))
}

/// What one report-local unit identifier binds to in the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoUnitBinding {
    unit: ResolutionUnitId,
    snapshot_unit: GoSnapshotUnitId,
    module: GoSnapshotModuleId,
    context: GoPackageContext,
}

impl GoUnitBinding {
    /// The report-local identifier this binding answers for.
    pub fn unit(&self) -> ResolutionUnitId {
        self.unit
    }

    /// The snapshot package context the report unit describes.
    pub fn snapshot_unit(&self) -> GoSnapshotUnitId {
        self.snapshot_unit
    }

    /// The module whose tree declares the bound package.
    pub fn module(&self) -> GoSnapshotModuleId {
        self.module
    }

    /// Which of the directory's three compilation contexts the unit is.
    pub fn context(&self) -> GoPackageContext {
        self.context
    }
}

/// One Go resolution result, bound to the snapshot it describes.
#[derive(Debug, Clone)]
pub struct GoProjectResolution {
    root_module: GoSnapshotModuleId,
    snapshot_fingerprint: GoSnapshotFingerprint,
    units: Box<[GoUnitBinding]>,
    report: Arc<ResolutionReport>,
}

impl GoProjectResolution {
    /// Bind `report` to `snapshot`, or refuse every disagreement between them.
    pub fn try_new(
        snapshot: &GoResolutionSnapshot,
        report: ResolutionReport,
    ) -> Result<Self, GoResolutionError> {
        let units = bind_units(snapshot, report.units())?;
        validate_definition_kinds(&report)?;
        validate_reference_kinds(&report)?;
        validate_snapshot_sites(snapshot, &report)?;
        Ok(Self {
            root_module: snapshot.root_module(),
            snapshot_fingerprint: snapshot.fingerprint(),
            units,
            report: Arc::new(report),
        })
    }

    /// The main module of the snapshot this resolution describes.
    pub fn root_module(&self) -> GoSnapshotModuleId {
        self.root_module
    }

    /// The identity of the snapshot this report was validated against.
    ///
    /// A consumer that later pairs this result with a snapshot compares this
    /// value first: equal roots do not prove the sources are the ones the
    /// report describes.
    pub fn snapshot_fingerprint(&self) -> GoSnapshotFingerprint {
        self.snapshot_fingerprint
    }

    /// Every report-local unit identifier and the package context it names.
    pub fn units(&self) -> &[GoUnitBinding] {
        &self.units
    }

    /// The binding one report-local unit identifier selects.
    pub fn unit(&self, unit: ResolutionUnitId) -> Option<&GoUnitBinding> {
        self.units.get(usize::try_from(unit.index()).ok()?)
    }

    /// The validated report, shared rather than copied.
    pub fn report(&self) -> &ResolutionReport {
        &self.report
    }

    /// A second handle on the same validated report.
    pub fn shared_report(&self) -> Arc<ResolutionReport> {
        Arc::clone(&self.report)
    }
}

fn bind_units(
    snapshot: &GoResolutionSnapshot,
    units: &[ResolutionUnit],
) -> Result<Box<[GoUnitBinding]>, GoResolutionError> {
    binding::bind_by_key(units, snapshot.units(), unit_key, bound).map_err(unit_refusal)
}

/// One report unit bound to the snapshot package context its key selected.
fn bound(unit: &ResolutionUnit, found: &GoResolutionUnit) -> GoUnitBinding {
    GoUnitBinding {
        unit: unit.id(),
        snapshot_unit: found.id(),
        module: found.module(),
        context: found.context(),
    }
}

/// The Go seam's own error for one report that does not describe the snapshot.
fn unit_refusal(fault: BindingFault) -> GoResolutionError {
    match fault {
        BindingFault::UnitCountMismatch { report, snapshot } => {
            GoResolutionError::UnitCountMismatch { report, snapshot }
        }
        BindingFault::UnknownKey { unit } => GoResolutionError::UnitMapping {
            unit,
            reason: Box::from("no snapshot package context carries this key"),
        },
    }
}

/// Prove every definition names a kind a Go resolution emits.
fn validate_definition_kinds(report: &ResolutionReport) -> Result<(), GoResolutionError> {
    match binding::first_unsupported_definition(report, is_go_definition_kind) {
        None => Ok(()),
        Some((definition, kind)) => {
            Err(GoResolutionError::UnsupportedDefinitionKind { definition, kind })
        }
    }
}

/// Prove every reference names a kind a Go resolution emits.
fn validate_reference_kinds(report: &ResolutionReport) -> Result<(), GoResolutionError> {
    match binding::first_unsupported_reference(report, is_go_reference_kind) {
        None => Ok(()),
        Some((reference, kind)) => {
            Err(GoResolutionError::UnsupportedReferenceKind { reference, kind })
        }
    }
}

/// Whether one definition kind is a kind a Go resolution emits.
///
/// Every variant of the shared vocabulary is named. A kind added for another
/// language is therefore a compile error here rather than a value this boundary
/// admits by falling through a wildcard, and a Go kind cannot be dropped from
/// the subset without one.
fn is_go_definition_kind(kind: SymbolKind) -> bool {
    match kind {
        SymbolKind::Package
        | SymbolKind::Function
        | SymbolKind::Method
        | SymbolKind::Struct
        | SymbolKind::Interface
        | SymbolKind::DefinedType
        | SymbolKind::TypeAlias
        | SymbolKind::Constant
        | SymbolKind::Variable
        | SymbolKind::Field => true,
        SymbolKind::Module
        | SymbolKind::Enum
        | SymbolKind::Union
        | SymbolKind::Trait
        | SymbolKind::Static => false,
    }
}

/// Whether one reference kind is a kind a Go resolution emits.
fn is_go_reference_kind(kind: ReferenceKind) -> bool {
    match kind {
        ReferenceKind::Import
        | ReferenceKind::Call
        | ReferenceKind::Type
        | ReferenceKind::Value
        | ReferenceKind::Implementation => true,
        ReferenceKind::Module => false,
    }
}

/// Prove every stated coordinate against the exact snapshotted source.
///
/// Named apart from the shared authority it hands to: this seam binds one
/// snapshot's texts and one typed error to that walk, and two functions spelled
/// alike in one module would read as a single route stated twice.
fn validate_snapshot_sites(
    snapshot: &GoResolutionSnapshot,
    report: &ResolutionReport,
) -> Result<(), GoResolutionError> {
    sites::validate_sites(&source_lines(snapshot.sources()), report).map_err(refusal)
}

/// The Go seam's own error for one refused site.
fn refusal(error: SiteError) -> GoResolutionError {
    match error {
        SiteError::UnknownFile { file } => GoResolutionError::UnknownFile { file },
        SiteError::InvalidCoordinate { file, line, column } => {
            GoResolutionError::InvalidCoordinate { file, line, column }
        }
    }
}
