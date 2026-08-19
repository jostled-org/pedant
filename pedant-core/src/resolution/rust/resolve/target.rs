//! The snapshot-bound resolution result, and the one core validation boundary
//! that produces it.
//!
//! A report is only meaningful beside the snapshot it describes, so every
//! resolver entry point returns this wrapper and nothing else. Construction
//! rebinds the report's units to snapshot units by their stable keys, proves
//! every site names a kind a Rust resolution emits, and proves every site
//! coordinate exists in the exact snapshotted source; a report built against
//! another snapshot cannot pass.
//!
//! The kind check is what makes the shared report vocabulary safe to widen. It
//! is one closed set across every language a report can carry, and each
//! language's wrapper states its own subset of it here, so adding a kind for
//! one language cannot quietly become a kind another one accepts.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{
    ReferenceKind, ResolutionReport, ResolutionUnit, ResolutionUnitId, SourceSpan,
    SymbolDefinition, SymbolKind, SymbolReference,
};

use crate::resolution::rust::fingerprint::RustSnapshotFingerprint;
use crate::resolution::rust::identity::{PackageId, TargetId, position};
use crate::resolution::rust::snapshot::{
    RustResolutionSnapshot, RustResolutionUnit, RustSnapshotUnitId,
};
use crate::resolution::rust::warning;

use super::coordinates::LineIndex;
use super::error::RustResolutionError;

/// The stable key one snapshot unit is identified by across reports.
pub(super) fn unit_key(unit: &RustResolutionUnit) -> Arc<str> {
    warning::unit_key(unit)
}

/// The canonical Cargo crate name one target compiles under.
pub(super) fn crate_name(unit: &RustResolutionUnit) -> Arc<str> {
    Arc::from(unit.name().replace('-', "_"))
}

/// What one report-local unit identifier binds to in the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustUnitBinding {
    unit: ResolutionUnitId,
    snapshot_unit: RustSnapshotUnitId,
    package: PackageId,
    target: TargetId,
}

impl RustUnitBinding {
    /// The report-local identifier this binding answers for.
    pub fn unit(&self) -> ResolutionUnitId {
        self.unit
    }

    /// The snapshot unit the report unit describes.
    pub fn snapshot_unit(&self) -> RustSnapshotUnitId {
        self.snapshot_unit
    }

    /// The package that declares the bound Cargo target.
    pub fn package(&self) -> PackageId {
        self.package
    }

    /// The Cargo target the report unit compiles.
    pub fn target(&self) -> TargetId {
        self.target
    }

    /// The same binding pointed at another snapshot unit.
    ///
    /// Proof-only: the validated boundary above binds each report unit by its
    /// stable key, so no ordinary caller can state a binding at all.
    #[cfg(feature = "resolution-test-support")]
    pub(in crate::resolution::rust) fn rebound(&self, snapshot_unit: RustSnapshotUnitId) -> Self {
        Self {
            snapshot_unit,
            ..*self
        }
    }
}

/// One resolution result, bound to the snapshot it describes.
#[derive(Debug, Clone)]
pub struct RustTargetResolution {
    root_target: TargetId,
    snapshot_fingerprint: RustSnapshotFingerprint,
    units: Box<[RustUnitBinding]>,
    report: Arc<ResolutionReport>,
}

impl RustTargetResolution {
    /// Bind `report` to `snapshot`, or refuse every disagreement between them.
    pub fn try_new(
        snapshot: &RustResolutionSnapshot,
        report: ResolutionReport,
    ) -> Result<Self, RustResolutionError> {
        let units = bind_units(snapshot, report.units())?;
        validate_definition_kinds(&report)?;
        validate_reference_kinds(&report)?;
        validate_sites(snapshot, &report)?;
        Ok(Self {
            root_target: snapshot.root_target(),
            snapshot_fingerprint: snapshot.fingerprint(),
            units,
            report: Arc::new(report),
        })
    }

    /// The target this resolution was requested for.
    pub fn root_target(&self) -> TargetId {
        self.root_target
    }

    /// The identity of the snapshot this report was validated against.
    ///
    /// A consumer that later pairs this result with a snapshot compares this
    /// value first: equal root targets do not prove the sources are the ones
    /// the report describes.
    pub fn snapshot_fingerprint(&self) -> RustSnapshotFingerprint {
        self.snapshot_fingerprint
    }

    /// Every report-local unit identifier and the Cargo target it names.
    pub fn units(&self) -> &[RustUnitBinding] {
        &self.units
    }

    /// The binding one report-local unit identifier selects.
    pub fn unit(&self, unit: ResolutionUnitId) -> Option<&RustUnitBinding> {
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

    /// The same validated report carrying deliberately restated unit bindings.
    ///
    /// Proof-only: [`Self::try_new`] is the sole ordinary constructor and binds
    /// every report unit by its stable key, so the join failures a downstream
    /// consumer must still refuse have no other construction path.
    #[cfg(feature = "resolution-test-support")]
    pub(in crate::resolution::rust) fn with_unit_bindings(
        &self,
        units: Box<[RustUnitBinding]>,
    ) -> Self {
        Self {
            root_target: self.root_target,
            snapshot_fingerprint: self.snapshot_fingerprint,
            units,
            report: Arc::clone(&self.report),
        }
    }
}

fn bind_units(
    snapshot: &RustResolutionSnapshot,
    units: &[ResolutionUnit],
) -> Result<Box<[RustUnitBinding]>, RustResolutionError> {
    if units.len() != snapshot.units().len() {
        return Err(RustResolutionError::UnitMapping {
            unit: position(units.len()),
            reason: Box::from("the report and the snapshot hold different unit counts"),
        });
    }
    let keyed = keyed_units(snapshot);
    units.iter().map(|unit| bind_unit(&keyed, unit)).collect()
}

/// Every snapshot unit under its stable key, so binding a report of N units
/// formats N keys rather than one key per candidate per report unit.
fn keyed_units(snapshot: &RustResolutionSnapshot) -> BTreeMap<Arc<str>, &RustResolutionUnit> {
    snapshot
        .units()
        .iter()
        .map(|unit| (unit_key(unit), unit))
        .collect()
}

fn bind_unit(
    keyed: &BTreeMap<Arc<str>, &RustResolutionUnit>,
    unit: &ResolutionUnit,
) -> Result<RustUnitBinding, RustResolutionError> {
    let found = keyed
        .get(unit.key())
        .ok_or_else(|| RustResolutionError::UnitMapping {
            unit: unit.id().index(),
            reason: Box::from("no snapshot unit carries this key"),
        })?;
    Ok(RustUnitBinding {
        unit: unit.id(),
        snapshot_unit: found.id(),
        package: found.package(),
        target: found.target(),
    })
}

/// Prove every definition names a kind a Rust resolution emits.
fn validate_definition_kinds(report: &ResolutionReport) -> Result<(), RustResolutionError> {
    match report
        .definitions()
        .iter()
        .find(|definition| !is_rust_definition_kind(definition.kind()))
    {
        None => Ok(()),
        Some(definition) => Err(RustResolutionError::UnsupportedDefinitionKind {
            definition: definition.id().index(),
            kind: definition.kind(),
        }),
    }
}

/// Prove every reference names a kind a Rust resolution emits.
fn validate_reference_kinds(report: &ResolutionReport) -> Result<(), RustResolutionError> {
    match report
        .references()
        .iter()
        .find(|reference| !is_rust_reference_kind(reference.kind()))
    {
        None => Ok(()),
        Some(reference) => Err(RustResolutionError::UnsupportedReferenceKind {
            reference: reference.id().index(),
            kind: reference.kind(),
        }),
    }
}

/// Whether one definition kind is a kind a Rust resolution emits.
///
/// Every variant of the shared vocabulary is named. A kind added for another
/// language is therefore a compile error here rather than a value this
/// boundary admits by falling through a wildcard, and a Rust kind cannot be
/// dropped from the subset without one.
fn is_rust_definition_kind(kind: SymbolKind) -> bool {
    match kind {
        SymbolKind::Module
        | SymbolKind::Function
        | SymbolKind::Method
        | SymbolKind::Struct
        | SymbolKind::Enum
        | SymbolKind::Union
        | SymbolKind::Trait
        | SymbolKind::TypeAlias
        | SymbolKind::Constant
        | SymbolKind::Static => true,
        SymbolKind::Package
        | SymbolKind::Interface
        | SymbolKind::DefinedType
        | SymbolKind::Variable
        | SymbolKind::Field => false,
    }
}

/// Whether one reference kind is a kind a Rust resolution emits.
fn is_rust_reference_kind(kind: ReferenceKind) -> bool {
    match kind {
        ReferenceKind::Module
        | ReferenceKind::Import
        | ReferenceKind::Call
        | ReferenceKind::Type
        | ReferenceKind::Implementation => true,
        ReferenceKind::Value => false,
    }
}

/// Prove every stated coordinate against the exact snapshotted source.
///
/// Each source is indexed once rather than once per site: a report states many
/// thousands of sites over the same files, and building the line table per site
/// rescanned whole sources for coordinates derived from those same tables.
fn validate_sites(
    snapshot: &RustResolutionSnapshot,
    report: &ResolutionReport,
) -> Result<(), RustResolutionError> {
    let lines = indexed_sources(snapshot);
    for definition in report.definitions() {
        validate_span(snapshot, &lines, SymbolDefinition::span(definition))?;
    }
    for reference in report.references() {
        validate_span(snapshot, &lines, SymbolReference::span(reference))?;
    }
    Ok(())
}

fn indexed_sources(snapshot: &RustResolutionSnapshot) -> BTreeMap<&str, LineIndex> {
    snapshot
        .sources()
        .iter()
        .map(|source| (source.path(), LineIndex::new(source.text())))
        .collect()
}

fn validate_span(
    snapshot: &RustResolutionSnapshot,
    lines: &BTreeMap<&str, LineIndex>,
    span: &SourceSpan,
) -> Result<(), RustResolutionError> {
    let stated = snapshot
        .source(span.file())
        .zip(lines.get(span.file()))
        .ok_or_else(|| RustResolutionError::UnknownFile {
            file: Box::from(span.file()),
        })?;
    let (source, index) = stated;
    for at in [span.start(), span.end()] {
        if !index.holds(source.text(), at) {
            return Err(RustResolutionError::InvalidCoordinate {
                file: Box::from(span.file()),
                line: at.line(),
                column: at.column(),
            });
        }
    }
    Ok(())
}
