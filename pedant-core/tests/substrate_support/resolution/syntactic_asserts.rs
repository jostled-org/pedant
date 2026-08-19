//! Claims the Tier 1 cases delegate to: snapshot binding refusals, the
//! parse-only observation contract, and deterministic serialization.

use std::sync::Arc;

use pedant_core::resolution::rust::{
    RustResolutionError, RustResolutionSnapshot, RustResolver, RustTargetResolution,
};
use pedant_types::resolution::{ReferenceKind, ResolutionGap, ResolutionUnitHandle};
use pedant_types::{
    Language, ResolutionReport, ResolutionReportBuilder, ResolutionReportLimits, ResolutionTier,
    SourcePosition, SourceSpan, SymbolKind,
};

use crate::resolution::fixture::{self, FixtureFile};
use crate::resolution::views::{app_library, sole_library};

/// One refused binding: its label and the error it owes.
pub type Refusal = (&'static str, fn(&RustResolutionError) -> bool);

/// Resolve one fixture's library target syntactically.
pub fn resolve_library(tmp: &tempfile::TempDir) -> RustTargetResolution {
    resolve_with_snapshot(tmp).1
}

/// Resolve one fixture's library target, keeping the snapshot it is bound to.
pub fn resolve_with_snapshot(
    tmp: &tempfile::TempDir,
) -> (RustResolutionSnapshot, RustTargetResolution) {
    let project = fixture::load_default(tmp);
    let snapshot = project
        .snapshot_resolution(app_library(&project))
        .expect("the fixture resolves under the documented defaults");
    let resolution =
        RustResolver::resolve_syntactic(&snapshot).expect("Tier 1 resolves the fixture");
    (snapshot, resolution)
}

/// Bind `report` to another repository's snapshot and require `refusal`.
pub fn assert_binding_refused(files: &[FixtureFile], report: &ResolutionReport, refusal: Refusal) {
    let (label, expected) = refusal;
    let tmp = fixture::build_repository(files, false);
    let project = fixture::load_default(&tmp);
    let snapshot = project
        .snapshot_resolution(sole_library(&project))
        .expect("the mismatched fixture still resolves against itself");
    let error = RustTargetResolution::try_new(&snapshot, report.clone())
        .err()
        .unwrap_or_else(|| panic!("{label} was accepted"));
    assert!(expected(&error), "{label}: unexpected error {error:?}");
}

/// Require that a hand-written span outside the snapshotted text is refused.
pub fn assert_coordinate_refused(snapshot: &RustResolutionSnapshot, label: &str, span: SourceSpan) {
    let report = single_definition_report(span);
    let error = RustTargetResolution::try_new(snapshot, report)
        .err()
        .unwrap_or_else(|| panic!("{label} was accepted"));
    assert!(
        matches!(error, RustResolutionError::InvalidCoordinate { .. }),
        "{label}: unexpected error {error:?}"
    );
}

/// Require that a hand-written span inside the snapshotted text is accepted, so
/// the refusals above come from the coordinates and not from the shape of a
/// hand-written report.
pub fn assert_coordinate_accepted(
    snapshot: &RustResolutionSnapshot,
    label: &str,
    span: SourceSpan,
) {
    let report = single_definition_report(span);
    RustTargetResolution::try_new(snapshot, report)
        .unwrap_or_else(|error| panic!("{label} was refused: {error:?}"));
}

/// A report holding one unit and one definition at `span`, so the only thing
/// the snapshot boundary can refuse is that span.
fn single_definition_report(span: SourceSpan) -> ResolutionReport {
    definition_report(SymbolKind::Function, &span)
}

/// A report holding one unit and one definition of `kind` at `span`.
///
/// The span is borrowed and copied once here, so a caller stating one report
/// per kind does not clone inside its own loop.
fn definition_report(kind: SymbolKind, span: &SourceSpan) -> ResolutionReport {
    let mut builder = report_builder();
    let unit = admit_unit(&mut builder);
    builder
        .add_definition(&unit, kind, Arc::from("caller"), span.clone(), None)
        .expect("the builder admits one definition");
    builder
        .finish()
        .expect("the stated report is structurally valid")
}

/// A report holding one unit and one answered reference of `kind` at `span`.
fn reference_report(kind: ReferenceKind, span: &SourceSpan) -> ResolutionReport {
    let mut builder = report_builder();
    let unit = admit_unit(&mut builder);
    let reference = builder
        .add_reference(&unit, kind, Arc::from("caller"), span.clone(), None)
        .expect("the builder admits one reference");
    builder
        .set_resolution(
            &reference,
            Box::from([]),
            Box::from([ResolutionGap::ExternalDefinition]),
        )
        .expect("the builder admits the one record its reference owes");
    builder
        .finish()
        .expect("the stated report is structurally valid")
}

fn report_builder() -> ResolutionReportBuilder {
    ResolutionReportBuilder::new(ResolutionTier::Syntactic, ResolutionReportLimits::default())
}

/// The single-package fixture's one library unit, under the key the snapshot
/// binds it by.
fn admit_unit(builder: &mut ResolutionReportBuilder) -> ResolutionUnitHandle {
    builder
        .add_unit(
            Language::Rust,
            Arc::from("Cargo.toml#lib#app"),
            Arc::from("app"),
        )
        .expect("the builder admits one unit")
}

/// Every definition kind the shared report vocabulary carries that no Rust
/// resolution emits.
const GO_ONLY_DEFINITION_KINDS: [SymbolKind; 5] = [
    SymbolKind::Package,
    SymbolKind::Interface,
    SymbolKind::DefinedType,
    SymbolKind::Variable,
    SymbolKind::Field,
];

/// Every reference kind in the same position.
const GO_ONLY_REFERENCE_KINDS: [ReferenceKind; 1] = [ReferenceKind::Value];

/// The Rust wrapper refuses every kind outside the Rust subset, and accepts the
/// same report shape when its kind is a Rust one.
///
/// `span` is a coordinate the snapshot holds, so a refusal here is the kind and
/// nothing else: the control rows below prove the same builder, the same unit
/// key, and the same span pass when only the kind changes.
pub fn assert_go_only_kinds_are_refused(snapshot: &RustResolutionSnapshot, span: &SourceSpan) {
    for kind in GO_ONLY_DEFINITION_KINDS {
        let report = definition_report(kind, span);
        let error = RustTargetResolution::try_new(snapshot, report)
            .err()
            .unwrap_or_else(|| panic!("a {kind:?} definition was accepted by a Rust resolution"));
        assert!(
            matches!(
                error,
                RustResolutionError::UnsupportedDefinitionKind { definition: 0, kind: stated }
                    if stated == kind
            ),
            "a {kind:?} definition: unexpected error {error:?}"
        );
    }
    for kind in GO_ONLY_REFERENCE_KINDS {
        let report = reference_report(kind, span);
        let error = RustTargetResolution::try_new(snapshot, report)
            .err()
            .unwrap_or_else(|| panic!("a {kind:?} reference was accepted by a Rust resolution"));
        assert!(
            matches!(
                error,
                RustResolutionError::UnsupportedReferenceKind { reference: 0, kind: stated }
                    if stated == kind
            ),
            "a {kind:?} reference: unexpected error {error:?}"
        );
    }

    RustTargetResolution::try_new(snapshot, definition_report(SymbolKind::Function, span))
        .unwrap_or_else(|error| {
            panic!("a Rust definition of the same shape was refused: {error:?}")
        });
    RustTargetResolution::try_new(snapshot, reference_report(ReferenceKind::Call, span))
        .unwrap_or_else(|error| {
            panic!("a Rust reference of the same shape was refused: {error:?}")
        });
}

/// A span over `file` from one point to the next column.
pub fn span_at(file: &str, line: u32, column: u32) -> SourceSpan {
    SourceSpan::new(
        Arc::from(file),
        SourcePosition::new(line, column),
        SourcePosition::new(line, column + 1),
    )
}

/// A span over `file` whose start and end sit on different lines.
pub fn span_between(file: &str, start: (u32, u32), end: (u32, u32)) -> SourceSpan {
    SourceSpan::new(
        Arc::from(file),
        SourcePosition::new(start.0, start.1),
        SourcePosition::new(end.0, end.1),
    )
}

/// The JSON one fixture's resolution serializes to, under a stated creation
/// order for its files.
pub fn resolution_json(files: &[FixtureFile], reversed: bool) -> Vec<u8> {
    let tmp = fixture::build_repository(files, reversed);
    let resolution = resolve_library(&tmp);
    serde_json::to_vec(resolution.report()).expect("a validated report serializes")
}
