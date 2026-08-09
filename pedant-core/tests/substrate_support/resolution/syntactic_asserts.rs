//! Claims the Tier 1 cases delegate to: snapshot binding refusals, the
//! parse-only observation contract, and deterministic serialization.

use std::sync::Arc;

use pedant_core::resolution::rust::{
    RustResolutionError, RustResolutionSnapshot, RustResolver, RustTargetResolution,
};
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
    let mut builder =
        ResolutionReportBuilder::new(ResolutionTier::Syntactic, ResolutionReportLimits::default());
    let unit = builder
        .add_unit(
            Language::Rust,
            Arc::from("Cargo.toml#lib#app"),
            Arc::from("app"),
        )
        .expect("the builder admits one unit");
    builder
        .add_definition(&unit, SymbolKind::Function, Arc::from("caller"), span, None)
        .expect("the builder admits one definition");
    builder
        .finish()
        .expect("the stated report is structurally valid")
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
