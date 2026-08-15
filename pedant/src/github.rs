//! GitHub Actions workflow command rendering.
//!
//! Emits [workflow commands] so findings surface as inline annotations on a pull
//! request instead of plain log lines. Violations carry a source location and are
//! anchored to it; gate verdicts are whole-profile judgements with no location, so
//! they attach to the workflow run itself.
//!
//! [workflow commands]: https://docs.github.com/actions/reference/workflow-commands-for-github-actions

use std::borrow::Cow;
use std::io::{self, Write};
use std::sync::Arc;

use pedant_core::GateVerdict;
use pedant_core::gate::GateSeverity;
use pedant_core::violation::{Severity, Violation};
use pedant_types::AnalysisTier;

/// Annotation level of a workflow command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnnotationLevel {
    /// Fails the annotation check and renders red.
    Error,
    /// Renders yellow; advisory only.
    Warning,
    /// Renders as an informational note.
    Notice,
}

impl AnnotationLevel {
    /// The workflow command name, used as `::<command> ...`.
    pub(crate) fn command(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Notice => "notice",
        }
    }
}

impl From<Severity> for AnnotationLevel {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Deny => Self::Error,
            Severity::Warn => Self::Warning,
        }
    }
}

impl From<GateSeverity> for AnnotationLevel {
    fn from(severity: GateSeverity) -> Self {
        match severity {
            GateSeverity::Deny => Self::Error,
            GateSeverity::Warn => Self::Warning,
            GateSeverity::Info => Self::Notice,
        }
    }
}

/// Escape the message body of a workflow command.
///
/// `%` must be replaced first, or the escapes introduced below would be escaped
/// again on their own percent signs.
fn escape_message(raw: &str) -> Cow<'_, str> {
    match raw.contains(['%', '\r', '\n']) {
        false => Cow::Borrowed(raw),
        true => Cow::Owned(
            raw.replace('%', "%25")
                .replace('\r', "%0D")
                .replace('\n', "%0A"),
        ),
    }
}

/// Escape a workflow command property value.
///
/// Properties are comma-separated `key=value` pairs terminated by `::`, so a raw
/// `,` or `:` in a value would truncate the annotation.
fn escape_property(raw: &str) -> Cow<'_, str> {
    match escape_message(raw) {
        Cow::Borrowed(escaped) if !escaped.contains([':', ',']) => Cow::Borrowed(escaped),
        escaped => Cow::Owned(escaped.replace(':', "%3A").replace(',', "%2C")),
    }
}

/// Emit each violation as an annotation anchored to its source location.
pub(crate) fn write_violations<W: Write>(
    violations: &[Violation],
    writer: &mut W,
) -> io::Result<()> {
    for violation in violations {
        writeln!(
            writer,
            "::{} file={},line={},col={},title={}::{}",
            AnnotationLevel::from(violation.severity).command(),
            escape_property(&violation.file_path),
            violation.line,
            violation.column,
            escape_property(violation.violation_type.code()),
            escape_message(&violation.message),
        )?;
    }
    Ok(())
}

/// Emit each gate verdict as an annotation attached to the workflow run.
pub(crate) fn write_gate_verdicts<W: Write>(
    verdicts: &[GateVerdict],
    writer: &mut W,
) -> io::Result<()> {
    write_verdict_annotations(verdicts, writer)
}

/// The title every project-mode summary notice carries.
const PROJECT_NOTICE_TITLE: &str = "pedant module-boundary";

/// Emit one project-mode gate result: a workflow summary notice, then one
/// annotation per verdict anchored to its subject location when it has one.
pub(crate) fn write_project_gate<W: Write>(
    tier: AnalysisTier,
    targets: &[Arc<str>],
    verdicts: &[GateVerdict],
    writer: &mut W,
) -> io::Result<()> {
    write_project_notice(tier, targets, writer)?;
    write_verdict_annotations(verdicts, writer)
}

/// One annotation per verdict, the sole owner of the verdict command grammar.
///
/// Every mode renders through here, so a verdict that carries evidence renders
/// it wherever it was produced, and a fifth annotation field is added once.
fn write_verdict_annotations<W: Write>(verdicts: &[GateVerdict], writer: &mut W) -> io::Result<()> {
    for verdict in verdicts {
        write_verdict_annotation(verdict, &crate::output::evidence_fields(verdict)?, writer)?;
    }
    Ok(())
}

/// The always-emitted workflow notice that makes a zero-verdict run visible.
fn write_project_notice<W: Write>(
    tier: AnalysisTier,
    targets: &[Arc<str>],
    writer: &mut W,
) -> io::Result<()> {
    let labels = crate::output::target_labels(targets);
    let message = format!(
        "analysis-tier={}; targets={}",
        crate::output::tier_token(tier),
        crate::output::compact(&labels)?
    );
    writeln!(
        writer,
        "::{} title={}::{}",
        AnnotationLevel::Notice.command(),
        escape_property(PROJECT_NOTICE_TITLE),
        escape_message(&message),
    )
}

/// One verdict annotation, anchored to its subject or to the workflow run.
///
/// The rationale and the evidence suffix are escaped separately and written in
/// order, because escaping is per-character: joining them first would buy one
/// allocation per verdict and change nothing else.
fn write_verdict_annotation<W: Write>(
    verdict: &GateVerdict,
    evidence: &str,
    writer: &mut W,
) -> io::Result<()> {
    let level = AnnotationLevel::from(verdict.severity).command();
    let title = escape_property(verdict.rule);
    let rationale = escape_message(verdict.rationale);
    let evidence = escape_message(evidence);
    match crate::output::subject_location(verdict) {
        None => writeln!(writer, "::{level} title={title}::{rationale}{evidence}"),
        Some(location) => writeln!(
            writer,
            "::{level} file={},line={},col={},title={title}::{rationale}{evidence}",
            escape_property(location.path()),
            location.line(),
            location.column(),
        ),
    }
}
