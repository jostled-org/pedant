use std::sync::Arc;

use crate::ir::IrSpan;
use crate::violation::{Severity, Violation, ViolationType};

/// Emit a single `Deny`-severity violation with the given metadata.
pub(super) fn emit_violation(
    violations: &mut Vec<Violation>,
    fp: &Arc<str>,
    span: IrSpan,
    violation_type: ViolationType,
    message: impl Into<Box<str>>,
) {
    violations.push(Violation::new(
        violation_type,
        Arc::clone(fp),
        span.line,
        span.column + 1,
        message,
    ));
}

/// Emit a single violation at the given severity.
pub(super) fn emit_violation_with_severity(
    violations: &mut Vec<Violation>,
    fp: &Arc<str>,
    span: IrSpan,
    violation_type: ViolationType,
    message: impl Into<Box<str>>,
    severity: Severity,
) {
    violations.push(
        Violation::new(
            violation_type,
            Arc::clone(fp),
            span.line,
            span.column + 1,
            message,
        )
        .with_severity(severity),
    );
}
