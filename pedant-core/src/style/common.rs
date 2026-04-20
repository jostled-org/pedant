use std::sync::Arc;

use crate::ir::IrSpan;
use crate::violation::{Violation, ViolationType};

/// Emit a single violation with the given metadata.
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
