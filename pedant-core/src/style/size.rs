use std::sync::Arc;

use crate::check_config::CheckConfig;
use crate::ir::{FileIr, IrSpan};
use crate::violation::{Severity, Violation, ViolationType};

use super::common::{emit_violation, emit_violation_with_severity};

/// Flag functions whose body block spans more physical lines than the ceiling.
///
/// Body length is exact: the AST records the brace-to-brace line span, so blank
/// lines, comments, attributes, and brace-bearing string/char literals inside
/// the body are all counted or ignored correctly with no lexer ambiguity.
pub(super) fn check_long_function_body(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_long_function_body {
        return;
    }
    for func in &ir.functions {
        if func.body_line_count > config.max_function_body_lines {
            emit_violation(
                violations,
                fp,
                func.span,
                ViolationType::LongFunctionBody,
                format!(
                    "`{}` body spans {} lines (limit: {}), extract cohesive sections into helpers",
                    func.name, func.body_line_count, config.max_function_body_lines
                ),
            );
        }
    }
}

/// Flag whole source files that exceed the configured line ceilings.
///
/// The denial ceiling emits a blocking `Deny`; the warning ceiling emits an
/// advisory `Warn` that is reported but does not fail the run. A threshold of
/// `0` disables that tier. Denial takes precedence when both would fire.
pub(super) fn check_large_source_file(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_large_source_file {
        return;
    }
    let lines = ir.source_line_count;
    let deny = config.source_file_deny_lines;
    let warn = config.source_file_warn_lines;

    let tier = match (deny != 0 && lines >= deny, warn != 0 && lines >= warn) {
        (true, _) => Some((Severity::Deny, "denial", deny)),
        (false, true) => Some((Severity::Warn, "warning", warn)),
        (false, false) => None,
    };

    let Some((severity, label, threshold)) = tier else {
        return;
    };
    emit_violation_with_severity(
        violations,
        fp,
        IrSpan { line: 1, column: 0 },
        ViolationType::LargeSourceFile,
        format!(
            "file has {lines} lines (exceeds {label} threshold of {threshold}), split it into focused modules"
        ),
        severity,
    );
}
