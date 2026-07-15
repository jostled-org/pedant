use std::collections::BTreeMap;
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

/// Flag god-object types by their aggregate inherent-method count.
///
/// Methods are summed across every inherent `impl Type` block in the file;
/// trait impls are excluded. Pure single-expression forwarders are excluded
/// unless `count_forwarders` is set. The type is reported once, at its first
/// inherent impl in the file.
pub(super) fn check_high_method_count(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_high_method_count {
        return;
    }

    // First inherent impl span per type, for the reporting location.
    let mut report_span: BTreeMap<&str, IrSpan> = BTreeMap::new();
    for imp in &ir.impl_blocks {
        if imp.trait_name.is_none() {
            report_span.entry(&imp.self_type).or_insert(imp.span);
        }
    }

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for func in &ir.functions {
        let Some(ty) = &func.inherent_method_of else {
            continue;
        };
        if func.is_pure_forwarder && !config.count_forwarders {
            continue;
        }
        *counts.entry(ty).or_insert(0) += 1;
    }

    for (ty, count) in counts {
        if count <= config.max_methods {
            continue;
        }
        let span = report_span
            .get(ty)
            .copied()
            .unwrap_or(IrSpan { line: 1, column: 0 });
        emit_violation(
            violations,
            fp,
            span,
            ViolationType::HighMethodCount,
            format!(
                "`{ty}` has {count} inherent methods (limit: {}), split its responsibilities into focused types",
                config.max_methods
            ),
        );
    }
}
