use std::sync::Arc;

use crate::check_config::CheckConfig;
use crate::ir::FileIr;
use crate::violation::{Violation, ViolationType};

use super::common::emit_violation;

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
