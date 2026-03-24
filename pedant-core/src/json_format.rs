use serde::Serialize;

use crate::violation::Violation;

/// Flat JSON representation of a violation for `--format json` output.
#[derive(Serialize)]
pub struct JsonViolation<'a> {
    r#type: &'a str,
    check: &'static str,
    file: &'a str,
    line: usize,
    column: usize,
    message: &'a str,
    fix: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<&'a str>,
}

impl<'a> From<&'a Violation> for JsonViolation<'a> {
    fn from(v: &'a Violation) -> Self {
        Self {
            r#type: v.violation_type.code(),
            check: v.violation_type.check_name(),
            file: &*v.file_path,
            line: v.line,
            column: v.column,
            message: &*v.message,
            fix: v.violation_type.rationale().fix,
            pattern: v.violation_type.pattern(),
        }
    }
}
