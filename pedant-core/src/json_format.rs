use serde::Serialize;

use crate::violation::{Severity, Violation};

/// Flat JSON representation of a violation for `--format json` output.
#[derive(Serialize)]
pub struct JsonViolation<'a> {
    r#type: &'a str,
    check: &'static str,
    category: &'static str,
    severity: Severity,
    file: &'a str,
    line: usize,
    column: usize,
    message: &'a str,
    fix: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed: Option<&'a str>,
}

impl<'a> From<&'a Violation> for JsonViolation<'a> {
    fn from(v: &'a Violation) -> Self {
        let detail = v.violation_type.visibility_detail();
        Self {
            r#type: v.violation_type.code(),
            check: v.violation_type.code(),
            category: v.violation_type.category(),
            severity: v.severity,
            file: &*v.file_path,
            line: v.line,
            column: v.column,
            message: &*v.message,
            fix: v.violation_type.rationale().fix,
            pattern: v.violation_type.pattern(),
            subject: detail.map(|d| &*d.subject),
            expected: detail.map(|d| &*d.expected),
            observed: detail.map(|d| &*d.observed),
        }
    }
}
