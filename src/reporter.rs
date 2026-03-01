use std::io::{self, Write};

use crate::violation::Violation;

/// Output format for violation reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Formats and writes violation reports to a writer.
pub struct Reporter {
    format: OutputFormat,
    quiet: bool,
}

impl Reporter {
    pub fn new(format: OutputFormat, quiet: bool) -> Self {
        Self { format, quiet }
    }

    pub fn report<W: Write>(&self, violations: &[Violation], writer: &mut W) -> io::Result<()> {
        match self.format {
            OutputFormat::Text => self.report_text(violations, writer),
            OutputFormat::Json => self.report_json(violations, writer),
        }
    }

    fn report_text<W: Write>(&self, violations: &[Violation], writer: &mut W) -> io::Result<()> {
        for v in violations {
            writeln!(writer, "{v}")?;
        }

        if !self.quiet && !violations.is_empty() {
            writeln!(writer)?;
            writeln!(writer, "Found {} violation(s)", violations.len())?;
        }

        Ok(())
    }

    fn report_json<W: Write>(&self, violations: &[Violation], writer: &mut W) -> io::Result<()> {
        writeln!(writer, "[")?;
        for (i, v) in violations.iter().enumerate() {
            let comma = if i + 1 < violations.len() { "," } else { "" };
            let pattern_field = v.violation_type.pattern()
                .map(|p| format!(r#", "pattern": "{}""#, escape_json(p)))
                .unwrap_or_default();
            let rationale = v.violation_type.rationale();
            writeln!(
                writer,
                r#"  {{"type": "{}", "check": "{}", "file": "{}", "line": {}, "column": {}, "message": "{}", "fix": "{}"{}}}{}"#,
                v.violation_type,
                v.violation_type.check_name(),
                escape_json(&v.file_path),
                v.line,
                v.column,
                escape_json(&v.message),
                escape_json(rationale.fix),
                pattern_field,
                comma
            )?;
        }
        writeln!(writer, "]")?;
        Ok(())
    }
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
