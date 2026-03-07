use std::io::{self, Write};

use crate::json_format::JsonViolation;
use crate::violation::Violation;

/// Output format for violation reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable text, one violation per line.
    #[default]
    Text,
    /// JSON array of violation objects.
    Json,
}

/// Formats and writes violation reports to a writer.
pub struct Reporter {
    format: OutputFormat,
    quiet: bool,
}

impl Reporter {
    /// Creates a reporter with the given format and quiet mode.
    pub fn new(format: OutputFormat, quiet: bool) -> Self {
        Self { format, quiet }
    }

    /// Writes all violations to the given writer in the configured format.
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
        let json_violations: Vec<JsonViolation<'_>> =
            violations.iter().map(JsonViolation::from).collect();
        serde_json::to_writer_pretty(&mut *writer, &json_violations).map_err(io::Error::other)?;
        writeln!(writer)?;
        Ok(())
    }
}
