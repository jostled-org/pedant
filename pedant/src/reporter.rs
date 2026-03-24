use std::io::{self, Write};

use pedant_core::GateVerdict;
use pedant_core::json_format::JsonViolation;
use pedant_core::violation::Violation;

/// Selects how violations and gate verdicts are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// One violation per line, suitable for editor integration.
    #[default]
    Text,
    /// Machine-readable JSON array.
    Json,
}

/// Writes violations and gate verdicts in the selected output format.
pub struct Reporter {
    format: OutputFormat,
    quiet: bool,
}

impl Reporter {
    /// Construct with the desired format and summary suppression flag.
    pub fn new(format: OutputFormat, quiet: bool) -> Self {
        Self { format, quiet }
    }

    /// Emit all violations to `writer` in the configured format.
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
        use serde::Serializer;
        use serde::ser::SerializeSeq;
        let serializer = &mut serde_json::Serializer::pretty(&mut *writer);
        let mut seq = serializer
            .serialize_seq(Some(violations.len()))
            .map_err(io::Error::other)?;
        for v in violations {
            seq.serialize_element(&JsonViolation::from(v))
                .map_err(io::Error::other)?;
        }
        serde::ser::SerializeSeq::end(seq).map_err(io::Error::other)?;
        writeln!(writer)?;
        Ok(())
    }

    /// Emit gate verdicts to `writer` in the configured format.
    pub fn report_gate<W: Write>(
        &self,
        verdicts: &[GateVerdict],
        writer: &mut W,
    ) -> io::Result<()> {
        match self.format {
            OutputFormat::Text => self.report_gate_text(verdicts, writer),
            OutputFormat::Json => self.report_gate_json(verdicts, writer),
        }
    }

    fn report_gate_text<W: Write>(
        &self,
        verdicts: &[GateVerdict],
        writer: &mut W,
    ) -> io::Result<()> {
        for v in verdicts {
            writeln!(writer, "{}: {} — {}", v.severity, v.rule, v.rationale)?;
        }
        Ok(())
    }

    fn report_gate_json<W: Write>(
        &self,
        verdicts: &[GateVerdict],
        writer: &mut W,
    ) -> io::Result<()> {
        serde_json::to_writer_pretty(&mut *writer, verdicts).map_err(io::Error::other)?;
        writeln!(writer)?;
        Ok(())
    }
}
