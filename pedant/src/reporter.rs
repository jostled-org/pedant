use std::io::{self, Write};

use pedant_core::GateVerdict;
use pedant_core::violation::Violation;

/// Writes violation and gate verdict text output.
pub struct Reporter {
    quiet: bool,
}

impl Reporter {
    /// Construct with the summary suppression flag.
    pub fn new(quiet: bool) -> Self {
        Self { quiet }
    }

    /// Emit all violations to `writer` in text format.
    ///
    /// Json output is handled by [`crate::output::write_json_analysis_output`]
    /// before `report` is called, so only the Text path is reachable here.
    pub fn report<W: Write>(&self, violations: &[Violation], writer: &mut W) -> io::Result<()> {
        for v in violations {
            writeln!(writer, "{v}")?;
        }

        if !self.quiet && !violations.is_empty() {
            writeln!(writer)?;
            writeln!(writer, "Found {} violation(s)", violations.len())?;
        }

        Ok(())
    }

    /// Emit gate verdicts to `writer` in text format.
    ///
    /// Json output is handled before this method is called.
    pub fn report_gate<W: Write>(
        &self,
        verdicts: &[GateVerdict],
        writer: &mut W,
    ) -> io::Result<()> {
        for v in verdicts {
            writeln!(writer, "{}: {} — {}", v.severity, v.rule, v.rationale)?;
        }
        Ok(())
    }
}
