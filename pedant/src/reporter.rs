use std::io::{self, Write};
use std::sync::Arc;

use pedant_core::GateVerdict;
use pedant_core::violation::Violation;
use pedant_types::AnalysisTier;

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
    /// Json output is handled by `output::write_json`
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
        write_verdict_lines(verdicts, writer)
    }
}

/// One text line per verdict, the sole owner of the verdict line grammar.
///
/// File, stdin, and project mode render one record type, so they render it one
/// way: a reader parses a single separator and evidence appears wherever a rule
/// produced it.
fn write_verdict_lines<W: Write>(verdicts: &[GateVerdict], writer: &mut W) -> io::Result<()> {
    for verdict in verdicts {
        writeln!(
            writer,
            "{}: {} — {}{}",
            verdict.severity,
            verdict.rule,
            verdict.rationale,
            crate::output::evidence_fields(verdict)?
        )?;
    }
    Ok(())
}

/// Emit one project-mode gate result: the tier, every analyzed target, and each
/// verdict with the evidence that triggered it.
///
/// The summary lines come first and are emitted even for an empty verdict list,
/// so a clean run is observable rather than silent. Project mode has no summary
/// to suppress, so this owns no quiet flag.
pub fn report_project_gate<W: Write>(
    tier: AnalysisTier,
    targets: &[Arc<str>],
    verdicts: &[GateVerdict],
    writer: &mut W,
) -> io::Result<()> {
    writeln!(writer, "analysis-tier: {}", crate::output::tier_token(tier))?;
    for target in targets {
        writeln!(writer, "target: {}", crate::output::compact(&**target)?)?;
    }
    write_verdict_lines(verdicts, writer)
}
