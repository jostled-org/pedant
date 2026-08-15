use std::io::{self, Write};
use std::process::ExitCode;

use pedant_core::checks::ALL_CHECKS;
use pedant_core::gate::{GateRuleInfo, all_gate_rules, all_module_boundary_rules};
use pedant_core::violation::lookup_rationale;

pub(crate) fn run_print_checks_list(stderr: &mut impl Write) -> ExitCode {
    match print_checks_list() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            crate::report_error(stderr, format_args!("error writing output: {e}"));
            ExitCode::from(2)
        }
    }
}

pub(crate) fn print_explain(code: &str, stderr: &mut impl Write) -> ExitCode {
    if let Some(rationale) = lookup_rationale(code) {
        return write_result_to_exit(write_explain(code, &rationale), stderr);
    }

    let gate_rules = every_gate_rule();
    if let Some(rule) = gate_rules.iter().find(|r| r.name == code) {
        return write_result_to_exit(write_gate_explain(rule), stderr);
    }

    crate::report_error(stderr, format_args!("Unknown check: {code}"));
    crate::report_error(
        stderr,
        format_args!("Use --list-checks to see available checks."),
    );
    ExitCode::from(1)
}

/// Column width for the check-code table: the longest code plus a space.
const CODE_WIDTH: usize = 24;

/// Every gate rule the binary can list or explain, capability rules first.
///
/// Both catalogs are read once through this owner, so a rule that
/// configuration accepts always has a listing and an explanation.
fn every_gate_rule() -> Box<[GateRuleInfo]> {
    all_gate_rules()
        .into_iter()
        .chain(all_module_boundary_rules())
        .collect()
}

fn print_checks_list() -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Available checks:\n")?;
    writeln!(stdout, "{:<CODE_WIDTH$} {:<8} DESCRIPTION", "CODE", "LLM?")?;
    writeln!(stdout, "{:-<CODE_WIDTH$} {:-<8} {:-<30}", "", "", "")?;

    for check in ALL_CHECKS {
        let llm_marker = match check.llm_specific {
            true => "yes",
            false => "",
        };
        writeln!(
            stdout,
            "{:<CODE_WIDTH$} {:<8} {}",
            check.code, llm_marker, check.description
        )?;
    }

    let gate_rules = every_gate_rule();
    writeln!(stdout, "\nGate rules:\n")?;
    writeln!(stdout, "{:<30} {:<8} DESCRIPTION", "RULE", "SEVERITY")?;
    writeln!(stdout, "{:-<30} {:-<8} {:-<40}", "", "", "")?;

    for rule in gate_rules.iter() {
        writeln!(
            stdout,
            "{:<30} {:<8} {}",
            rule.name, rule.default_severity, rule.description
        )?;
    }

    writeln!(stdout)?;
    writeln!(stdout, "Use --explain <CODE> for detailed rationale.")
}

fn write_result_to_exit(io_outcome: io::Result<()>, stderr: &mut impl Write) -> ExitCode {
    match io_outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            crate::report_error(stderr, format_args!("error writing output: {e}"));
            ExitCode::from(2)
        }
    }
}

fn write_explain(code: &str, rationale: &pedant_core::violation::CheckRationale) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Check: {code}\n")?;
    writeln!(stdout, "{rationale}")
}

fn write_gate_explain(rule: &pedant_core::gate::GateRuleInfo) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Gate rule: {}\n", rule.name)?;
    writeln!(stdout, "Severity: {}", rule.default_severity)?;
    writeln!(stdout, "Description: {}\n", rule.description)?;
    writeln!(stdout, "Rationale: {}", rule.rationale)
}
