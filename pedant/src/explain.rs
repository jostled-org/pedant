use std::io::{self, Write};
use std::process::ExitCode;

use pedant_core::checks::ALL_CHECKS;
use pedant_core::gate::all_gate_rules;
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

    let gate_rules = all_gate_rules();
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

fn print_checks_list() -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Available checks:\n")?;
    writeln!(stdout, "{:<20} {:<8} DESCRIPTION", "CODE", "LLM?")?;
    writeln!(stdout, "{:-<20} {:-<8} {:-<30}", "", "", "")?;

    for check in ALL_CHECKS {
        let llm_marker = match check.llm_specific {
            true => "yes",
            false => "",
        };
        writeln!(
            stdout,
            "{:<20} {:<8} {}",
            check.code, llm_marker, check.description
        )?;
    }

    let gate_rules = all_gate_rules();
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
