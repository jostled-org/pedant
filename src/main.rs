use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use pedant::config::{
    check_path_override, find_config_file, load_config_file, Cli, ConfigFile, PatternCheck,
    PatternOverride,
};
use pedant::reporter::Reporter;
use pedant::checks::ALL_CHECKS;
use pedant::violation::{lookup_rationale, Violation};
use pedant::visitor::{analyze, CheckConfig};

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.list_checks {
        print_checks_list();
        return ExitCode::SUCCESS;
    }

    if let Some(ref code) = cli.explain {
        return print_explain(code);
    }

    let file_config = load_file_config(&cli);
    let base_config = cli.to_check_config(file_config.as_ref());

    let mut all_violations: Vec<Violation> = Vec::new();
    let mut had_error = false;

    match cli.stdin {
        true => handle_result(
            process_stdin(&base_config),
            "error",
            &mut all_violations,
            &mut had_error,
        ),
        false => {
            for file_path in &cli.files {
                let config = resolve_config_for_path(file_path, &base_config, file_config.as_ref());
                let Some(cfg) = config else { continue };
                handle_result(
                    process_file(file_path, &cfg),
                    file_path,
                    &mut all_violations,
                    &mut had_error,
                );
            }
        }
    }

    let reporter = Reporter::new(cli.output_format(), cli.quiet);
    let mut stdout = io::stdout().lock();
    if let Err(e) = reporter.report(&all_violations, &mut stdout) {
        eprintln!("error writing output: {e}");
        return ExitCode::from(2);
    }

    match (had_error, all_violations.is_empty()) {
        (true, _) => ExitCode::from(2),
        (false, false) => ExitCode::from(1),
        (false, true) => ExitCode::from(0),
    }
}

fn load_file_config(cli: &Cli) -> Option<ConfigFile> {
    let config_path = cli.config.as_ref().map(Path::new).map(Path::to_path_buf)
        .or_else(find_config_file)?;

    match load_config_file(&config_path) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            eprintln!("warning: {e}");
            None
        }
    }
}

fn resolve_config_for_path(
    file_path: &str,
    base_config: &CheckConfig,
    file_config: Option<&ConfigFile>,
) -> Option<CheckConfig> {
    let Some(fc) = file_config else {
        return Some(base_config.clone());
    };

    let Some(override_cfg) = check_path_override(file_path, fc) else {
        return Some(base_config.clone());
    };

    if override_cfg.enabled == Some(false) {
        return None;
    }

    let mut config = base_config.clone();
    if let Some(max_depth) = override_cfg.max_depth {
        config.max_depth = max_depth;
    }

    apply_pattern_override(&mut config.forbid_attributes, &override_cfg.forbid_attributes);
    apply_pattern_override(&mut config.forbid_types, &override_cfg.forbid_types);
    apply_pattern_override(&mut config.forbid_calls, &override_cfg.forbid_calls);
    apply_pattern_override(&mut config.forbid_macros, &override_cfg.forbid_macros);
    if let Some(forbid_else) = override_cfg.forbid_else {
        config.forbid_else = forbid_else;
    }
    if let Some(forbid_unsafe) = override_cfg.forbid_unsafe {
        config.forbid_unsafe = forbid_unsafe;
    }
    if let Some(v) = override_cfg.check_dyn_return {
        config.check_dyn_return = v;
    }
    if let Some(v) = override_cfg.check_dyn_param {
        config.check_dyn_param = v;
    }
    if let Some(v) = override_cfg.check_vec_box_dyn {
        config.check_vec_box_dyn = v;
    }
    if let Some(v) = override_cfg.check_dyn_field {
        config.check_dyn_field = v;
    }
    if let Some(v) = override_cfg.check_clone_in_loop {
        config.check_clone_in_loop = v;
    }
    if let Some(v) = override_cfg.check_default_hasher {
        config.check_default_hasher = v;
    }
    if let Some(v) = override_cfg.check_mixed_concerns {
        config.check_mixed_concerns = v;
    }
    if let Some(v) = override_cfg.check_inline_tests {
        config.check_inline_tests = v;
    }

    Some(config)
}

fn apply_pattern_override(check: &mut PatternCheck, override_opt: &Option<PatternOverride>) {
    let Some(ovr) = override_opt else { return };

    if let Some(enabled) = ovr.enabled {
        check.enabled = enabled;
    }

    if !ovr.patterns.is_empty() {
        check.patterns = ovr.patterns.clone();
    }
}

fn process_stdin(config: &CheckConfig) -> Result<Vec<Violation>, String> {
    let mut source = String::new();
    io::stdin()
        .read_to_string(&mut source)
        .map_err(|e| format!("failed to read stdin: {e}"))?;

    analyze("<stdin>", &source, config)
        .map_err(|e| format!("parse error: {e}"))
}

fn process_file(file_path: &str, config: &CheckConfig) -> Result<Vec<Violation>, String> {
    let source = fs::read_to_string(file_path)
        .map_err(|e| format!("failed to read file: {e}"))?;

    analyze(file_path, &source, config)
        .map_err(|e| format!("parse error: {e}"))
}

fn handle_result(
    result: Result<Vec<Violation>, String>,
    context: &str,
    violations: &mut Vec<Violation>,
    had_error: &mut bool,
) {
    match result {
        Ok(v) => violations.extend(v),
        Err(e) => {
            eprintln!("{context}: {e}");
            *had_error = true;
        }
    }
}

fn print_checks_list() {
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "Available checks:\n");
    let _ = writeln!(stdout, "{:<20} {:<8} DESCRIPTION", "CODE", "LLM?");
    let _ = writeln!(stdout, "{:-<20} {:-<8} {:-<30}", "", "", "");

    for check in ALL_CHECKS {
        let llm_marker = match check.llm_specific {
            true => "yes",
            false => "",
        };
        let _ = writeln!(stdout, "{:<20} {:<8} {}", check.code, llm_marker, check.description);
    }

    let _ = writeln!(stdout);
    let _ = writeln!(stdout, "Use --explain <CODE> for detailed rationale.");
}

fn print_explain(code: &str) -> ExitCode {
    let Some(rationale) = lookup_rationale(code) else {
        eprintln!("Unknown check: {code}");
        eprintln!("Use --list-checks to see available checks.");
        return ExitCode::from(1);
    };

    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "Check: {code}\n");

    let _ = writeln!(stdout, "Problem:");
    let _ = writeln!(stdout, "  {}\n", rationale.problem);

    let _ = writeln!(stdout, "Fix:");
    let _ = writeln!(stdout, "  {}\n", rationale.fix);

    let _ = writeln!(stdout, "Exception:");
    let _ = writeln!(stdout, "  {}\n", rationale.exception);

    let llm_note = match rationale.llm_specific {
        true => "Yes - particularly relevant for LLM-generated code",
        false => "No - general code quality check",
    };
    let _ = writeln!(stdout, "LLM-specific: {llm_note}");

    ExitCode::SUCCESS
}
