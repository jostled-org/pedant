#![allow(dead_code)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn run_pedant(args: &[&str], stdin_data: Option<&str>) -> std::process::Output {
    run_pedant_in(env!("CARGO_MANIFEST_DIR"), args, stdin_data)
}

pub fn run_pedant_in(
    cwd: impl AsRef<Path>,
    args: &[&str],
    stdin_data: Option<&str>,
) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pedant"));
    // Strip GITHUB_OUTPUT so a spawned `supply-chain verify` never appends to
    // the CI runner's real output file. Parallel test subprocesses interleave
    // those writes, producing malformed lines that fail the workflow step.
    cmd.env_remove("RUST_LOG")
        .env_remove("GITHUB_OUTPUT")
        .current_dir(cwd)
        .args(args);

    match stdin_data {
        Some(data) => {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd.spawn().expect("failed to spawn pedant");
            child
                .stdin
                .take()
                .expect("stdin not available")
                .write_all(data.as_bytes())
                .expect("failed to write stdin");
            child.wait_with_output().expect("failed to wait")
        }
        None => cmd.output().expect("failed to run pedant"),
    }
}

/// The published capability wire shapes carry no lexical symbol data: symbol
/// evidence is a library projection, not an operator or persisted surface.
///
/// `subject` names the payload under test, so a failure says which surface
/// leaked.
pub fn assert_no_symbol_fields(payload: &str, subject: &str) {
    for field in ["\"symbols\"", "\"symbol_attribution\""] {
        assert!(
            !payload.contains(field),
            "{subject} must not carry {field}: {payload}"
        );
    }
}

pub fn run_subcommand(
    command: &str,
    args: &[&str],
    stdin_data: Option<&str>,
) -> std::process::Output {
    let mut full_args = Vec::with_capacity(args.len() + 1);
    full_args.push(command);
    full_args.extend_from_slice(args);
    run_pedant(&full_args, stdin_data)
}
