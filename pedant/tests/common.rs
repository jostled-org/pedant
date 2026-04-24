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
    cmd.env_remove("RUST_LOG").current_dir(cwd).args(args);

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
