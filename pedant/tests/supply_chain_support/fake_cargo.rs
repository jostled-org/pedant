//! The stand-in Cargo a vendor journey runs against.
//!
//! `pedant supply-chain` shells out to `cargo vendor`. A fixture that wants a
//! specific vendored tree — or a specific way for Cargo to misbehave — installs
//! a script named `cargo` on the child's `PATH`. Every other subcommand is
//! forwarded to the real Cargo, so a fixture keeps a working
//! `generate-lockfile`.

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::process_guard::{BUDGET, Completed, Failure, PEDANT, POLL, Run, execute};

/// Run `pedant` with a caller-written `cargo vendor` body, under a guard.
pub(crate) fn run_with_fake_cargo(
    script_dir: &Path,
    consumer_root: &Path,
    vendor_body: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> Completed {
    guarded_run(script_dir, consumer_root, vendor_body, args, env, BUDGET)
        .unwrap_or_else(|failure| panic!("the guarded pedant run failed: {failure}"))
}

/// The same run under a caller-chosen budget, reporting the guard's failures.
pub(crate) fn guarded_run(
    script_dir: &Path,
    consumer_root: &Path,
    vendor_body: &str,
    args: &[&str],
    env: &[(&str, &str)],
    budget: Duration,
) -> Result<Completed, Failure> {
    write_fake_cargo_script(script_dir, vendor_body);
    let mut run = Run::program(PEDANT, consumer_root, args);
    run.path_prefix = Some(script_dir);
    run.env = env;
    run.budget = budget;
    execute(&run)
}

/// Run the real binary under a guard, with the real Cargo on `PATH`.
pub(crate) fn run_pedant_in(cwd: &Path, args: &[&str]) -> Completed {
    execute(&Run::new(cwd, args))
        .unwrap_or_else(|failure| panic!("the guarded pedant run failed: {failure}"))
}

/// A `cargo vendor` body that copies a prepared tree into place. It does not
/// exit, so a caller may append whatever else its case needs Cargo to do.
pub(crate) fn copying_vendor_body(vendor_source: &Path) -> String {
    format!(
        "mkdir -p \"$2\"\n  cp -R \"{}\"/. \"$2\"",
        vendor_source.display()
    )
}

fn write_fake_cargo_script(script_dir: &Path, vendor_body: &str) {
    let script_path = script_dir.join("cargo");
    std::fs::write(
        &script_path,
        format!(
            "#!/bin/sh\nif [ \"$1\" = vendor ]; then\n  {vendor_body}\nfi\nexec {} \"$@\"\n",
            real_cargo()
        ),
    )
    .expect("the fake cargo script should be writable");
    make_executable(&script_path);
}

/// Give one written fake tool the mode a `PATH` lookup needs.
#[cfg(unix)]
pub(crate) fn make_executable(script_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(script_path)
        .expect("the fake tool should exist")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(script_path, permissions).expect("the fake tool should be executable");
}

/// Windows resolves an interpreter rather than a mode bit.
#[cfg(windows)]
pub(crate) fn make_executable(_script_path: &Path) {}

/// Where the real Cargo lives, so the fake one can forward to it.
fn real_cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| String::from("cargo"))
}

/// Generate a lockfile for a fixture workspace, failing loudly if Cargo cannot.
///
/// Setup runs under the same guard as the journeys: an unbounded `Command` here
/// would let a wedged Cargo hang a run that owns every other child it starts.
pub(crate) fn generate_lockfile(root: &Path) {
    let cargo = real_cargo();
    let completed = execute(&Run::program(
        &cargo,
        root,
        &["generate-lockfile", "--offline"],
    ))
    .unwrap_or_else(|failure| panic!("the guarded cargo generate-lockfile failed: {failure}"));
    assert!(
        completed.success(),
        "failed to generate lockfile: {}",
        completed.transcript()
    );
}

/// The pid a fake-Cargo descendant recorded, once the file holds one.
pub(crate) fn descendant_pid(path: &Path, budget: Duration) -> Option<u32> {
    let deadline = Instant::now() + budget;
    loop {
        let recorded = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok());
        match (recorded, Instant::now() >= deadline) {
            (Some(pid), _) => return Some(pid),
            (None, true) => return None,
            (None, false) => thread::sleep(POLL),
        }
    }
}
