//! Holding one tracked repository check to its registration.
//!
//! A default-off feature graph is only as proven as the job that runs its
//! checker. A script that is present, correct, and reachable from nothing at
//! all looks exactly like one that runs on every push, so every plan that adds
//! a checker asks the same three questions of it: can the workflow execute it,
//! does the workflow execute it, and does ShellCheck lint it.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use crate::resolution::authority_scan::read_text;
use crate::resolution::root_inventory::workspace_root;

/// The workflow that runs every tracked check.
pub(crate) const CI_WORKFLOW: &str = ".github/workflows/ci.yml";

/// The ShellCheck inventory every tracked script must appear in.
pub(crate) const SHELLCHECK_INVENTORY: &str = ".github/scripts/run_shellcheck.sh";

/// One tracked path, resolved against the workspace root.
pub(crate) fn tracked_path(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

/// Every named script is executable and linted.
///
/// Split from the CI clause below because registration is not one shape for
/// every script. A script a push-triggered job cannot run still has to be
/// executable for its live owner to run it, and still has to be a ShellCheck
/// subject — and a caller with no `- run:` line to point at would otherwise
/// restate both clauses itself.
///
/// The inventory is asked once for the whole list, because the answer does not
/// change between two scripts and the run is a process.
pub(crate) fn assert_scripts_are_executable_and_linted(scripts: &[&str]) {
    assert!(
        !scripts.is_empty(),
        "a registration claim over no script constrains nothing"
    );
    let linted = linted_scripts();
    for script in scripts {
        assert_executable(script);
        assert!(
            linted.iter().any(|subject| &**subject == *script),
            "{SHELLCHECK_INVENTORY} must lint {script}"
        );
    }
}

/// Every path the tracked ShellCheck runner states it lints.
///
/// Asked of the runner rather than read out of it. The subject list is derived
/// from the directories that hold the scripts, so the file holds no path to
/// search for and a text scan would report every script as unlinted. `--list`
/// prints the same expansion the lint run passes to the analyser, so this reads
/// the coverage rather than a second copy of it.
///
/// Run once for the whole binary: the answer is a property of the tree, and
/// every case that asks costs a process otherwise.
pub(crate) fn linted_scripts() -> &'static [Box<str>] {
    static LINTED: OnceLock<Box<[Box<str>]>> = OnceLock::new();
    LINTED.get_or_init(|| {
        let listed = Command::new("bash")
            .arg(tracked_path(SHELLCHECK_INVENTORY))
            .arg("--list")
            .current_dir(workspace_root())
            .output()
            .unwrap_or_else(|error| panic!("{SHELLCHECK_INVENTORY} --list: {error}"));
        assert!(
            listed.status.success(),
            "{SHELLCHECK_INVENTORY} --list must state its subjects: {}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let subjects: Box<[Box<str>]> = String::from_utf8_lossy(&listed.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(Box::from)
            .collect();
        assert!(
            !subjects.is_empty(),
            "{SHELLCHECK_INVENTORY} --list stated no subject, so every claim over it is vacuous"
        );
        subjects
    })
}

/// Every named check is executable, linted, and run once by the tracked
/// workflow.
///
/// The workflow is read once for the whole list, for the reason the inventory
/// above is.
pub(crate) fn assert_checks_are_executable_linted_and_in_ci(scripts: &[&str]) {
    assert_scripts_are_executable_and_linted(scripts);
    let workflow = executed_workflow();
    for script in scripts {
        assert_eq!(
            workflow.matches(&format!("- run: {script}")).count(),
            1,
            "{CI_WORKFLOW} must run {script} exactly once"
        );
    }
}

/// The tracked workflow with every commented-out line dropped.
///
/// A count over the raw file reads `# - run: check.sh` as an invocation, so a
/// check disabled in place satisfies the registration claim while nothing
/// executes it — the same silent pass `comment_scan` exists to stop for Rust.
/// Whole-line comments are what YAML disables a step with; a trailing comment
/// beside a live `- run:` leaves the step running and is kept.
///
/// Read and stripped once for the whole binary, for the reason the inventory
/// above is: the workflow is a property of the commit, and every registration
/// claim asks the same question of the same file.
fn executed_workflow() -> &'static str {
    static EXECUTED: OnceLock<String> = OnceLock::new();
    EXECUTED.get_or_init(|| {
        read_text(CI_WORKFLOW)
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<&str>>()
            .join("\n")
    })
}

/// A tracked check is a file the workflow can execute.
#[cfg(unix)]
pub(crate) fn assert_executable(script: &str) {
    use std::os::unix::fs::PermissionsExt;

    let path = tracked_path(script);
    let mode = std::fs::metadata(&path)
        .unwrap_or_else(|error| panic!("{script}: {error}"))
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o111,
        0o111,
        "{script} must be executable; the workflow invokes it directly"
    );
}

/// The mode bit is a POSIX fact, and no job on this repository's Windows runner
/// compiles this root. The file must still be tracked.
///
/// Asked of Git rather than of the disk, which is what "tracked" means and what
/// the alternative — a file the workflow's checkout would not contain — is.
#[cfg(not(unix))]
pub(crate) fn assert_executable(script: &str) {
    assert!(
        crate::resolution::tracked_index::is_tracked(script),
        "{script} must be a tracked file"
    );
}
