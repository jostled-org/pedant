//! Holding the acceptance identities to [`super::authority_keys`].
//!
//! Three facts, and none of them implies the next: the manifest declares a
//! command, the workflow a clone receives runs that command, and every script
//! either one names is committed. A key checked for its text alone passes while
//! CI reads a file no checkout carries; the whole set is asserted here so the
//! next script added to a key cannot repeat that.
//!
//! `.manifest.toml` is local tooling, which is why this module carries
//! `resolution-test-support`. Its reads panic rather than skip.

use std::fs;

use crate::resolution::authority_keys::{
    CI_KEYS, GITIGNORE, RESOLUTION_CHECK_KEY, RESOLUTION_CHECK_PATHS, RESOLUTION_CHECK_PREFIX,
    SCRIPT_DIRECTORY, SOURCE_DIRECTIVE, WORKFLOW,
};
use crate::resolution::authority_scan::read_text;
use crate::resolution::root_inventory::workspace_root;

/// The acceptance keys this plan adds or widens carry their exact values.
pub fn assert_ci_keys() {
    for (key, expected) in CI_KEYS {
        assert_eq!(
            normalize(&ci_value(key)),
            normalize(expected),
            "[ci].{key} must hold the acceptance command this plan states"
        );
    }
}

/// Every script an acceptance key names, and every helper those scripts source,
/// exists and reaches a fresh checkout.
///
/// `docs/scripts/` is ignored wholesale and re-included one file at a time, so
/// a key can name a script that only this working copy holds — and the job it
/// was written for is the one place that fails. The two subject forms fail
/// differently and are checked differently. A named file that no commit carries
/// is a job that dies on a clone. A glob resolves against the checkout it runs
/// in, so on CI it stands for exactly its committed matches: it cannot name an
/// absent file, but it can quietly stand for nothing, which is what the
/// non-empty requirement rejects. `shellcheck -x` follows a `source=` directive
/// into a helper, so an uncommitted helper fails the lint as surely as a
/// missing subject would, and helpers are checked with their callers.
pub fn assert_committed_ci_scripts() {
    let ignore = read_text(GITIGNORE);
    for (key, _) in CI_KEYS {
        for subject in script_subjects(&ci_value(key)) {
            assert_subject_is_committed(&ignore, subject, key);
        }
    }
}

fn assert_subject_is_committed(ignore: &str, subject: &str, key: &str) {
    let committed: Vec<String> = expand(subject)
        .into_iter()
        .filter(|script| is_committed(ignore, script))
        .collect();
    assert!(
        !committed.is_empty(),
        "[ci].{key} names {subject}, which stands for no committed script; \
         CI reads {SCRIPT_DIRECTORY} from a fresh checkout, and {GITIGNORE} \
         re-includes one file at a time"
    );
    for script in &committed {
        assert!(
            workspace_root().join(script).exists(),
            "[ci].{key} names {script}, which does not exist"
        );
        for helper in sourced_helpers(script) {
            assert!(
                is_committed(ignore, &helper),
                "[ci].{key} runs {script}, which sources {helper}; \
                 shellcheck -x follows that directive, so an uncommitted helper \
                 fails the lint on a clone"
            );
        }
    }
}

/// `docs/scripts/` is ignored as a whole, so a script reaches a checkout only
/// through its own re-inclusion line.
fn is_committed(ignore: &str, script: &str) -> bool {
    let re_inclusion = format!("!{script}");
    ignore.lines().any(|line| line.trim() == re_inclusion)
}

/// The workflow a clone receives runs the commands the manifest declares.
///
/// The manifest is the plan loop's index; this file is what GitHub executes.
/// Two records of one identity can agree or drift, and only the comparison
/// tells them apart.
pub fn assert_workflow_mirrors_manifest() {
    let workflow = read_text(WORKFLOW);
    for (key, expected) in CI_KEYS {
        let expected_step = format!("- run: {expected}");
        let count = workflow
            .lines()
            .filter(|line| line.trim() == expected_step)
            .count();
        assert_eq!(
            count, 1,
            "{WORKFLOW} must carry exactly one executable [ci].{key} step: {expected}"
        );
    }
    let expected_paths = format!("paths: {}", RESOLUTION_CHECK_PATHS.join(" "));
    let count = workflow
        .lines()
        .filter(|line| line.trim() == expected_paths)
        .count();
    assert_eq!(
        count, 1,
        "{WORKFLOW} must carry exactly one pedant-check input with the paths [ci].{RESOLUTION_CHECK_KEY} names"
    );
}

/// The resolution test-coverage key names every affected root and support tree,
/// in order, and each one exists.
pub fn assert_resolution_check_coverage() {
    let command = ci_value(RESOLUTION_CHECK_KEY);
    let paths = command
        .strip_prefix(RESOLUTION_CHECK_PREFIX)
        .unwrap_or_else(|| {
            panic!("[ci].{RESOLUTION_CHECK_KEY} must run {RESOLUTION_CHECK_PREFIX}")
        });
    assert_eq!(
        paths.split_whitespace().collect::<Vec<&str>>(),
        RESOLUTION_CHECK_PATHS,
        "[ci].{RESOLUTION_CHECK_KEY} must cover exactly the affected roots and support trees"
    );

    let root = workspace_root();
    let missing: Vec<&&str> = RESOLUTION_CHECK_PATHS
        .iter()
        .filter(|path| !root.join(path).exists())
        .collect();
    assert!(
        missing.is_empty(),
        "the coverage key names paths that do not exist: {missing:?}"
    );
}

/// Every `docs/scripts/` subject one command names, as written.
fn script_subjects(command: &str) -> Vec<&str> {
    command
        .split_whitespace()
        .filter(|token| token.starts_with(SCRIPT_DIRECTORY))
        .collect()
}

/// The scripts one subject stands for: itself, or its glob's matches.
fn expand(subject: &str) -> Vec<String> {
    match subject.split_once('*') {
        None => vec![subject.to_owned()],
        Some((prefix, suffix)) => matching_scripts(prefix, suffix),
    }
}

/// The scripts one `prefix*suffix` subject stands for, in name order.
fn matching_scripts(prefix: &str, suffix: &str) -> Vec<String> {
    assert!(
        !suffix.contains('*'),
        "{prefix}*{suffix} carries two globs, and this reader expands one"
    );
    let directory = workspace_root().join(SCRIPT_DIRECTORY);
    let entries =
        fs::read_dir(&directory).unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
    let mut found: Vec<String> = entries
        .map(|entry| entry.unwrap_or_else(|error| panic!("{}: {error}", directory.display())))
        .map(|entry| {
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .unwrap_or_else(|_| panic!("{} has a non-UTF-8 file name", path.display()));
            format!("{SCRIPT_DIRECTORY}{name}")
        })
        .filter(|path| path.starts_with(prefix) && path.ends_with(suffix))
        .collect();
    found.sort();
    found
}

/// The helpers one script tells `shellcheck -x` to follow.
fn sourced_helpers(script: &str) -> Vec<String> {
    let text = read_text(script);
    text.lines()
        .filter_map(|line| line.trim().strip_prefix(SOURCE_DIRECTIVE))
        .map(|helper| format!("{SCRIPT_DIRECTORY}{helper}"))
        .collect()
}

fn ci_value(key: &str) -> String {
    ci_table()
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("[ci].{key} should be declared"))
        .to_owned()
}

fn ci_table() -> toml::Table {
    let manifest: toml::Table =
        toml::from_str(&read_text(".manifest.toml")).expect(".manifest.toml should parse");
    manifest
        .get("ci")
        .and_then(toml::Value::as_table)
        .expect("[ci] should be declared")
        .clone()
}

/// Collapse whitespace used to wrap a long model constant in Rust source.
fn normalize(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}
