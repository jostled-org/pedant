//! What a finished packaged-workspace row must show, however it ended.
//!
//! [`super::row`] runs one row; this module reads it. The readings are shared
//! because every case module takes the same ones: the child's own exit, the
//! stated status, no process of this row surviving into the next, the target
//! root every Cargo call inherited, no proof-owned staging root, a pinned tool
//! root that matches how far the row got, and a caller's repository the proof
//! never wrote into.

use std::time::Duration;

use pedant_process_guard::wait_until_gone;

use super::fixture::{self, RELEASE_ORDER};
use super::row::{PINNED_BINARIES, RowRoot};
use crate::cargo_classifier_cases::{entries, redacted};
use crate::process_guard::Completed;

/// How long the killed process tree has to disappear after the guard's
/// teardown.
const REAP_BUDGET: Duration = Duration::from_secs(30);

/// The direct child every package-proof staging root uses beneath `TMPDIR`.
const STAGING_PREFIX: &str = "pedant-packaged-workspace.";

/// The status a classified infrastructure transcript becomes.
pub(super) const INFRASTRUCTURE_STATUS: i32 = 75;

/// The status a proof that handled TERM must leave with.
pub(super) const SIGNALLED_STATUS: i32 = 143;

/// The status a proof that refused its own graph must leave with.
pub(super) const REFUSED_STATUS: i32 = 1;

/// The isolated history packaging must find in the clone, newest first.
///
/// `cargo package --locked` builds an archive out of a committed tree and
/// refuses a dirty one, so what the archives hold is decided by the two commits
/// the proof writes: the breaking commit release-plz reads to choose a version,
/// and the one that commits what release-plz then wrote. The fake Cargo records
/// what it packaged onto, because the archive it produces looks the same either
/// way and the difference only shows up on the registry.
const PACKAGED_HISTORY: &[&str] = &[
    "package onto chore: stage the release-plz update",
    "package onto feat!: implement symbol capability profiles",
    "package onto base",
];

/// The refusal reached the operator.
pub(super) fn assert_refusal(label: &str, completed: &Completed, fragment: &str) {
    assert!(
        completed.stderr.contains(fragment),
        "{label}: the proof did not refuse with [{fragment}]: {}",
        redacted(&completed.transcript())
    );
}

/// A refused graph is refused before anything is built from it.
pub(super) fn assert_nothing_compiled(root: &RowRoot, label: &str) {
    assert!(
        !root
            .operations()
            .iter()
            .any(|entry| entry.as_ref() == "check"),
        "{label}: the proof compiled the archive workspace it had already refused"
    );
}

/// The pinned tool root outlives the row, and holds exactly what the row got as
/// far as installing.
///
/// A run that failed after installing the tools leaves them installed, and the
/// next run over that target is entitled to skip the quarter hour they cost; a
/// run that failed during installation leaves nothing to claim. A warm state
/// tied to the proof's own success would have said the opposite of both, and
/// the run that read it would have been held to the wrong budget. A tool stage
/// is the same claim from the other side: it must leave the one tool it was
/// named for and never the other.
pub(super) fn assert_tool_root_matches_the_row(root: &RowRoot, label: &str, installed: &[&str]) {
    for binary in PINNED_BINARIES.iter().copied() {
        assert_eq!(
            root.tool_build(binary).is_file(),
            installed.contains(&binary),
            "{label}: the pinned {binary} must survive this row exactly when it was installed"
        );
    }
}

/// What every row requires however it ended: the child's own exit, the stated
/// status, no process of this row surviving into the next, the inherited target
/// root on every Cargo call, no proof-owned staging root, and a pinned tool
/// root that matches how far the row got.
pub(super) fn assert_row_is_clean(
    root: &RowRoot,
    label: &str,
    completed: &Completed,
    code: i32,
    installed: &[&str],
) {
    assert!(
        !completed.timed_out(),
        "{label}: the row outlived its budget: {}",
        redacted(&completed.transcript())
    );
    assert_eq!(
        completed.code(),
        Some(code),
        "{label}: unexpected exit status: {}",
        redacted(&completed.transcript())
    );
    assert_no_process_survives_the_row(root, label);
    let targets = root.recorded_targets();
    assert!(
        !targets.is_empty(),
        "{label}: no Cargo operation ran, so the row proved nothing"
    );
    let expected: Box<str> = root.target.to_string_lossy().into();
    for observed in targets.iter() {
        assert_eq!(
            observed, &expected,
            "{label}: a Cargo operation inherited the wrong target root"
        );
    }
    assert!(
        root.target.is_dir() && root.target.is_absolute(),
        "{label}: the sentinel target root must stay an existing absolute directory"
    );
    assert_no_staging_root(root, label);
    assert_tool_root_matches_the_row(root, label, installed);
    assert_caller_repository_is_untouched(root, label);
}

/// No process this row started is still running once the row is read.
///
/// The reaping is the guard's work rather than the script's, and the script
/// says so: it leaves with the signal's status precisely so the build lease or
/// process guard that started it kills the command group, because a proof that
/// killed its own group would kill whatever ran it. [`crate::process_guard`]
/// terminates the group and joins both drains before `execute` returns, so this
/// reading states the fixture boundary the row owns — a descendant an
/// interrupted tool orphaned reaches no later row, and the recorded pids are
/// where containment that stopped covering the tree would show. That
/// containment has its own proof beside these rows in
/// `supply_chain_process_guard_reaps_descendants_on_success_timeout_and_early_error`.
/// The script's own release-what-it-owns claim is [`assert_no_staging_root`],
/// which the script performs and this suite falsifies.
pub(super) fn assert_no_process_survives_the_row(root: &RowRoot, label: &str) {
    for pid in root.recorded_pids().iter().copied() {
        assert!(
            wait_until_gone(pid, REAP_BUDGET),
            "{label}: the tool process {pid} survived the guard's teardown"
        );
    }
}

/// No package-proof staging root remains beneath the row's temporary root.
///
/// Platform tool launchers may create their own cache entries under `TMPDIR`.
/// Those entries are not owned by the package proof and must not be deleted or
/// mistaken for its staging resources.
pub(super) fn assert_no_staging_root(root: &RowRoot, label: &str) {
    let observed = entries(&root.tmp);
    assert!(
        !observed
            .iter()
            .any(|entry| entry.starts_with(STAGING_PREFIX)),
        "{label}: the proof left staging behind: {observed:?}"
    );
}

/// The caller's repository ends every row exactly as the fixture planted it.
///
/// The proof's whole method is to clone the repository it was run from, commit
/// twice into that clone, and let release-plz write versions, requirements,
/// changelogs, and a lockfile there. A regression that dropped the `-C
/// "${clone_root}"` from one of those commands would stage into the operator's
/// checkout instead, and every other reading a row takes — exit status, driven
/// operations, inherited target, absent staging root, tool root — would be
/// unchanged. The caller's head, refs, and working-tree changes are where that
/// lands.
pub(super) fn assert_caller_repository_is_untouched(root: &RowRoot, label: &str) {
    assert_eq!(
        fixture::repository_state(&root.repository),
        fixture::planted_state(&root.base),
        "{label}: the proof wrote into the caller's repository"
    );
}

/// The operation sequence a cold proof drives: build each tool and prove its
/// version before the next, then release.
///
/// One owner per tool, so the stage that builds one in its own slice and the
/// proof that needs both run the same code. Interleaved because each owner
/// proves what it just built rather than trusting the pair.
pub(super) fn expected_operations() -> Box<[Box<str>]> {
    let mut expected: Vec<Box<str>> = vec![
        "install cargo-semver-checks".into(),
        "version cargo-semver-checks".into(),
        "install release-plz".into(),
        "version release-plz".into(),
    ];
    expected.extend(release_operations());
    expected.into_boxed_slice()
}

/// The operation sequence a warm proof drives.
///
/// Two version probes and no installation: that is the proof asking the two
/// binaries in the target root whether they are the pinned revisions, believing
/// the answer, and reusing the quarter hour they cost.
pub(super) fn warm_expected_operations() -> Box<[Box<str>]> {
    let mut expected: Vec<Box<str>> = vec![
        "version cargo-semver-checks".into(),
        "version release-plz".into(),
    ];
    expected.extend(release_operations());
    expected.into_boxed_slice()
}

/// The operation sequence one tool stage drives: build the named tool, prove
/// what was built, stop.
pub(super) fn tool_stage_operations(binary: &str) -> Box<[Box<str>]> {
    Box::new([
        format!("install {binary}").into(),
        format!("version {binary}").into(),
    ])
}

/// Everything a proof drives once its pinned tools are in place, derived from
/// the release order rather than written out twice.
fn release_operations() -> Vec<Box<str>> {
    let mut expected: Vec<Box<str>> = vec![
        "update release-plz semver-checks-present".into(),
        "metadata staged".into(),
    ];
    expected.extend(PACKAGED_HISTORY.iter().copied().map(Box::from));
    for name in RELEASE_ORDER {
        expected.push(format!("package {name}").into());
    }
    for name in RELEASE_ORDER {
        expected.push(format!("metadata extracted {name}").into());
    }
    expected.push("generate-lockfile".into());
    expected.push("metadata archive".into());
    expected.push("check".into());
    expected
}
