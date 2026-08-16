//! Runtime contract of the tracked Cargo classification owner.
//!
//! `.github/scripts/cargo_infrastructure.sh` decides whether a failed Cargo run
//! means "this code is wrong" or "this machine could not do the work", and every
//! repository and lifecycle proof exits on its answer. Reading the script proves
//! what it says; only running it proves what it does. So each row here sources
//! the tracked file in a guarded child shell and requires an exact transcript,
//! an exact exit status, one receipt, and no capture left behind.
//!
//! Each row owns its own root. `TMPDIR` and `PROOF_OUTPUT_DIR` point inside it,
//! so a capture the classifier failed to remove shows up as a file the row left
//! rather than as noise in a shared temporary directory. The supply-chain
//! process guard kills, reaps, drains, and joins every child before a row
//! asserts, and the root is removed when that row's `TempDir` drops.
//!
//! No signature this module exercises appears verbatim on any line of it. The
//! classifier reads Cargo's transcript, and Cargo puts source lines in that
//! transcript: a rustfmt diff, a clippy span, or a compiler error quoting one
//! of these samples verbatim would make every honest failure of this crate look
//! like an exhausted volume, and the loop would retry a real defect rather than
//! report it. So every matching sample is stored with underscores where its
//! spaces belong, and [`expanded`] restores them at the one boundary that hands
//! text to a child.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::TempDir;

use crate::process_guard::{Completed, Run, execute};

/// Every row runs one short shell body, so a row that overran this budget is
/// broken rather than slow.
const ROW_BUDGET: Duration = Duration::from_secs(60);

/// What every row runs before its own body.
const PRELUDE: &str = "set -uo pipefail\n. .github/scripts/cargo_infrastructure.sh\n";

/// Representative Cargo output for each infrastructure signature, in the order
/// the signature table states them, written in the redacted form this module's
/// header requires.
pub(crate) const INFRASTRUCTURE_MATCHES: &[&str] = &[
    "warning:_spurious_network_error_(3_tries_remaining)",
    "failed_to_fetch_https://github.com/rust-lang/crates.io-index",
    "Could_not_resolve_host:_index.crates.io",
    "error:_could_not_download_file_from_crates.io",
    "No_space_left_on_device_(os_error_28)",
    "Read-only_file_system_(os_error_30)",
    "failed_to_acquire_package_cache_lock",
    "toolchain_'1.90.0'_is_not_installed",
    "rustup_could_not_choose_a_version_of_cargo_to_run",
];

/// The near miss each signature must refuse, in the same order. A classifier
/// that matched loosely, or that folded case, would call one of these an
/// unavailable machine and retry a real failure forever.
///
/// These are safe to write plainly: not matching the table is what they are.
const INFRASTRUCTURE_NEAR_MISSES: &[&str] = &[
    "network capability forbidden",
    "failed to validate fetched metadata",
    "host target is unsupported",
    "error: downloaded checksum mismatch",
    "space reservation is below policy",
    "read-only API contract failed",
    "package cache entry is corrupt",
    "toolchain component failed to compile",
    "rustup target selection was rejected",
];

/// The one sample the aggregation and `cargo_run` rows need.
const REPRESENTATIVE_MATCH: &str = INFRASTRUCTURE_MATCHES[4];

/// The status a matching transcript becomes.
const INFRASTRUCTURE_STATUS: &str = "75";

/// The ordinary failure a near miss must keep.
const ORDINARY_STATUS: &str = "4";

/// The body both classification entry points answer for.
const CLASSIFY_BODY: &str = concat!(
    "printf '%s\\n' \"$CLASSIFY_SAMPLE\" > \"$CLASSIFY_CAPTURE\"\n",
    "printf 'output=%s\\n' \"$(cargo_classify_output \"$CLASSIFY_STATUS\" \"$CLASSIFY_SAMPLE\")\"\n",
    "printf 'file=%s\\n' \"$(cargo_classify \"$CLASSIFY_STATUS\" \"$CLASSIFY_CAPTURE\")\"\n",
);

/// The body whose recorded infrastructure status must outrank an earlier
/// ordinary failure and leave before the statement after it.
const RECORD_BODY: &str = concat!(
    "cargo_record 3\n",
    "printf 'before\\n'\n",
    "cargo_record 1 \"$CLASSIFY_SAMPLE\"\n",
    "printf 'sentinel\\n'\n",
    "exit \"$(cargo_worst)\"\n",
);

/// The body whose run reports an unavailable machine.
const INFRASTRUCTURE_RUN_BODY: &str = concat!(
    "cargo_run infra /bin/sh -c 'printf \"%s\\n\" \"$CLASSIFY_SAMPLE\"; exit 1'\n",
    "printf 'sentinel\\n'\n",
    "exit \"$(cargo_worst)\"\n",
);

/// The body whose capture cannot be allocated, because its `TMPDIR` is a file.
const ALLOCATION_BODY: &str = concat!(
    "cargo_run alloc /bin/sh -c 'printf \"ran\\n\"'\n",
    "printf 'sentinel\\n'\n",
    "exit \"$(cargo_worst)\"\n",
);

/// One classification row: the status Cargo reported, the transcript it wrote,
/// and the status the classifier must print for both input forms.
struct ClassifyRow {
    status: &'static str,
    output: &'static str,
    expected: &'static str,
}

/// One aggregation or `cargo_run` row: a shell body, the transcript it must
/// replay, the status it must exit with, and the receipts it must leave.
struct LifecycleRow {
    label: &'static str,
    body: &'static str,
    stdout: &'static str,
    code: i32,
    receipts: &'static [(&'static str, &'static str)],
}

const LIFECYCLE_ROWS: &[LifecycleRow] = &[
    LifecycleRow {
        label: "the first ordinary failure survives a later success",
        body: "cargo_record 3\ncargo_record 0\nprintf 'sentinel\\n'\nexit \"$(cargo_worst)\"\n",
        stdout: "sentinel\n",
        code: 3,
        receipts: &[],
    },
    LifecycleRow {
        label: "a near-miss transcript keeps its ordinary status",
        body: "cargo_record 4 'read-only API contract failed'\n\
               printf 'sentinel\\n'\nexit \"$(cargo_worst)\"\n",
        stdout: "sentinel\n",
        code: 4,
        receipts: &[],
    },
    LifecycleRow {
        label: "a successful run replays once and leaves one receipt",
        body: "cargo_run ok /bin/sh -c 'printf \"run-ok\\n\"'\n\
               printf 'sentinel\\n'\nexit \"$(cargo_worst)\"\n",
        stdout: "run-ok\nsentinel\n",
        code: 0,
        receipts: &[("ok.log", "run-ok\n")],
    },
    LifecycleRow {
        label: "an ordinary run is recorded and the caller continues",
        body: "cargo_run bad /bin/sh -c 'printf \"run-bad\\n\"; exit 4'\n\
               printf 'sentinel\\n'\nexit \"$(cargo_worst)\"\n",
        stdout: "run-bad\nsentinel\n",
        code: 4,
        receipts: &[("bad.log", "run-bad\n")],
    },
];

/// The tracked classifier answers every signature, near miss, aggregation, and
/// `cargo_run` path exactly, and owns its capture on all of them.
#[test]
fn cargo_infrastructure_classifier_runtime_contract_is_exact() {
    for row in classify_rows().iter() {
        classification_row_reports_the_exact_status(&RowRoot::new(), row);
    }
    for row in LIFECYCLE_ROWS {
        lifecycle_row_replays_records_and_cleans_up(&RowRoot::new(), row);
    }
    infrastructure_record_leaves_before_the_next_statement(&RowRoot::new());
    infrastructure_run_replays_reclassifies_and_leaves(&RowRoot::new());
    capture_allocation_failure_exits_before_the_command(&RowRoot::with_unusable_tmp());
}

/// Every classification row: one success that must stay 0 despite a matching
/// transcript, the nine signatures, and the nine near misses.
fn classify_rows() -> Box<[ClassifyRow]> {
    let mut rows = vec![ClassifyRow {
        status: "0",
        output: REPRESENTATIVE_MATCH,
        expected: "0",
    }];
    rows.extend(
        INFRASTRUCTURE_MATCHES
            .iter()
            .copied()
            .map(|output| ClassifyRow {
                status: "1",
                output,
                expected: INFRASTRUCTURE_STATUS,
            }),
    );
    rows.extend(
        INFRASTRUCTURE_NEAR_MISSES
            .iter()
            .copied()
            .map(|output| ClassifyRow {
                status: ORDINARY_STATUS,
                output,
                expected: ORDINARY_STATUS,
            }),
    );
    rows.into_boxed_slice()
}

/// Both entry points report the row's status for the row's transcript.
fn classification_row_reports_the_exact_status(root: &RowRoot, row: &ClassifyRow) {
    let capture = root.capture_path();
    let capture_argument: Box<str> = capture.to_string_lossy().into();
    let sample = expanded(row.output);
    let environment = [
        ("CLASSIFY_STATUS", row.status),
        ("CLASSIFY_SAMPLE", sample.as_ref()),
        ("CLASSIFY_CAPTURE", capture_argument.as_ref()),
    ];
    let completed = root.run(CLASSIFY_BODY, &environment);
    let expected: Box<str> = format!("output={}\nfile={}\n", row.expected, row.expected).into();

    assert_transcript(&completed, row.output, &expected, 0);
    root.assert_no_capture(row.output);
    root.assert_receipts(row.output, &[]);
}

/// One aggregation or `cargo_run` row exits, replays, and leaves exactly what
/// its table row states.
fn lifecycle_row_replays_records_and_cleans_up(root: &RowRoot, row: &LifecycleRow) {
    let completed = root.run(row.body, &[]);

    assert_transcript(&completed, row.label, row.stdout, row.code);
    root.assert_no_capture(row.label);
    root.assert_receipts(row.label, row.receipts);
}

/// A recorded infrastructure transcript outranks an earlier ordinary failure
/// and leaves before the statement after it.
fn infrastructure_record_leaves_before_the_next_statement(root: &RowRoot) {
    let label = "a recorded infrastructure transcript leaves immediately";
    let sample = expanded(REPRESENTATIVE_MATCH);
    let completed = root.run(RECORD_BODY, &[("CLASSIFY_SAMPLE", sample.as_ref())]);

    assert_transcript(&completed, label, "before\n", 75);
    root.assert_no_capture(label);
    root.assert_receipts(label, &[]);
}

/// An infrastructure run replays its transcript once, says what it
/// reclassified, keeps its receipt, and leaves before the next statement.
fn infrastructure_run_replays_reclassifies_and_leaves(root: &RowRoot) {
    let label = "an infrastructure run leaves before the next statement";
    let sample = expanded(REPRESENTATIVE_MATCH);
    let completed = root.run(
        INFRASTRUCTURE_RUN_BODY,
        &[("CLASSIFY_SAMPLE", sample.as_ref())],
    );
    let receipt: Box<str> = format!("{sample}\n").into();
    let stdout: Box<str> = format!(
        "{receipt}[cargo_infrastructure] infra: INFRASTRUCTURE (exit 1 reclassified as 75)\n"
    )
    .into();

    assert_transcript(&completed, label, &stdout, 75);
    root.assert_no_capture(label);
    root.assert_receipts(label, &[("infra.log", receipt.as_ref())]);
}

/// A capture the classifier cannot allocate is an unavailable machine, so the
/// run exits 75 before the command it was asked to run produces anything.
fn capture_allocation_failure_exits_before_the_command(root: &RowRoot) {
    let label = "an unallocatable capture exits before the command";
    let completed = root.run(ALLOCATION_BODY, &[]);

    assert_transcript(&completed, label, "", 75);
    root.assert_no_capture(label);
    root.assert_receipts(label, &[]);
}

/// The child ended on its own with the stated status and transcript.
///
/// Exact equality is what proves the transcript was replayed once: a second
/// replay, a missing reclassification note, or a statement that ran after an
/// infrastructure exit all change these bytes.
fn assert_transcript(completed: &Completed, label: &str, stdout: &str, code: i32) {
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
    assert!(
        completed.stdout.as_ref() == stdout,
        "{label}: expected [{}] but read [{}], stderr=[{}]",
        redacted(stdout),
        redacted(&completed.stdout),
        redacted(&completed.stderr)
    );
}

/// One stored sample, with its underscores restored to the spaces a child sees.
pub(crate) fn expanded(text: &str) -> Box<str> {
    text.replace('_', " ").into()
}

/// One observed transcript, rendered back into the stored form so a failure
/// message cannot restate a signature. See this module's header.
pub(crate) fn redacted(text: &str) -> Box<str> {
    text.replace(' ', "_").into()
}

/// One row's own filesystem root: its `TMPDIR`, its receipt directory, and the
/// capture fixture a classification row reads. Dropping it removes all three.
struct RowRoot {
    root: TempDir,
    tmp: PathBuf,
    receipts: PathBuf,
}

impl RowRoot {
    /// A root whose `TMPDIR` is an empty directory the classifier may use.
    fn new() -> Self {
        Self::build(|tmp| fs::create_dir_all(tmp).expect("a writable temporary directory"))
    }

    /// A root whose `TMPDIR` is a regular file, so no capture can be created.
    fn with_unusable_tmp() -> Self {
        Self::build(|tmp| fs::write(tmp, b"not a directory").expect("a writable placeholder"))
    }

    fn build(prepare: impl FnOnce(&Path)) -> Self {
        let root = tempfile::tempdir().expect("a temporary row root");
        let tmp = root.path().join("tmp");
        let receipts = root.path().join("receipts");
        prepare(&tmp);
        fs::create_dir_all(&receipts).expect("a receipt directory");
        fs::create_dir_all(root.path().join("captures")).expect("a capture directory");
        Self {
            root,
            tmp,
            receipts,
        }
    }

    /// Where a classification row writes the transcript it classifies by path.
    fn capture_path(&self) -> PathBuf {
        self.root.path().join("captures/sample.log")
    }

    /// Run one shell body against the tracked classifier under the guard.
    fn run(&self, body: &str, extra: &[(&str, &str)]) -> Completed {
        let script: Box<str> = format!("{PRELUDE}{body}").into();
        let arguments = ["-c", script.as_ref()];
        let tmp: Box<str> = self.tmp.to_string_lossy().into();
        let receipts: Box<str> = self.receipts.to_string_lossy().into();
        let mut environment = vec![
            ("TMPDIR", tmp.as_ref()),
            ("PROOF_OUTPUT_DIR", receipts.as_ref()),
        ];
        environment.extend_from_slice(extra);
        let environment = environment.into_boxed_slice();
        let workspace = repository_root();
        let mut run = Run::program("bash", &workspace, &arguments);
        run.env = &environment;
        run.budget = ROW_BUDGET;
        execute(&run).unwrap_or_else(|failure| panic!("the guard failed: {failure}"))
    }

    /// No capture may survive the row, whatever status it reported.
    fn assert_no_capture(&self, label: &str) {
        let leftovers = match self.tmp.is_dir() {
            true => entries(&self.tmp),
            false => Box::default(),
        };
        assert!(
            leftovers.is_empty(),
            "{label}: the classifier left a capture behind: {leftovers:?}"
        );
    }

    /// The receipt directory holds exactly the named logs with exactly the
    /// bytes the row replayed.
    fn assert_receipts(&self, label: &str, expected: &[(&str, &str)]) {
        let names: Box<[Box<str>]> = expected.iter().map(|(name, _)| (*name).into()).collect();
        assert_eq!(
            entries(&self.receipts),
            names,
            "{label}: unexpected receipt inventory"
        );
        for (name, contents) in expected {
            let receipt = fs::read_to_string(self.receipts.join(name))
                .unwrap_or_else(|error| panic!("{label}: unreadable receipt {name}: {error}"));
            assert!(
                receipt == *contents,
                "{label}: receipt {name} holds [{}] rather than [{}]",
                redacted(&receipt),
                redacted(contents)
            );
        }
    }
}

/// The sorted file names one directory holds.
pub(crate) fn entries(directory: &Path) -> Box<[Box<str>]> {
    let mut names: Vec<Box<str>> = fs::read_dir(directory)
        .expect("a readable directory")
        .map(|entry| {
            entry
                .expect("a readable directory entry")
                .file_name()
                .to_string_lossy()
                .into()
        })
        .collect();
    names.sort();
    names.into_boxed_slice()
}

/// The workspace root, which is the only directory the tracked helper's
/// repository-relative path resolves from.
pub(crate) fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant has a workspace parent")
        .to_path_buf()
}
