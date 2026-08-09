//! The well-formed input set every contract row starts from.
//!
//! One fixture, stated once: a row that built its own valid inputs could differ
//! from the others in a second way and pass for the wrong reason.

use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::receipt::{self, CompletionProofInputs, QueryRecord};

/// A synthetic commit name of the right shape, owned by this root.
const SYNTHETIC_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

/// A synthetic terminal summary, owned by this root.
const SYNTHETIC_SUMMARY: &str = "step 7 synthetic identity: fmt, clippy, and tests recorded";

/// A valid input set and the directory the runner would own for it.
pub(crate) struct Fixture {
    /// Kept so the proof directory outlives every case that writes into it.
    dir: TempDir,
    /// The inputs a case mutates.
    pub(crate) inputs: CompletionProofInputs,
}

impl Fixture {
    /// A well-formed input set: canonical root, shaped HEAD, two packages, a
    /// summary, a fresh runner directory, and a path nothing has written yet.
    pub(crate) fn valid() -> Self {
        let dir = tempfile::tempdir().expect("the proof directory should be creatable");
        let proof_output_dir = canonical(dir.path());
        let receipt_path = proof_output_dir.join("completion-receipt.json");
        Self {
            dir,
            inputs: CompletionProofInputs {
                root: workspace_root(),
                head_sha: SYNTHETIC_SHA.into(),
                test_scope: Box::from([Box::from("pedant-core"), Box::from("pedant-mcp")]),
                terminal_summary: SYNTHETIC_SUMMARY.into(),
                proof_output_dir,
                receipt_path,
            },
        }
    }

    /// The runner-owned directory, for a case that needs a second path in it.
    pub(crate) fn dir(&self) -> PathBuf {
        canonical(self.dir.path())
    }

    /// Write the receipt this input set describes, with plausible counts.
    pub(crate) fn write_receipt(&self) -> Result<(), String> {
        let queries: Box<[QueryRecord]> = self
            .inputs
            .expected_queries()
            .iter()
            .enumerate()
            .map(|(index, (package, tool))| QueryRecord {
                package: (*package).into(),
                tool: (*tool).into(),
                results: index,
            })
            .collect();
        receipt::write(&self.inputs, queries)
    }
}

/// A temporary root is reached through a symbolic link on macOS, so every
/// path this fixture hands the validator is resolved first. A case that
/// supplied the unresolved spelling would be refused for that rather than for
/// the defect it meant to introduce.
fn canonical(path: &Path) -> PathBuf {
    path.canonicalize()
        .unwrap_or_else(|error| panic!("{} is not canonical: {error}", path.display()))
}

/// The canonical root of the repository this crate sits in.
pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant-mcp sits inside the workspace root")
        .canonicalize()
        .expect("the workspace root should be canonical")
}

/// A well-formed input set and its own receipt are accepted.
///
/// Without this the rows above would pass against a validator that refused
/// everything, which proves nothing about a real run.
pub(crate) fn assert_valid_inputs_and_receipt_pass() {
    let fixture = Fixture::valid();
    fixture
        .inputs
        .validate()
        .expect("the well-formed input set is valid");
    fixture
        .write_receipt()
        .expect("the receipt should be writable");
    receipt::validate(&fixture.inputs).expect("the receipt this input set produced is valid");
}
