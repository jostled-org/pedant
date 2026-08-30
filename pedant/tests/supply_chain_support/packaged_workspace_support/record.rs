//! What one row's fake tools left behind, read back.
//!
//! [`super::row`] owns the root, the fixture, and the run. This owns the reading
//! of what that run recorded: the operations, the target roots they inherited,
//! the processes they became, and the three documents the packaging wrote. The
//! two were one type until `RowRoot` carried sixteen inherent methods and
//! pedant's `high-method-count` rule refused it, and they are two concerns
//! rather than one long list — a root is created once and handed to a run, while
//! a record is asked a question after that run has finished.
//!
//! A [`Record`] borrows the two directories rather than owning copies of them.
//! The row still hands both to its children through the environment, and a
//! second copy of either path here would be a second answer to where a row's
//! state is.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::cargo_classifier_cases::entries;

/// The record one row's fake tools kept, read from the row that owns it.
pub(super) struct Record<'row> {
    /// Where the fake tools wrote what they did.
    state: &'row Path,
    /// The target root the packaging left its archives in.
    target: &'row Path,
}

impl<'row> Record<'row> {
    /// The record kept under one row's state and target directories.
    pub(super) fn of(state: &'row Path, target: &'row Path) -> Self {
        Self { state, target }
    }

    /// Everything the fake tools recorded doing, in order.
    pub(super) fn operations(&self) -> Box<[Box<str>]> {
        recorded_lines(&self.state.join("operations"))
    }

    /// The target root every Cargo call inherited, one line per call.
    pub(super) fn recorded_targets(&self) -> Box<[Box<str>]> {
        recorded_lines(&self.state.join("targets"))
    }

    /// Every process the fake tools started or became.
    ///
    /// A line this reader cannot understand is a failure rather than a skipped
    /// entry. [`super::verdict::assert_no_process_survives_the_row`] states
    /// nothing about a pid it never read, so containment that stopped covering
    /// the tree would read exactly like containment that worked.
    pub(super) fn recorded_pids(&self) -> Box<[u32]> {
        let path = self.state.join("pids");
        recorded_lines(&path)
            .iter()
            .map(|line| {
                line.parse().unwrap_or_else(|error| {
                    panic!(
                        "{} records the process [{line}], which is no pid this row can wait on: \
                         {error}",
                        path.display()
                    )
                })
            })
            .collect()
    }

    /// The archives this row's packaging left in the target root, sorted.
    ///
    /// The target root outlives the staging root the proof removes, which is
    /// what makes the archives a row can still read after the proof has
    /// finished releasing everything it owns.
    pub(super) fn archives(&self) -> Box<[Box<str>]> {
        entries(&self.target.join("package"))
    }

    /// The manifest one packaged archive carries, read from the tree the
    /// packaging built that archive out of.
    pub(super) fn packaged_manifest(&self, name: &str, version: &str) -> Box<str> {
        read_recorded(
            &self
                .state
                .join("pack")
                .join(format!("{name}-{version}"))
                .join("Cargo.toml"),
        )
    }

    /// The generated workspace manifest the proof handed Cargo to resolve the
    /// archive graph from.
    pub(super) fn archive_manifest(&self) -> Box<str> {
        read_recorded(&self.state.join("archive-manifest.toml"))
    }

    /// Forget what the fake tools recorded, so a second run over this root is
    /// read on its own.
    pub(super) fn clear(&self) {
        fs::remove_dir_all(self.state).expect("the recorded operations");
        fs::create_dir_all(self.state).expect("a writable row directory");
    }
}

/// One record file's lines, empty when the fake tools wrote none.
///
/// A missing file is the only reading that means no lines. Every other IO
/// error is a reader that failed, and the rows requiring exactly no operations
/// would pass on one without reading anything at all.
fn recorded_lines(path: &Path) -> Box<[Box<str>]> {
    match fs::read_to_string(path) {
        Ok(recorded) => recorded.lines().map(Box::from).collect(),
        Err(error) if error.kind() == ErrorKind::NotFound => Box::default(),
        Err(error) => panic!("{} could not be read: {error}", path.display()),
    }
}

/// One document the row's fake tools left, which must be there.
///
/// Absence is a failure rather than an empty reading: every caller asks what a
/// finished stage produced, and a stage that produced nothing is the regression
/// those callers exist to catch.
fn read_recorded(path: &Path) -> Box<str> {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} could not be read: {error}", path.display()))
        .into()
}
