//! One packaged-workspace row: the root it owns, and the fault it runs under.
//!
//! Every row installs fake Cargo, release-plz, clock, and sizer executables
//! that implement the whole operation protocol and can fail exactly once, in
//! exactly one place, in exactly one way. This module owns that machinery;
//! [`super::record`] owns the reading of what those tools left,
//! [`super::verdict`] owns what a finished row must show, and the case modules
//! beside it own the claims.
//!
//! Each row owns its root. `TMPDIR`, `CARGO_TARGET_DIR`, the Git fixture, the
//! fake tools, and the recorded operations all live inside it, so a clone the
//! script failed to release shows up as a directory the row left rather than as
//! noise somewhere shared. The supply-chain process guard kills, reaps, drains,
//! and joins every child before a row asserts, and the root is removed when
//! that row's `TempDir` drops.
//!
//! Signatures are stored redacted for the reason
//! [`crate::cargo_classifier_cases`] states, and expanded at the one boundary
//! that hands text to a child.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::TempDir;

use super::fixture::{self, ISOLATED_GIT, NAVIGATION_PACKAGE};
use super::record::Record;
use crate::cargo_classifier_cases::{expanded, repository_root};
use crate::process_guard::{Completed, Run, execute};

/// The tracked proof every row runs.
const PACKAGE_SCRIPT: &str = ".github/scripts/check_packaged_workspace.sh";

/// Every row drives a fixture of eight one-file crates through executables that
/// compile nothing, so a row that overran this budget is broken rather than
/// slow.
///
/// Half the process guard's own default, which is the ceiling a row would
/// otherwise inherit and restate. The most expensive row here drives one
/// installation, thirty-odd fake Cargo calls, and the Git, tar and jq those
/// call, and finishes in under a second; a minute is the same order of headroom
/// the sibling classifier rows keep over their short shell bodies.
const ROW_BUDGET: Duration = Duration::from_secs(60);

/// The ordinary status a failing Cargo operation must keep.
pub(super) const ORDINARY_STATUS: i32 = 3;

/// The pinned binaries the proof installs into the target's tool root, which is
/// also what a warm run asks for its version.
pub(super) const PINNED_BINARIES: &[&str] = &["cargo-semver-checks", "release-plz"];

/// The stage selector the release proof takes: none.
///
/// The repository root is a separate, required argument every row supplies.
pub(super) const RELEASE_STAGE: &[&str] = &[];

/// A near miss the classifier must refuse, so the ordinary row proves the
/// script kept a real failure rather than that no signature was present.
const ORDINARY_SAMPLE: &str = "error: package cache entry is corrupt";

/// How one row's fake tools must behave.
pub(super) enum Fault<'a> {
    /// Every operation succeeds.
    None,
    /// One operation exits with an ordinary status after a near-miss message.
    Ordinary {
        /// The operation that fails.
        operation: &'a str,
    },
    /// One operation exits non-zero with an infrastructure signature.
    Infrastructure {
        /// The operation that fails.
        operation: &'a str,
        /// The redacted signature it writes.
        sample: &'a str,
    },
    /// One operation leaves a live descendant and signals the proof.
    Interrupt {
        /// The operation that signals.
        operation: &'a str,
    },
    /// Every operation succeeds, but the archive metadata describes a graph the
    /// proof has to refuse.
    Graph {
        /// The jq filter that bends that metadata.
        mutation: &'a str,
        /// The warning the metadata call writes to its transcript.
        warning: &'a str,
    },
    /// Every operation succeeds, but the clock or the sizer reports a cost the
    /// budget has to refuse.
    Overrun {
        /// The seconds the clock jumps before the budget is judged.
        jump: &'a str,
        /// The target-root size the sizer reports after the stage.
        target_kib: &'a str,
        /// The staging-root size the sizer reports during the stage.
        staging_kib: &'a str,
    },
}

/// Everything one row's fake tools read from its fault.
///
/// One reading rather than one accessor per field: the values are consumed
/// together at a single call site, and six exhaustive matches over the same six
/// variants can disagree about one of them while each still compiles.
#[derive(Default)]
pub(super) struct Tuning<'a> {
    /// The operation that fails, or none.
    pub(super) operation: &'a str,
    /// The mode the fake tools read.
    mode: &'a str,
    /// The message the failing operation writes, still redacted.
    sample: &'a str,
    /// The jq filter the archive metadata is passed through.
    mutation: &'a str,
    /// The warning the archive metadata call writes to its transcript.
    warning: &'a str,
    /// The seconds the clock jumps before the budget is judged.
    jump: &'a str,
    /// The target-root size the sizer reports after the stage.
    target_kib: &'a str,
    /// The staging-root size the sizer reports during the stage.
    staging_kib: &'a str,
}

impl Fault<'_> {
    /// How this fault tunes the fake tools, read once.
    pub(super) fn tuning(&self) -> Tuning<'_> {
        match self {
            Self::None => Tuning::default(),
            Self::Ordinary { operation } => Tuning {
                operation,
                mode: "ordinary",
                sample: ORDINARY_SAMPLE,
                ..Tuning::default()
            },
            Self::Infrastructure { operation, sample } => Tuning {
                operation,
                mode: "infrastructure",
                sample,
                ..Tuning::default()
            },
            Self::Interrupt { operation } => Tuning {
                operation,
                mode: "interrupt",
                ..Tuning::default()
            },
            Self::Graph { mutation, warning } => Tuning {
                mutation,
                warning,
                ..Tuning::default()
            },
            Self::Overrun {
                jump,
                target_kib,
                staging_kib,
            } => Tuning {
                jump,
                target_kib,
                staging_kib,
                ..Tuning::default()
            },
        }
    }

    /// Which pinned tool builds survive a release-proof row carrying this
    /// fault.
    ///
    /// Every fault but one lands after both installations, and a run that fails
    /// after building the tools leaves them built. Only a fault during the
    /// build leaves the target root with nothing to claim.
    pub(super) fn surviving_tool_builds(&self) -> &'static [&'static str] {
        match self.tuning().operation {
            "install" => &[],
            _ => PINNED_BINARIES,
        }
    }
}

/// One row's own filesystem root: its temporary directory, its sentinel target
/// root, its Git fixture, its fake tools, and the record those tools keep.
/// Dropping it removes all five.
pub(super) struct RowRoot {
    root: TempDir,
    /// The temporary root the proof's staging must be gone from.
    pub(super) tmp: PathBuf,
    /// The target root every Cargo call must inherit.
    pub(super) target: PathBuf,
    /// The caller's checkout, which the proof clones and never writes into.
    pub(super) repository: PathBuf,
    tools: PathBuf,
    state: PathBuf,
    /// The commit the proof is asked to stage onto.
    pub(super) base: Box<str>,
}

impl RowRoot {
    /// A root holding a committed eight-package fixture, one uncommitted
    /// final-tree edit, one untracked file, and the fake tools that stand in
    /// for Cargo and release-plz.
    pub(super) fn new() -> Self {
        let root = tempfile::tempdir().expect("a temporary row root");
        let tmp = root.path().join("tmp");
        let target = root.path().join("target");
        let repository = root.path().join("repository");
        let tools = root.path().join("tools");
        let state = root.path().join("state");
        for directory in [&tmp, &target, &repository, &tools, &state] {
            fs::create_dir_all(directory).expect("a writable row directory");
        }
        let base = fixture::build_repository(&repository);
        fixture::write_staged_tree(&root.path().join("staged"));
        fixture::write_fake_tools(&tools);
        Self {
            root,
            tmp,
            target,
            repository,
            tools,
            state,
            base,
        }
    }

    /// Run the release proof against this row's fixture and fake tools.
    pub(super) fn run(&self, fault: &Fault<'_>) -> Completed {
        self.run_stage(fault, RELEASE_STAGE)
    }

    /// Run the tracked proof with one exact argument list, which is what
    /// selects the stage under proof.
    pub(super) fn run_stage(&self, fault: &Fault<'_>, stage: &[&str]) -> Completed {
        self.run_stage_with_repository_root(fault, &self.repository, stage)
    }

    /// Run the tracked proof without its required repository-root argument.
    pub(super) fn run_without_repository_root(&self, fault: &Fault<'_>) -> Completed {
        self.run_arguments(fault, None, RELEASE_STAGE)
    }

    /// Run the tracked proof with one explicit repository-root candidate.
    pub(super) fn run_stage_with_repository_root(
        &self,
        fault: &Fault<'_>,
        repository_root: &Path,
        stage: &[&str],
    ) -> Completed {
        self.run_arguments(fault, Some(repository_root), stage)
    }

    /// An existing file, which cannot be a repository root.
    pub(super) fn repository_root_file(&self) -> PathBuf {
        let path = self.root.path().join("repository-root-file");
        fs::write(&path, "not a directory\n").expect("a repository-root file fixture");
        path
    }

    /// An existing directory that is not inside a Git working tree.
    ///
    /// The row root holds no `.git` of its own, and [`Self::git_ceiling`] stops
    /// the proof's own discovery from climbing out of it, so this is a non-Git
    /// root under every harness rather than only under a `TMPDIR` that happens
    /// to sit outside a checkout.
    pub(super) fn non_git_root(&self) -> &Path {
        self.root.path()
    }

    /// The directory the proof's Git discovery must not climb into.
    ///
    /// `ISOLATED_GIT` neutralizes Git *configuration*; it says nothing about
    /// upward repository *discovery*. Under a harness whose `TMPDIR` sits
    /// inside a checkout, the row root discovers that checkout's toplevel, and
    /// the non-Git row is refused with "does not match its Git toplevel"
    /// instead — a red row reporting a claim nobody made. The ceiling is the
    /// row root's parent rather than the root itself, because the root must
    /// stay searchable: that is where a row expects Git to find nothing.
    ///
    /// Git resolves symlinks in this list before comparing, which is what keeps
    /// it true on a host whose temporary root is reached through one.
    fn git_ceiling(&self) -> Box<str> {
        self.root
            .path()
            .parent()
            .expect("a temporary row root sits inside a parent directory")
            .to_string_lossy()
            .into()
    }

    /// A directory inside the fixture checkout, but not its Git toplevel.
    pub(super) fn nested_repository_root(&self) -> PathBuf {
        self.repository.join(NAVIGATION_PACKAGE)
    }

    /// Run one row from outside the repository it explicitly names.
    fn run_arguments(
        &self,
        fault: &Fault<'_>,
        requested_repository_root: Option<&Path>,
        stage: &[&str],
    ) -> Completed {
        let script: Box<str> = repository_root()
            .join(PACKAGE_SCRIPT)
            .to_string_lossy()
            .into();
        let mut arguments: Vec<&str> = vec![script.as_ref()];
        let repository_argument: Option<Box<str>> = requested_repository_root
            .map(|path| path.to_string_lossy().into_owned().into_boxed_str());
        if let Some(argument) = repository_argument.as_deref() {
            arguments.push(argument);
        }
        arguments.extend_from_slice(stage);
        let arguments = arguments.into_boxed_slice();
        let tmp: Box<str> = self.tmp.to_string_lossy().into();
        let target: Box<str> = self.target.to_string_lossy().into();
        let state: Box<str> = self.state.to_string_lossy().into();
        let staged: Box<str> = self.root.path().join("staged").to_string_lossy().into();
        let bodies: Box<str> = self.tools.join("bodies").to_string_lossy().into();
        let ceiling = self.git_ceiling();
        let tuning = fault.tuning();
        let sample = expanded(tuning.sample);
        let ordinary: Box<str> = ORDINARY_STATUS.to_string().into();
        let mut environment: Vec<(&str, &str)> = vec![
            ("TMPDIR", tmp.as_ref()),
            ("CARGO_TARGET_DIR", target.as_ref()),
            ("PLAN_BASE_SHA", self.base.as_ref()),
            ("PROOF_OUTPUT_DIR", ""),
            ("FAKE_STATE_DIR", state.as_ref()),
            ("FAKE_STAGED_TREE", staged.as_ref()),
            ("FAKE_TOOL_BODIES", bodies.as_ref()),
            ("FAKE_FAULT_OPERATION", tuning.operation),
            ("FAKE_FAULT_MODE", tuning.mode),
            ("FAKE_FAULT_SAMPLE", sample.as_ref()),
            ("FAKE_FAULT_STATUS", ordinary.as_ref()),
            ("FAKE_GRAPH_MUTATION", tuning.mutation),
            ("FAKE_METADATA_WARNING", tuning.warning),
            ("FAKE_DATE_JUMP_SECONDS", tuning.jump),
            ("FAKE_DU_TARGET_KIB", tuning.target_kib),
            ("FAKE_DU_STAGING_KIB", tuning.staging_kib),
        ];
        environment.extend_from_slice(ISOLATED_GIT);
        environment.push(("GIT_CEILING_DIRECTORIES", ceiling.as_ref()));
        let environment = environment.into_boxed_slice();
        let mut run = Run::program("bash", self.root.path(), &arguments);
        run.path_prefix = Some(&self.tools);
        run.env = &environment;
        run.budget = ROW_BUDGET;
        execute(&run).unwrap_or_else(|failure| panic!("the guard failed: {failure}"))
    }

    /// Where one pinned tool is installed: the revision-named root inside the
    /// target, which outlives the staging root the proof throws away.
    pub(super) fn tool_build(&self, binary: &str) -> PathBuf {
        self.target
            .join(".pedant-packaged-workspace-7e38e7a-c9d2ce64.tools")
            .join("bin")
            .join(binary)
    }

    /// What this row's fake tools recorded, read back.
    ///
    /// One accessor rather than seven readers on the root: a root is built once
    /// and handed to a run, and a record is asked a question after that run has
    /// finished. [`super::record`] owns the reading; the two directories it
    /// reads stay here, because the row is what hands both to its children.
    pub(super) fn record(&self) -> Record<'_> {
        Record::of(&self.state, &self.target)
    }
}
