//! One packaged-workspace row: the root it owns, and the fault it runs under.
//!
//! Every row installs fake Cargo, release-plz, clock, and sizer executables
//! that implement the whole operation protocol and can fail exactly once, in
//! exactly one place, in exactly one way. This module owns that machinery;
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

use super::fixture;
use crate::cargo_classifier_cases::{expanded, repository_root};
use crate::process_guard::{Completed, Run, execute};

/// The tracked proof every row runs.
const PACKAGE_SCRIPT: &str = ".github/scripts/check_packaged_workspace.sh";

/// Every row drives a fixture of eight one-file crates, so a row that overran
/// this budget is broken rather than slow.
const ROW_BUDGET: Duration = Duration::from_secs(120);

/// The ordinary status a failing Cargo operation must keep.
pub(super) const ORDINARY_STATUS: i32 = 3;

/// The pinned binaries the proof installs into the target's tool root, which is
/// also what a warm run asks for its version.
pub(super) const PINNED_BINARIES: &[&str] = &["cargo-semver-checks", "release-plz"];

/// The argument list the release proof takes: none.
const RELEASE_STAGE: &[&str] = &[];

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

impl Fault<'_> {
    /// The operation this fault targets, or none.
    fn operation(&self) -> &str {
        match self {
            Self::None | Self::Graph { .. } | Self::Overrun { .. } => "",
            Self::Ordinary { operation }
            | Self::Infrastructure { operation, .. }
            | Self::Interrupt { operation } => operation,
        }
    }

    /// The mode the fake tools read.
    fn mode(&self) -> &'static str {
        match self {
            Self::None | Self::Graph { .. } | Self::Overrun { .. } => "",
            Self::Ordinary { .. } => "ordinary",
            Self::Infrastructure { .. } => "infrastructure",
            Self::Interrupt { .. } => "interrupt",
        }
    }

    /// The message the failing operation writes, already expanded.
    fn sample(&self) -> Box<str> {
        match self {
            Self::Ordinary { .. } => ORDINARY_SAMPLE.into(),
            Self::Infrastructure { sample, .. } => expanded(sample),
            Self::None | Self::Interrupt { .. } | Self::Graph { .. } | Self::Overrun { .. } => {
                Box::default()
            }
        }
    }

    /// The jq filter the archive metadata is passed through.
    fn mutation(&self) -> &str {
        match self {
            Self::Graph { mutation, .. } => mutation,
            Self::None
            | Self::Ordinary { .. }
            | Self::Infrastructure { .. }
            | Self::Interrupt { .. }
            | Self::Overrun { .. } => "",
        }
    }

    /// The warning the archive metadata call writes to its transcript.
    fn warning(&self) -> &str {
        match self {
            Self::Graph { warning, .. } => warning,
            Self::None
            | Self::Ordinary { .. }
            | Self::Infrastructure { .. }
            | Self::Interrupt { .. }
            | Self::Overrun { .. } => "",
        }
    }

    /// The clock jump and the two sizes the fake clock and sizer report.
    fn overrun(&self) -> (&str, &str, &str) {
        match self {
            Self::Overrun {
                jump,
                target_kib,
                staging_kib,
            } => (jump, target_kib, staging_kib),
            Self::None
            | Self::Ordinary { .. }
            | Self::Infrastructure { .. }
            | Self::Interrupt { .. }
            | Self::Graph { .. } => ("", "", ""),
        }
    }

    /// Which pinned tool builds survive a release-proof row carrying this
    /// fault.
    ///
    /// Every fault but one lands after both installations, and a run that fails
    /// after building the tools leaves them built. Only a fault during the
    /// build leaves the target root with nothing to claim.
    pub(super) fn surviving_tool_builds(&self) -> &'static [&'static str] {
        match self.operation() {
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
        let script: Box<str> = repository_root()
            .join(PACKAGE_SCRIPT)
            .to_string_lossy()
            .into();
        let mut arguments: Vec<&str> = vec![script.as_ref()];
        arguments.extend_from_slice(stage);
        let tmp: Box<str> = self.tmp.to_string_lossy().into();
        let target: Box<str> = self.target.to_string_lossy().into();
        let state: Box<str> = self.state.to_string_lossy().into();
        let staged: Box<str> = self.root.path().join("staged").to_string_lossy().into();
        let bodies: Box<str> = self.tools.join("bodies").to_string_lossy().into();
        let sample = fault.sample();
        let ordinary: Box<str> = ORDINARY_STATUS.to_string().into();
        let (jump, target_kib, staging_kib) = fault.overrun();
        let environment = [
            ("TMPDIR", tmp.as_ref()),
            ("CARGO_TARGET_DIR", target.as_ref()),
            ("PLAN_BASE_SHA", self.base.as_ref()),
            ("PROOF_OUTPUT_DIR", ""),
            ("FAKE_STATE_DIR", state.as_ref()),
            ("FAKE_STAGED_TREE", staged.as_ref()),
            ("FAKE_TOOL_BODIES", bodies.as_ref()),
            ("FAKE_FAULT_OPERATION", fault.operation()),
            ("FAKE_FAULT_MODE", fault.mode()),
            ("FAKE_FAULT_SAMPLE", sample.as_ref()),
            ("FAKE_FAULT_STATUS", ordinary.as_ref()),
            ("FAKE_GRAPH_MUTATION", fault.mutation()),
            ("FAKE_METADATA_WARNING", fault.warning()),
            ("FAKE_DATE_JUMP_SECONDS", jump),
            ("FAKE_DU_TARGET_KIB", target_kib),
            ("FAKE_DU_STAGING_KIB", staging_kib),
        ];
        let mut run = Run::program("bash", &self.repository, &arguments);
        run.path_prefix = Some(&self.tools);
        run.env = &environment;
        run.budget = ROW_BUDGET;
        execute(&run).unwrap_or_else(|failure| panic!("the guard failed: {failure}"))
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
    pub(super) fn recorded_pids(&self) -> Box<[u32]> {
        recorded_lines(&self.state.join("pids"))
            .iter()
            .filter_map(|line| line.parse().ok())
            .collect()
    }

    /// Where one pinned tool is installed: the revision-named root inside the
    /// target, which outlives the staging root the proof throws away.
    pub(super) fn tool_build(&self, binary: &str) -> PathBuf {
        self.target
            .join(".pedant-packaged-workspace-7e38e7a-c9d2ce64.tools")
            .join("bin")
            .join(binary)
    }

    /// Forget what the fake tools recorded, so a second run over this root is
    /// read on its own.
    pub(super) fn clear_record(&self) {
        fs::remove_dir_all(&self.state).expect("the recorded operations");
        fs::create_dir_all(&self.state).expect("a writable row directory");
    }
}

/// One record file's lines, empty when the fake tools wrote none.
fn recorded_lines(path: &Path) -> Box<[Box<str>]> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(Box::from)
        .collect()
}
