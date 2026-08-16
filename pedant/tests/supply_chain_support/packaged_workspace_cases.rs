//! Lifecycle contract of the tracked packaged-workspace release proof.
//!
//! `.github/scripts/check_packaged_workspace.sh` clones the repository, builds
//! two pinned tools, lets release-plz stage eight versions, packages every
//! member, and compiles the extracted archives against each other. The indexed
//! proof runs that against the real registry and the real Cargo; nothing about
//! it is cheap, and nothing about it is deterministic enough to state what
//! happens when a package step exits 3, when a volume fills mid-install, or
//! when the operator presses Ctrl-C.
//!
//! That is what this module owns. Every row installs fake Cargo and fake
//! release-plz executables that implement the whole operation protocol and can
//! fail exactly once, in exactly one place, in exactly one way. What the rows
//! require is the part an operator depends on: the script's own status, the
//! order it drove the tools in, the target root every Cargo call inherited, a
//! dead process tree, and a temporary directory holding nothing at all.
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

use pedant_process_guard::wait_until_gone;
use tempfile::TempDir;

use crate::cargo_classifier_cases::{
    INFRASTRUCTURE_MATCHES, entries, expanded, redacted, repository_root,
};
use crate::process_guard::{Completed, Run, execute};

/// The repository, staged tree, and fake tools every row is given. Same
/// `#[path]` reason as the modules `supply_chain.rs` declares.
#[path = "packaged_workspace_support/fixture.rs"]
mod fixture;

use fixture::RELEASE_ORDER;

/// The tracked proof every row runs.
const PACKAGE_SCRIPT: &str = ".github/scripts/check_packaged_workspace.sh";

/// Every row drives a fixture of eight one-file crates, so a row that overran
/// this budget is broken rather than slow.
const ROW_BUDGET: Duration = Duration::from_secs(120);

/// How long a killed process tree has to disappear.
const REAP_BUDGET: Duration = Duration::from_secs(30);

/// The ordinary status a failing Cargo operation must keep.
const ORDINARY_STATUS: i32 = 3;

/// The status a classified infrastructure transcript becomes.
const INFRASTRUCTURE_STATUS: i32 = 75;

/// The status a proof that handled TERM must leave with.
const SIGNALLED_STATUS: i32 = 143;

/// A near miss the classifier must refuse, so the ordinary row proves the
/// script kept a real failure rather than that no signature was present.
const ORDINARY_SAMPLE: &str = "error: package cache entry is corrupt";

/// Which Cargo operation carries each signature, so classification is proved at
/// every stage the script runs rather than only at the cheapest one.
const INFRASTRUCTURE_OPERATIONS: &[&str] = &[
    "install",
    "package",
    "metadata",
    "generate-lockfile",
    "check",
    "install",
    "package",
    "metadata",
    "check",
];

/// How one row's fake tools must behave.
enum Fault<'a> {
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
}

impl Fault<'_> {
    /// The operation this fault targets, or none.
    fn operation(&self) -> &str {
        match self {
            Self::None => "",
            Self::Ordinary { operation }
            | Self::Infrastructure { operation, .. }
            | Self::Interrupt { operation } => operation,
        }
    }

    /// The mode the fake tools read.
    fn mode(&self) -> &'static str {
        match self {
            Self::None => "",
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
            Self::None | Self::Interrupt { .. } => Box::default(),
        }
    }
}

/// The packaged-workspace proof keeps an ordinary failure, reclassifies every
/// infrastructure signature, honours TERM, and leaves nothing behind on any of
/// them.
#[test]
fn packaged_workspace_cleanup_is_bounded_on_success_failure_infrastructure_and_interrupt() {
    successful_proof_drives_every_operation_in_order(&RowRoot::new());
    ordinary_failure_keeps_its_status(&RowRoot::new());
    assert_eq!(
        INFRASTRUCTURE_OPERATIONS.len(),
        INFRASTRUCTURE_MATCHES.len(),
        "every classifier signature must still have a row"
    );
    for (sample, operation) in INFRASTRUCTURE_MATCHES
        .iter()
        .copied()
        .zip(INFRASTRUCTURE_OPERATIONS.iter().copied())
    {
        infrastructure_signature_is_reclassified(&RowRoot::new(), sample, operation);
    }
    signalled_proof_leaves_with_its_signal(&RowRoot::new());
}

/// A clean run installs both pinned tools, proves their versions, stages the
/// release, packages all eight members, and compiles the archive workspace — in
/// that order, and with the inherited target root on every Cargo call.
fn successful_proof_drives_every_operation_in_order(root: &RowRoot) {
    let label = "a clean packaged-workspace proof";
    let completed = root.run(&Fault::None);

    assert_row_is_clean(root, label, &completed, 0);
    assert_eq!(
        root.operations(),
        expected_operations(),
        "{label}: the proof drove the tools in the wrong order"
    );
    assert!(
        completed
            .stdout
            .contains("packaged workspace proof: state=cold"),
        "{label}: the proof must state its own cost: {}",
        redacted(&completed.transcript())
    );
    assert!(
        root.warm_marker().is_file(),
        "{label}: a successful cold proof records its warm marker"
    );
}

/// A Cargo operation that fails for an ordinary reason keeps its exact status,
/// and the proof still releases everything it owns.
fn ordinary_failure_keeps_its_status(root: &RowRoot) {
    let label = "an ordinary packaging failure";
    let completed = root.run(&Fault::Ordinary {
        operation: "package",
    });

    assert_row_is_clean(root, label, &completed, ORDINARY_STATUS);
    assert!(
        !root.warm_marker().exists(),
        "{label}: a failed proof must not claim a warm target"
    );
}

/// Every infrastructure signature leaves through 75, whichever operation wrote
/// it, and takes the staging root with it.
fn infrastructure_signature_is_reclassified(root: &RowRoot, sample: &str, operation: &str) {
    let label: Box<str> = format!("an unavailable machine during {operation}").into();
    let completed = root.run(&Fault::Infrastructure { operation, sample });

    assert_row_is_clean(root, &label, &completed, INFRASTRUCTURE_STATUS);
    assert!(
        !root.warm_marker().exists(),
        "{label}: an unavailable machine must not claim a warm target"
    );
}

/// A proof that receives TERM leaves with the signal's status, releases its
/// staging root, and leaves no descendant of the tool it was running.
fn signalled_proof_leaves_with_its_signal(root: &RowRoot) {
    let label = "an interrupted packaged-workspace proof";
    let completed = root.run(&Fault::Interrupt {
        operation: "install",
    });

    assert_row_is_clean(root, label, &completed, SIGNALLED_STATUS);
    assert!(
        !root.warm_marker().exists(),
        "{label}: an interrupted proof must not claim a warm target"
    );
}

/// What every row requires however it ended: the child's own exit, the stated
/// status, a dead process tree, the inherited target root on every Cargo call,
/// and an empty temporary root.
fn assert_row_is_clean(root: &RowRoot, label: &str, completed: &Completed, code: i32) {
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
    for pid in root.recorded_pids().iter().copied() {
        assert!(
            wait_until_gone(pid, REAP_BUDGET),
            "{label}: the tool process {pid} outlived the proof"
        );
    }
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
    assert_eq!(
        entries(&root.tmp),
        Box::default(),
        "{label}: the proof left staging behind"
    );
}

/// The complete operation sequence a clean proof drives, derived from the
/// release order rather than written out twice.
fn expected_operations() -> Box<[Box<str>]> {
    let mut expected: Vec<Box<str>> = vec![
        "install cargo-semver-checks".into(),
        "install release-plz".into(),
        "version cargo-semver-checks".into(),
        "version release-plz".into(),
        "update release-plz semver-checks-present".into(),
        "metadata staged".into(),
    ];
    for name in RELEASE_ORDER {
        expected.push(format!("package {name}").into());
    }
    for name in RELEASE_ORDER {
        expected.push(format!("metadata extracted {name}").into());
    }
    expected.push("generate-lockfile".into());
    expected.push("metadata archive".into());
    expected.push("check".into());
    expected.into_boxed_slice()
}

/// One row's own filesystem root: its temporary directory, its sentinel target
/// root, its Git fixture, its fake tools, and the record those tools keep.
/// Dropping it removes all five.
struct RowRoot {
    root: TempDir,
    tmp: PathBuf,
    target: PathBuf,
    repository: PathBuf,
    tools: PathBuf,
    state: PathBuf,
    base: Box<str>,
}

impl RowRoot {
    /// A root holding a committed eight-package fixture, one uncommitted
    /// final-tree edit, one untracked file, and the fake tools that stand in
    /// for Cargo and release-plz.
    fn new() -> Self {
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

    /// Run the tracked proof against this row's fixture and fake tools.
    fn run(&self, fault: &Fault<'_>) -> Completed {
        let script: Box<str> = repository_root()
            .join(PACKAGE_SCRIPT)
            .to_string_lossy()
            .into();
        let arguments = [script.as_ref()];
        let tmp: Box<str> = self.tmp.to_string_lossy().into();
        let target: Box<str> = self.target.to_string_lossy().into();
        let state: Box<str> = self.state.to_string_lossy().into();
        let staged: Box<str> = self.root.path().join("staged").to_string_lossy().into();
        let bodies: Box<str> = self.tools.join("bodies").to_string_lossy().into();
        let sample = fault.sample();
        let ordinary: Box<str> = ORDINARY_STATUS.to_string().into();
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
        ];
        let mut run = Run::program("bash", &self.repository, &arguments);
        run.path_prefix = Some(&self.tools);
        run.env = &environment;
        run.budget = ROW_BUDGET;
        execute(&run).unwrap_or_else(|failure| panic!("the guard failed: {failure}"))
    }

    /// Everything the fake tools recorded doing, in order.
    fn operations(&self) -> Box<[Box<str>]> {
        recorded_lines(&self.state.join("operations"))
    }

    /// The target root every Cargo call inherited, one line per call.
    fn recorded_targets(&self) -> Box<[Box<str>]> {
        recorded_lines(&self.state.join("targets"))
    }

    /// Every process the fake tools started or became.
    fn recorded_pids(&self) -> Box<[u32]> {
        recorded_lines(&self.state.join("pids"))
            .iter()
            .filter_map(|line| line.parse().ok())
            .collect()
    }

    /// The warm marker a successful cold proof leaves in the target root.
    fn warm_marker(&self) -> PathBuf {
        self.target
            .join(".pedant-packaged-workspace-7e38e7a-c9d2ce64.warm")
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
