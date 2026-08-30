//! Every `--exact` filter the tracked CI workflow runs, and how one is read.
//!
//! The table is written down and the workflow is parsed; the case compares the
//! two. Written down for the reason every inventory here is: a set taken from
//! the workflow agrees with whatever the workflow says, and the whole hazard is
//! a workflow whose command stopped naming a test that exists.

/// One `--exact` invocation, as a job writes it and as the workspace answers it.
pub(crate) struct ExactFilter {
    /// The package the run line pins.
    pub(crate) package: &'static str,
    /// The integration executable the run line pins.
    pub(crate) target: &'static str,
    /// The whole libtest name the run line passes before `-- --exact`.
    pub(crate) filter: &'static str,
    /// What the run line asks for beyond the package's default features. Part
    /// of the identity, not a detail: a predicate is only registered under the
    /// profile that compiles it, and a job that dropped a `--features` would go
    /// on running a command that selected nothing.
    pub(crate) features: &'static [&'static str],
    /// The file the model says declares that predicate, repository-relative.
    pub(crate) owner: &'static str,
}

impl ExactFilter {
    /// The run line this row says the workflow states.
    pub(crate) fn stated_run(&self) -> ExactRun {
        ExactRun {
            package: self.package.into(),
            target: self.target.into(),
            filter: self.filter.into(),
            features: self.features.iter().map(|it| Box::from(*it)).collect(),
        }
    }
}

/// Every filter the tracked workflow runs exactly, by identity.
///
/// Six rows for seven run lines: the two hosted jobs run the platform predicate
/// each, and one identity selecting the same test from two jobs is one claim
/// about the workspace. Which jobs state which line is the receipt classifier's
/// subject, and it holds each requirement to the job that owns it.
pub(crate) const WORKFLOW_EXACT_FILTERS: &[ExactFilter] = &[
    ExactFilter {
        package: "pedant",
        target: "supply_chain",
        filter: "snapshot_capability_projection_reuses_stored_file_ir",
        features: &["resolution-test-support"],
        owner: "pedant/tests/supply_chain.rs",
    },
    ExactFilter {
        package: "pedant",
        target: "supply_chain",
        filter: "supply_chain_process_guard_reaps_descendants_on_success_timeout_and_early_error",
        features: &[],
        owner: "pedant/tests/supply_chain.rs",
    },
    ExactFilter {
        package: "pedant-mcp",
        target: "integration",
        filter: "relative_completion_paths_are_anchored_to_workspace_root",
        features: &["completion-proof-support"],
        owner: "pedant-mcp/tests/integration.rs",
    },
    ExactFilter {
        package: "pedant-mcp",
        target: "integration",
        filter: "mcp_stdio_guard_reaps_descendants_on_success_timeout_and_early_error",
        features: &[],
        owner: "pedant-mcp/tests/integration.rs",
    },
    ExactFilter {
        package: "pedant-snippet",
        target: "interfaces",
        filter: "journeys::platform::code_intelligence_platform_process_contract_is_exact",
        features: &[],
        owner: "pedant-snippet/tests/interfaces_support/journeys/platform.rs",
    },
    ExactFilter {
        package: "pedant-snippet",
        target: "interfaces",
        filter: "live::transactions::live_index_create_modify_remove_and_rename_publish_atomic_states",
        features: &[],
        owner: "pedant-snippet/tests/interfaces_support/live/transactions.rs",
    },
];

/// The one conditional a hosted filter's module path crosses, and the package
/// whose default features have to hold it open.
///
/// Both hosted jobs run the default profile, so a predicate behind a default-off
/// feature is exactly as unselectable as one whose module was renamed — and
/// reports the same success.
pub(crate) const PROFILE_GATE: (&str, &str) = (
    "pedant-snippet",
    "pedant-snippet/tests/interfaces_support/profile_gate.rs",
);

/// The prefix of a workflow step that runs one cargo test command.
const RUN_PREFIX: &str = "- run: cargo test";

/// What separates a cargo invocation from the arguments libtest reads.
const HARNESS_SEPARATOR: &str = " -- ";

/// The libtest argument that makes a filter a whole-name match.
const EXACT: &str = "--exact";

/// The flag that would take a run line off the default feature profile.
const NO_DEFAULT_FEATURES: &str = "--no-default-features";

/// One parsed `--exact` run line.
///
/// Every field is settled when the row is built and read only through the
/// ordering that compares two of them, so none owns a buffer it can grow.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) struct ExactRun {
    pub(crate) package: Box<str>,
    pub(crate) target: Box<str>,
    pub(crate) filter: Box<str>,
    pub(crate) features: Box<[Box<str>]>,
}

/// Every `--exact` invocation the workflow text states, in file order.
///
/// A line this cannot read is an error rather than a skipped row. The claim is
/// about every exact filter the workflow runs, and a parser that quietly
/// dropped the one it did not recognize would make that claim about the rest.
///
/// The split on the harness separator happens once, in the stage that selects
/// the line, and the halves are handed on. Splitting again in the parser meant
/// every surviving line was cut twice and the parser carried an arm for a shape
/// the selection had already refused.
pub(crate) fn exact_runs(workflow: &str) -> Result<Box<[ExactRun]>, String> {
    workflow
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(RUN_PREFIX))
        .filter_map(|line| {
            let (invocation, harness) = line.split_once(HARNESS_SEPARATOR)?;
            harness.contains(EXACT).then_some((line, invocation))
        })
        .map(|(line, invocation)| parse_exact_run(line, invocation))
        .collect()
}

fn parse_exact_run(line: &str, invocation: &str) -> Result<ExactRun, String> {
    let words: Box<[&str]> = invocation.split_whitespace().collect();
    let package = argument_after(&words, "-p")
        .ok_or_else(|| format!("{line} pins no package, so its filter names no one target"))?;
    let target = argument_after(&words, "--test")
        .ok_or_else(|| format!("{line} pins no test target, so its filter names no one target"))?;
    let filter = words
        .last()
        .copied()
        .filter(|last| !last.starts_with('-'))
        .ok_or_else(|| format!("{line} ends in a flag rather than a filter"))?;
    match words.contains(&NO_DEFAULT_FEATURES) {
        true => Err(format!(
            "{line} leaves the default profile; the registration model reads default features only"
        )),
        false => Ok(ExactRun {
            package: package.into(),
            target: target.into(),
            filter: filter.into(),
            features: selected_features(&words),
        }),
    }
}

/// What one run line asks for beyond the package's defaults.
fn selected_features(words: &[&str]) -> Box<[Box<str>]> {
    argument_after(words, "--features")
        .unwrap_or_default()
        .split(',')
        .filter(|feature| !feature.is_empty())
        .map(Box::from)
        .collect()
}

/// The word one flag takes, when the flag is stated and something follows it.
fn argument_after<'read>(words: &[&'read str], flag: &str) -> Option<&'read str> {
    let position = words.iter().position(|word| *word == flag)?;
    words.get(position + 1).copied()
}
