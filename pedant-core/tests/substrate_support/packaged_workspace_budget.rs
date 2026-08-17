//! What the tracked packaged-workspace release proof costs, and which stage a
//! caller can ask for.
//!
//! [`crate::packaged_workspace`] reads the structure of that proof; this module
//! reads its price. The two are split for the source-file budget alone, and
//! both compare the script against the tables
//! [`crate::packaged_workspace_claims`] owns.

use crate::packaged_workspace_claims::{
    BUDGET_CONSTANTS, PINNED_TOOLS, REJECTED_STAGE_SELECTIONS, REQUIRED_TOOLS, STAGE_SELECTION,
    assert_contains_all, assert_exactly_once, assert_in_order, function_body,
};

/// The warm release stage's own pair of numbers, as the script spells them.
const WARM_BUDGET_CALL: &str =
    "measure_budget verify \"${WARM_RUNTIME_BUDGET_SECONDS}\" \"${WARM_TARGET_BUDGET_KIB}\"";

/// The cold release stage's own pair.
const COLD_BUDGET_CALL: &str =
    "measure_budget verify \"${COLD_RUNTIME_BUDGET_SECONDS}\" \"${COLD_TARGET_BUDGET_KIB}\"";

/// The tool stage's own pair.
const INSTALL_BUDGET_CALL: &str =
    "measure_budget install \"${INSTALL_RUNTIME_BUDGET_SECONDS}\" \"${INSTALL_TARGET_BUDGET_KIB}\"";

/// The proof states its own cost, fails when it exceeds the budget its warm
/// state selects, and reads that state out of the target root.
pub(crate) fn assert_budget_contract(joined: &str) {
    assert_contains_all(joined, BUDGET_CONSTANTS, "the budget contract");
    assert!(
        joined.contains(REQUIRED_TOOLS),
        "the proof must require exactly [{REQUIRED_TOOLS}]"
    );
    assert_contains_all(
        &function_body(joined, "measure_budget"),
        &[
            "elapsed=",
            "target_growth_kib=",
            "temp_peak_kib",
            "warm_state",
        ],
        "the budget report",
    );
    assert!(
        joined.contains("du -sk"),
        "target growth and owned temporary peak are measured, not estimated"
    );
    assert!(
        function_body(joined, "now_seconds").contains("date +%s"),
        "elapsed time is read through the clock on PATH, not the shell's counter"
    );
    assert_warm_state_is_a_target_fact(joined);
    assert_budget_pair_mapping(joined);
    assert_stage_selection(joined);
}

/// The warm claim is asked of the pinned binaries in the target root, and a
/// warm root is reused rather than rebuilt.
///
/// A file saying the tools are here is a claim about a file. A pruned target, or
/// one copied out of another tree, keeps the claim and loses the tools, and the
/// run that believed it would be held to the warm budget for a quarter hour of
/// work it still has to do. `cargo install` moves its binary out of the build
/// directory, so the durable evidence is the installation root itself — which is
/// why that root lives in the target and carries both revisions in its name.
///
/// That each tool is probed before it is built is
/// [`crate::packaged_workspace::assert_pinned_tool_installation`]'s claim, read
/// over the same installer bodies. What is left here is the other half: the warm
/// reading asks the same question those installers ask.
fn assert_warm_state_is_a_target_fact(joined: &str) {
    assert!(
        joined.contains("tool_root=\"${target_root}/${TOOL_ROOT_NAME}\""),
        "the pinned tool root must outlive the staging root inside the target root"
    );
    assert!(
        !function_body(joined, "cleanup").contains("tool_root"),
        "a proof that removed the pinned tool root would rebuild it every run"
    );
    let warm = function_body(joined, "read_warm_state");
    for tool in PINNED_TOOLS {
        let condition = tool
            .probe
            .strip_prefix("if ")
            .and_then(|probe| probe.strip_suffix("; then"))
            .expect("PinnedTool::probe is spelled as a shell if-condition");
        assert!(
            warm.contains(condition),
            "the warm state must be proved against the installed {}",
            tool.binary
        );
    }
    assert_in_order(
        &function_body(joined, "install_pinned_tools"),
        &["warm) return 0 ;;", "install_semver_checks"],
        "a warm tool root is reused whole rather than rebuilt",
    );
}

/// Warm, cold, and install stages each pass their own exact runtime and target
/// pair to the common budget judge.
fn assert_budget_pair_mapping(joined: &str) {
    let release = function_body(joined, "measure_proof_budget");
    assert_budget_arm(
        &release,
        "\nwarm)",
        "warm",
        WARM_BUDGET_CALL,
        COLD_BUDGET_CALL,
    );
    assert_budget_arm(&release, "\n*)", "cold", COLD_BUDGET_CALL, WARM_BUDGET_CALL);
    assert_exactly_once(
        &function_body(joined, "run_tool_installation"),
        INSTALL_BUDGET_CALL,
        "the install stage's budget pair",
    );
}

/// One arm of the budget selector states its own pair and never the other's.
///
/// The arm is found by its `case` pattern and read to its `;;`, so an author who
/// writes the whole arm on one line states the same contract. Refusing the other
/// stage's pair inside it is the reading that matters: a warm arm holding the
/// cold numbers is the defect, and a fragment check alone would pass it.
fn assert_budget_arm(release: &str, pattern: &str, stage: &str, own: &str, foreign: &str) {
    let arm = release
        .split(";;")
        .find_map(|segment| segment.split_once(pattern).map(|(_, arm)| arm))
        .unwrap_or_else(|| panic!("the budget selector holds no [{pattern}] arm"));
    assert_exactly_once(arm, own, &format!("the {stage} stage's budget pair"));
    assert!(
        !arm.contains(foreign),
        "the {stage} arm also selects the other stage's budget pair"
    );
}

/// The script has two stages, one entry point, and no third answer.
fn assert_stage_selection(joined: &str) {
    assert_contains_all(joined, STAGE_SELECTION, "the stage selection");
    for rejected in REJECTED_STAGE_SELECTIONS {
        assert!(
            !joined.contains(rejected),
            "a stage chosen by [{rejected}] acts on a request it has not finished reading"
        );
    }
    let selection = function_body(joined, "main");
    let installation = function_body(joined, "run_tool_installation");
    for tool in PINNED_TOOLS {
        assert!(
            selection.contains(tool.binary),
            "the entry point must refuse an unknown tool name where it counts the \
             arguments, and [{}] is not named there",
            tool.binary
        );
        assert!(
            !installation.contains(tool.binary),
            "a tool stage that chose between the tools itself would have moved state \
             before it could refuse [{}]",
            tool.binary
        );
    }
    assert!(
        installation.contains("\"$1\""),
        "the tool stage builds the installer it was handed"
    );
    assert!(
        !installation.contains("stage_isolated_source"),
        "the tool stage stages no release"
    );
}
