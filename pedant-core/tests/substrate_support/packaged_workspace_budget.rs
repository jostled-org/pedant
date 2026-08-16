//! What the tracked packaged-workspace release proof costs, and which stage a
//! caller can ask for.
//!
//! [`crate::packaged_workspace`] reads the structure of that proof; this module
//! reads its price. The two are split for the source-file budget alone, and
//! both compare the script against the tables
//! [`crate::packaged_workspace_claims`] owns.

use crate::packaged_workspace_claims::{
    BUDGET_CONSTANTS, PINNED_TOOLS, REJECTED_STAGE_SELECTIONS, REQUIRED_TOOLS, STAGE_SELECTION,
};
use crate::release_workflow::{function_body, offset_of};

/// The proof states its own cost, fails when it exceeds the budget its warm
/// state selects, and reads that state out of the target root.
pub(crate) fn assert_budget_contract(joined: &str) {
    for constant in BUDGET_CONSTANTS {
        assert!(
            joined.contains(constant),
            "the budget contract is missing [{constant}]"
        );
    }
    assert!(
        joined.contains(REQUIRED_TOOLS),
        "the proof must require exactly [{REQUIRED_TOOLS}]"
    );
    let body = function_body(joined, "measure_budget");
    for fragment in [
        "elapsed=",
        "target_growth_kib=",
        "temp_peak_kib",
        "warm_state",
    ] {
        assert!(
            body.contains(fragment),
            "the budget report omits [{fragment}]"
        );
    }
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
        assert!(
            warm.contains(
                tool.probe
                    .trim_start_matches("if ")
                    .trim_end_matches("; then")
            ),
            "the warm state must be proved against the installed {}",
            tool.binary
        );
        let installer = function_body(joined, tool.installer);
        assert!(
            offset_of(&installer, tool.probe) < offset_of(&installer, tool.installation),
            "{} is asked for its version before it is rebuilt",
            tool.binary
        );
    }
    assert!(
        offset_of(
            &function_body(joined, "install_pinned_tools"),
            "warm) return 0 ;;"
        ) < offset_of(
            &function_body(joined, "install_pinned_tools"),
            "install_semver_checks"
        ),
        "a warm tool root is reused whole rather than rebuilt"
    );
}

/// Warm, cold, and install stages each pass their own exact runtime and target
/// pair to the common budget judge.
fn assert_budget_pair_mapping(joined: &str) {
    let release = function_body(joined, "measure_proof_budget");
    assert_exact_budget_call(
        &release,
        "warm",
        "warm)\nmeasure_budget verify \"${WARM_RUNTIME_BUDGET_SECONDS}\" \"${WARM_TARGET_BUDGET_KIB}\"",
    );
    assert_exact_budget_call(
        &release,
        "cold",
        "*)\nmeasure_budget verify \"${COLD_RUNTIME_BUDGET_SECONDS}\" \"${COLD_TARGET_BUDGET_KIB}\"",
    );
    assert_exact_budget_call(
        &function_body(joined, "run_tool_installation"),
        "install",
        "measure_budget install \"${INSTALL_RUNTIME_BUDGET_SECONDS}\" \"${INSTALL_TARGET_BUDGET_KIB}\"",
    );
}

/// One stage-to-budget relation must occur exactly once.
fn assert_exact_budget_call(body: &str, stage: &str, call: &str) {
    assert_eq!(
        body.matches(call).count(),
        1,
        "the {stage} stage must select exactly its own runtime and target budget pair [{call}]"
    );
}

/// The script has two stages, one entry point, and no third answer.
fn assert_stage_selection(joined: &str) {
    for fragment in STAGE_SELECTION {
        assert!(
            joined.contains(fragment),
            "the stage selection is missing [{fragment}]"
        );
    }
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
