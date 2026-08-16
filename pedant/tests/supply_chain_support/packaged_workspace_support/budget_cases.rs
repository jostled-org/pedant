//! What the release proof costs, and which budget it is held to.
//!
//! No run this side of a filled disk is over budget, so a stand-in clock and a
//! stand-in sizer report the truth until a row asks otherwise, and
//! [`BUDGET_OVERRUNS`] hands the proof one reading per refusal. Warm state is
//! the other half of that claim: it is a fact about the pinned tool root inside
//! the target, so the only way to observe it is to leave one behind and run the
//! proof again.

use super::row::{Fault, RowRoot};
use super::verdict::{
    REFUSED_STATUS, assert_refusal, assert_row_is_clean, warm_expected_operations,
};
use crate::cargo_classifier_cases::redacted;

/// A target growth no run could reach and no budget could allow, in KiB.
const OVER_BUDGET_KIB: &str = "999999999";

/// A jump past every runtime budget the proof states, in seconds.
const OVER_BUDGET_SECONDS: &str = "99999";

/// One stage cost the budget has to refuse.
struct BudgetOverrun {
    /// What the row makes too expensive, for the assertion message.
    label: &'static str,
    /// The clock jump the fake clock reports, or none.
    jump: &'static str,
    /// The target-root size the fake sizer reports, or none.
    target_kib: &'static str,
    /// The staging-root size the fake sizer reports, or none.
    staging_kib: &'static str,
    /// The fragment of the refusal the proof must print.
    refusal: &'static str,
}

/// Every budget the proof enforces, one row each.
const BUDGET_OVERRUNS: &[BudgetOverrun] = &[
    BudgetOverrun {
        label: "a stage that outran its runtime budget",
        jump: OVER_BUDGET_SECONDS,
        target_kib: "",
        staging_kib: "",
        refusal: "the verify stage took 99999s, over its",
    },
    BudgetOverrun {
        label: "a stage that outgrew its target budget",
        jump: "",
        target_kib: OVER_BUDGET_KIB,
        staging_kib: "",
        refusal: "grew the target root by 999999999KiB, over its",
    },
    BudgetOverrun {
        label: "a stage that outgrew its staging budget",
        jump: "",
        target_kib: "",
        staging_kib: OVER_BUDGET_KIB,
        refusal: "held 999999999KiB of staging, over its",
    },
];

/// The proof states which budget it is held to, and refuses every way a stage
/// can exceed one.
///
/// The three refusals in `measure_budget` guard the claim that this proof costs
/// what it says it costs, and no real run reaches any of them: an inverted
/// comparison or a swapped variable would pass the structural test, all twenty
/// lifecycle rows, and both indexed runs. The clock and the sizer are the two
/// readings those refusals judge, so the rows below supply the readings.
pub(super) fn verify_packaged_workspace_budgets() {
    warm_target_selects_the_warm_budget(&RowRoot::new());
    for overrun in BUDGET_OVERRUNS {
        budget_overrun_is_refused(&RowRoot::new(), overrun);
    }
    tool_stage_overrun_is_refused_against_the_install_budget(&RowRoot::new());
}

/// A second proof over the same target root finds the pinned tool builds and
/// says so.
///
/// The first run installs them into the revision-named root inside the target;
/// the second asks those binaries their version and believes the answer. The
/// row runs the proof twice rather than planting a file, because a file is
/// exactly what the warm claim is no longer allowed to rest on.
fn warm_target_selects_the_warm_budget(root: &RowRoot) {
    let label = "a proof over a target that already holds the pinned tool builds";
    let fault = Fault::None;
    let first = root.run(&fault);
    assert_row_is_clean(
        root,
        "the cold proof before it",
        &first,
        0,
        fault.surviving_tool_builds(),
    );
    root.clear_record();

    let completed = root.run(&fault);

    assert_row_is_clean(root, label, &completed, 0, fault.surviving_tool_builds());
    assert!(
        completed
            .stdout
            .contains("packaged workspace proof: stage=verify state=warm"),
        "{label}: the proof must read its warm state from the target: {}",
        redacted(&completed.transcript())
    );
    assert_eq!(
        root.operations(),
        warm_expected_operations(),
        "{label}: a warm proof must prove the builds it found before reusing them"
    );
}

/// One over-budget stage is refused by name, and still releases its staging.
fn budget_overrun_is_refused(root: &RowRoot, overrun: &BudgetOverrun) {
    let fault = Fault::Overrun {
        jump: overrun.jump,
        target_kib: overrun.target_kib,
        staging_kib: overrun.staging_kib,
    };
    let completed = root.run(&fault);

    assert_row_is_clean(
        root,
        overrun.label,
        &completed,
        REFUSED_STATUS,
        fault.surviving_tool_builds(),
    );
    assert_refusal(overrun.label, &completed, overrun.refusal);
    assert!(
        completed
            .stdout
            .contains("packaged workspace proof: stage=verify state=cold"),
        "{}: the cost has to reach the operator before it is judged: {}",
        overrun.label,
        redacted(&completed.transcript())
    );
}

/// The tool stage is held to the install budget, and refuses an overrun of it.
///
/// The release proof chooses between the warm and cold pairs; the tool stage
/// has a third pair of its own, and it is the pair the two indexed install
/// commands are actually judged against. A stage that reported its cost and
/// then compared it to the wrong ceiling — or to none — would pass every other
/// row here, because no other row runs it.
fn tool_stage_overrun_is_refused_against_the_install_budget(root: &RowRoot) {
    let label = "a tool stage that outran its install budget";
    let fault = Fault::Overrun {
        jump: OVER_BUDGET_SECONDS,
        target_kib: "",
        staging_kib: "",
    };
    let completed = root.run_stage(&fault, &["--install-tools", "release-plz"]);

    assert_row_is_clean(root, label, &completed, REFUSED_STATUS, &["release-plz"]);
    assert_refusal(label, &completed, "the install stage took 99999s, over its");
    assert!(
        completed
            .stdout
            .contains("packaged workspace proof: stage=install state=cold"),
        "{label}: the cost has to reach the operator before it is judged: {}",
        redacted(&completed.transcript())
    );
}
