//! What the release proof costs, and which budget it is held to.
//!
//! No run this side of a filled disk is over budget, so a stand-in clock and a
//! stand-in sizer report the truth until a row asks otherwise, and
//! [`BUDGET_OVERRUNS`] hands the proof one reading per refusal. Warm state is
//! the other half of that claim: it is a fact about the pinned tool root inside
//! the target, so the only way to observe it is to leave one behind and run the
//! proof again.

use super::row::{Fault, PINNED_BINARIES, RELEASE_STAGE, RowRoot};
use super::verdict::{
    REFUSED_STATUS, assert_refusal, assert_row_is_clean, assert_stated_cost,
    assert_stated_cost_shape, warm_expected_operations, warm_the_tool_root,
};

/// A target growth no run could reach and no budget could allow, in KiB.
const OVER_BUDGET_KIB: &str = "999999999";

/// A jump past every runtime budget the proof states, in seconds.
const OVER_BUDGET_SECONDS: &str = "99999";

/// The one tool the install-budget rows name, and the stage that names it.
const INSTALL_TOOL: &str = "release-plz";
const INSTALL_STAGE: &[&str] = &["--install-tools", INSTALL_TOOL];

/// The stage and warm state each group of rows must find on the stated cost
/// line, so a proof that reported one stage's cost under the other's heading is
/// a failure rather than a passing row.
const COLD_VERIFY: (&str, &str) = ("verify", "cold");
const WARM_VERIFY: (&str, &str) = ("verify", "warm");
const COLD_INSTALL: (&str, &str) = ("install", "cold");

/// How many refusals `measure_budget` states, so a table that lost a row is a
/// failure rather than a shorter loop.
///
/// Three for the release proof — runtime, target growth, owned staging — and
/// two each for the warm and install pairs, which are two other ceilings over
/// the same runtime and target readings.
const BUDGET_REFUSALS: usize = 3;
const WARM_BUDGET_REFUSALS: usize = 2;
const INSTALL_BUDGET_REFUSALS: usize = 2;

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
    /// The reading the proof must state, exactly as its cost line spells it.
    ///
    /// Determined rather than observed: the fake clock pins the stage's first
    /// reading so the elapsed seconds are the jump this row asked for, and the
    /// fake sizer reports nothing for the target's first reading so the growth
    /// is the size this row asked for.
    cost: &'static str,
    /// The fragment of the refusal the proof must print.
    refusal: &'static str,
}

impl BudgetOverrun {
    /// The reading this row hands the fake clock and the fake sizer.
    fn fault(&self) -> Fault<'_> {
        Fault::Overrun {
            jump: self.jump,
            target_kib: self.target_kib,
            staging_kib: self.staging_kib,
        }
    }
}

/// Every budget the proof enforces, one row each.
const BUDGET_OVERRUNS: &[BudgetOverrun] = &[
    BudgetOverrun {
        label: "a stage that outran its runtime budget",
        jump: OVER_BUDGET_SECONDS,
        target_kib: "",
        staging_kib: "",
        cost: "elapsed=99999s",
        refusal: "the verify stage took 99999s, over its 2100s budget",
    },
    BudgetOverrun {
        label: "a stage that outgrew its target budget",
        jump: "",
        target_kib: OVER_BUDGET_KIB,
        staging_kib: "",
        cost: "target_growth=999999999KiB",
        refusal: "grew the target root by 999999999KiB, over its 5242880KiB budget",
    },
    BudgetOverrun {
        label: "a stage that outgrew its staging budget",
        jump: "",
        target_kib: "",
        staging_kib: OVER_BUDGET_KIB,
        cost: "owned_temp_peak=999999999KiB",
        refusal: "held 999999999KiB of staging, over its 1048576KiB budget",
    },
];

/// The warm runtime and target pairs, each exercised after the pinned tools are
/// planted in the target root.
const WARM_BUDGET_OVERRUNS: &[BudgetOverrun] = &[
    BudgetOverrun {
        label: "a warm stage that outran its runtime budget",
        jump: OVER_BUDGET_SECONDS,
        target_kib: "",
        staging_kib: "",
        cost: "elapsed=99999s",
        refusal: "the verify stage took 99999s, over its 600s budget",
    },
    BudgetOverrun {
        label: "a warm stage that outgrew its target budget",
        jump: "",
        target_kib: OVER_BUDGET_KIB,
        staging_kib: "",
        cost: "target_growth=999999999KiB",
        refusal: "grew the target root by 999999999KiB, over its 2097152KiB budget",
    },
];

/// The tool-install runtime and target pairs.
///
/// The release proof chooses between the warm and cold pairs; the tool stage
/// has a third pair of its own, and it is the pair the two indexed install
/// commands are actually judged against. A stage that reported its cost and
/// then compared it to the wrong ceiling — or to none — would pass every other
/// row here, because no other row runs it.
const INSTALL_BUDGET_OVERRUNS: &[BudgetOverrun] = &[
    BudgetOverrun {
        label: "a tool stage that outran its install budget",
        jump: OVER_BUDGET_SECONDS,
        target_kib: "",
        staging_kib: "",
        cost: "elapsed=99999s",
        refusal: "the install stage took 99999s, over its 1100s budget",
    },
    BudgetOverrun {
        label: "a tool stage that outgrew its target budget",
        jump: "",
        target_kib: OVER_BUDGET_KIB,
        staging_kib: "",
        cost: "target_growth=999999999KiB",
        refusal: "grew the target root by 999999999KiB, over its 2097152KiB budget",
    },
];

/// The proof states which budget it is held to, and refuses every way a stage
/// can exceed one.
///
/// The three refusals in `measure_budget` guard the claim that this proof costs
/// what it says it costs, and no real run reaches any of them: an inverted
/// comparison or a swapped variable would pass the structural test, every other
/// lifecycle row, and both indexed runs. The clock and the sizer are the two
/// readings those refusals judge, so the rows below supply the readings.
pub(super) fn verify_packaged_workspace_budgets() {
    warm_target_selects_the_warm_budget(&RowRoot::new());
    assert_eq!(
        BUDGET_OVERRUNS.len(),
        BUDGET_REFUSALS,
        "every budget the release proof states must still have a row"
    );
    for overrun in BUDGET_OVERRUNS {
        overrun_is_refused(
            &RowRoot::new(),
            overrun,
            RELEASE_STAGE,
            PINNED_BINARIES,
            COLD_VERIFY,
        );
    }
    assert_eq!(
        WARM_BUDGET_OVERRUNS.len(),
        WARM_BUDGET_REFUSALS,
        "every warm budget must still have a row"
    );
    for overrun in WARM_BUDGET_OVERRUNS {
        let root = RowRoot::new();
        warm_the_tool_root(&root);
        overrun_is_refused(&root, overrun, RELEASE_STAGE, PINNED_BINARIES, WARM_VERIFY);
    }
    assert_eq!(
        INSTALL_BUDGET_OVERRUNS.len(),
        INSTALL_BUDGET_REFUSALS,
        "every install budget must still have a row"
    );
    for overrun in INSTALL_BUDGET_OVERRUNS {
        overrun_is_refused(
            &RowRoot::new(),
            overrun,
            INSTALL_STAGE,
            &[INSTALL_TOOL],
            COLD_INSTALL,
        );
    }
}

/// One over-budget stage states its cost, is refused by name, and still
/// releases its staging.
///
/// `stated` is the stage and warm state that cost line must carry, so the pair
/// the proof selected is read rather than assumed.
fn overrun_is_refused(
    root: &RowRoot,
    overrun: &BudgetOverrun,
    arguments: &[&str],
    installed: &[&str],
    stated: (&str, &str),
) {
    let fault = overrun.fault();
    let completed = root.run_stage(&fault, arguments);

    assert_row_is_clean(root, overrun.label, &completed, REFUSED_STATUS, installed);
    assert_refusal(overrun.label, &completed, overrun.refusal);
    assert_stated_cost(overrun.label, &completed, stated.0, stated.1, overrun.cost);
}

/// A proof over a target root that already holds the pinned tool builds finds
/// them and says so.
///
/// The two tool stages install them into the revision-named root inside the
/// target; the proof that follows asks those binaries their version and
/// believes the answer. The row plants that state through the script's own
/// installer rather than by writing a file, because a file is exactly what the
/// warm claim is no longer allowed to rest on.
fn warm_target_selects_the_warm_budget(root: &RowRoot) {
    let label = "a proof over a target that already holds the pinned tool builds";
    let fault = Fault::None;
    warm_the_tool_root(root);

    let completed = root.run(&fault);

    assert_row_is_clean(root, label, &completed, 0, fault.surviving_tool_builds());
    assert_stated_cost_shape(label, &completed, WARM_VERIFY.0, WARM_VERIFY.1);
    assert_eq!(
        root.record().operations(),
        warm_expected_operations(),
        "{label}: a warm proof must prove the builds it found before reusing them"
    );
}
