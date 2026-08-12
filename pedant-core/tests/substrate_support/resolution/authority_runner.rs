//! Holding `run_resolution_proof.sh` to [`super::authority_proofs`].
//!
//! The runner is the artifact that decides what the final proofs execute, and
//! nothing in a cargo build reads it. This module does: it parses the script's
//! declarations back out of its text and compares them, whole, with the model.
//! Equality is the point. A containment check would accept a runner that had
//! quietly dropped half its inventory, which is the regression worth catching.
//!
//! The parsing itself lives in [`crate::shell_script`], because the graph
//! runner's model reads the same shapes. So does the row comparison: both
//! runners now pair a configuration with its predicates in one array, and one
//! reader of that shape is one place for it to stay exact.

use std::collections::{BTreeMap, BTreeSet};

use crate::resolution::authority_proofs::{
    PROOF_MODES, PROOF_REJECTIONS, PROOF_RUNNER, PROOF_SCALARS, REGISTRATION_ROWS,
    SUBSTRATE_EXTRA_PREDICATES, TIER1_PREDICATES, TIER2_PREDICATES,
};
use crate::resolution::authority_scan::read_text;
use crate::shell_script::{array_entries, assert_registration_rows, mode_arms, model_scalars};

/// The final-proof runner is closed: seven modes, the exact inventories, the
/// exact configurations, and a refusal for every way a mode could select
/// nothing.
pub fn assert_proof_runner() {
    let runner = read_text(PROOF_RUNNER);

    assert_eq!(
        mode_arms(&runner),
        PROOF_MODES
            .iter()
            .map(|mode| (*mode).to_owned())
            .collect::<BTreeSet<String>>(),
        "{PROOF_RUNNER} must dispatch exactly the seven declared modes"
    );

    assert_eq!(
        model_scalars(PROOF_RUNNER, &runner),
        PROOF_SCALARS
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<BTreeMap<String, String>>(),
        "{PROOF_RUNNER}'s fixed model must declare exactly the modelled scalars"
    );

    for (name, expected) in [
        ("TIER1_PREDICATES", TIER1_PREDICATES),
        ("TIER2_PREDICATES", TIER2_PREDICATES),
        ("SUBSTRATE_EXTRA_PREDICATES", SUBSTRATE_EXTRA_PREDICATES),
    ] {
        assert_eq!(
            array_entries(PROOF_RUNNER, &runner, name, PROOF_SCALARS),
            expected,
            "{PROOF_RUNNER}: {name} must be exactly the modelled inventory"
        );
    }

    let rows: Vec<(&str, &[&str])> = REGISTRATION_ROWS
        .iter()
        .map(|row| (row.config, row.predicates))
        .collect();
    assert_registration_rows(
        PROOF_RUNNER,
        &runner,
        "REGISTRATION_ROWS",
        PROOF_SCALARS,
        &rows,
    );

    for rejection in PROOF_REJECTIONS {
        assert!(
            runner.contains(rejection),
            "{PROOF_RUNNER} must refuse with {rejection:?}"
        );
    }
}
