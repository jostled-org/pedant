//! Holding `run_resolution_proof.sh` to [`super::authority_proofs`].
//!
//! The runner is the artifact that decides what the final proofs execute, and
//! nothing in a cargo build reads it. This module does: it parses the script's
//! declarations back out of its text and compares them, whole, with the model.
//! Equality is the point. A containment check would accept a runner that had
//! quietly dropped half its inventory, which is the regression worth catching.

use std::collections::BTreeSet;

use crate::resolution::authority_proofs::{
    PROOF_MODES, PROOF_REJECTIONS, PROOF_RUNNER, PROOF_SCALARS, REGISTRATION_ROWS,
    SUBSTRATE_EXTRA_PREDICATES, TIER1_PREDICATES, TIER2_PREDICATES,
};
use crate::resolution::authority_scan::read_text;

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

    for (name, expected) in PROOF_SCALARS {
        assert_eq!(
            scalar_value(&runner, name),
            *expected,
            "{PROOF_RUNNER} must declare {name} with the modelled value"
        );
    }

    for (name, expected) in [
        ("TIER1_PREDICATES", TIER1_PREDICATES),
        ("TIER2_PREDICATES", TIER2_PREDICATES),
        ("SUBSTRATE_EXTRA_PREDICATES", SUBSTRATE_EXTRA_PREDICATES),
    ] {
        assert_eq!(
            array_entries(&runner, name),
            expected,
            "{PROOF_RUNNER}: {name} must be exactly the modelled inventory"
        );
    }

    assert_registration_rows(&runner);

    for rejection in PROOF_REJECTIONS {
        assert!(
            runner.contains(rejection),
            "{PROOF_RUNNER} must refuse with {rejection:?}"
        );
    }
}

/// Every `<config>|<predicates>` row, split and compared against the table.
fn assert_registration_rows(runner: &str) {
    let rows = array_entries(runner, "REGISTRATION_ROWS");
    assert_eq!(
        rows.len(),
        REGISTRATION_ROWS.len(),
        "{PROOF_RUNNER}: REGISTRATION_ROWS declares {} rows, not the modelled {}",
        rows.len(),
        REGISTRATION_ROWS.len()
    );
    for (found, expected) in rows.iter().zip(REGISTRATION_ROWS) {
        let (config, predicates) = found
            .split_once('|')
            .unwrap_or_else(|| panic!("{PROOF_RUNNER}: {found:?} is not `<config>|<predicates>`"));
        assert_eq!(
            config, expected.config,
            "{PROOF_RUNNER}: a registration row runs an unmodelled configuration"
        );
        assert_eq!(
            predicates.split_whitespace().collect::<Vec<&str>>(),
            expected.predicates,
            "{PROOF_RUNNER}: {config} must register exactly its modelled predicates"
        );
    }
}

/// The mode names the runner's dispatch answers, taken from its case arms.
fn mode_arms(runner: &str) -> BTreeSet<String> {
    runner
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_suffix(";;"))
        .filter_map(|arm| arm.split_once(')'))
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, _)| name.to_owned())
        .collect()
}

/// The value of a `NAME="…"` assignment, with its quotes removed.
fn scalar_value(runner: &str, name: &str) -> String {
    let prefix = format!("{name}=\"");
    runner
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .filter_map(|value| value.strip_suffix('"'))
        .map(str::to_owned)
        .next()
        .unwrap_or_else(|| panic!("{PROOF_RUNNER} must declare {name} as a quoted scalar"))
}

/// The entries of a `NAME=(` … `)` array literal, one per line.
///
/// Reading the script rather than running it is deliberate: executing it would
/// need a build, and the claim is about what the committed text declares.
fn array_entries(runner: &str, name: &str) -> Vec<String> {
    let opening = format!("{name}=(");
    let body = runner
        .split_once(&opening)
        .unwrap_or_else(|| panic!("{PROOF_RUNNER} must declare the array {name}"))
        .1;
    let body = body
        .split_once("\n)")
        .unwrap_or_else(|| panic!("{PROOF_RUNNER}: the array {name} is never closed"))
        .0;
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| expand(line.trim_matches('"')))
        .collect()
}

/// Resolve the one `${…}` reference an array entry may hold, so the model
/// compares predicate names rather than shell spellings.
fn expand(entry: &str) -> String {
    match entry.strip_prefix("${").and_then(|it| it.strip_suffix('}')) {
        Some(name) => PROOF_SCALARS
            .iter()
            .find(|(declared, _)| *declared == name)
            .unwrap_or_else(|| panic!("{PROOF_RUNNER} expands {name}, which the model omits"))
            .1
            .to_owned(),
        None => entry.to_owned(),
    }
}
