//! The baseline snapshot claim and the field families the digest must cover.
//!
//! Split from `fingerprint.rs` so the table and the cases that read it each stay
//! inside the source-file budget. The table is the subject of exactly one case,
//! `snapshot_fingerprint_covers_every_projection_claim`, which sizes its own
//! pass bar from `CLAIM_CASES` — so a row deleted here lowers that bar, and the
//! case asserts the row count to stop it.

#![cfg(feature = "resolution-test-support")]

use std::path::PathBuf;

use pedant_core::resolution::rust::{
    CargoDependencyKind, EdgeFingerprintClaim, SnapshotFingerprintClaim, SourceFingerprintClaim,
    UnitFingerprintClaim,
};

/// One perturbed field family and the label its row fails under.
pub(crate) struct ClaimCase {
    pub(crate) label: &'static str,
    pub(crate) perturb: fn(&mut SnapshotFingerprintClaim),
}

/// The baseline claim every row is compared against.
///
/// Canonical root and requested authority are held byte-identical by every
/// row, so a row that changes the fingerprint proves the perturbed family is
/// covered rather than proving the identity is.
pub(crate) fn baseline_claim() -> SnapshotFingerprintClaim {
    SnapshotFingerprintClaim {
        root: PathBuf::from("/repo"),
        requested: 0,
        units: vec![
            UnitFingerprintClaim {
                name: "app".to_owned(),
                manifest: "Cargo.toml".to_owned(),
                kind: "lib".to_owned(),
                crate_root: "src/lib.rs".to_owned(),
                predicate: None,
                sources: vec!["src/lib.rs".to_owned(), "src/alpha.rs".to_owned()],
            },
            UnitFingerprintClaim {
                name: "helper".to_owned(),
                manifest: "crates/helper/Cargo.toml".to_owned(),
                kind: "lib".to_owned(),
                crate_root: "crates/helper/src/lib.rs".to_owned(),
                predicate: Some("cfg(unix)".to_owned()),
                sources: vec!["crates/helper/src/lib.rs".to_owned()],
            },
        ],
        edges: vec![EdgeFingerprintClaim {
            source: 0,
            target: 1,
            alias: "helper".to_owned(),
            kind: CargoDependencyKind::Normal,
            predicate: None,
        }],
        sources: vec![
            SourceFingerprintClaim {
                path: "src/lib.rs".to_owned(),
                digest: [7; 32],
            },
            SourceFingerprintClaim {
                path: "crates/helper/src/lib.rs".to_owned(),
                digest: [9; 32],
            },
        ],
    }
}

/// Every field family the digest must cover, one row at a time.
pub(crate) const CLAIM_CASES: &[ClaimCase] = &[
    ClaimCase {
        label: "unit name",
        perturb: |claim| claim.units[0].name = "renamed".to_owned(),
    },
    ClaimCase {
        label: "unit manifest",
        perturb: |claim| claim.units[0].manifest = "other/Cargo.toml".to_owned(),
    },
    ClaimCase {
        label: "unit target kind",
        perturb: |claim| claim.units[0].kind = "bin".to_owned(),
    },
    ClaimCase {
        label: "unit crate root",
        perturb: |claim| claim.units[0].crate_root = "src/main.rs".to_owned(),
    },
    ClaimCase {
        label: "unit activation predicate",
        perturb: |claim| claim.units[1].predicate = Some("cfg(windows)".to_owned()),
    },
    ClaimCase {
        label: "unit activation presence",
        perturb: |claim| claim.units[1].predicate = None,
    },
    ClaimCase {
        label: "unit order",
        perturb: |claim| claim.units.swap(0, 1),
    },
    ClaimCase {
        label: "unit source membership",
        perturb: |claim| claim.units[0].sources.push("src/beta.rs".to_owned()),
    },
    ClaimCase {
        label: "unit source order",
        perturb: |claim| claim.units[0].sources.swap(0, 1),
    },
    ClaimCase {
        label: "edge source",
        perturb: |claim| claim.edges[0].source = 1,
    },
    ClaimCase {
        label: "edge target",
        perturb: |claim| claim.edges[0].target = 0,
    },
    ClaimCase {
        label: "edge alias",
        perturb: |claim| claim.edges[0].alias = "aliased".to_owned(),
    },
    ClaimCase {
        label: "edge dependency kind",
        perturb: |claim| claim.edges[0].kind = CargoDependencyKind::Development,
    },
    ClaimCase {
        label: "edge activation predicate",
        perturb: |claim| claim.edges[0].predicate = Some("cfg(test)".to_owned()),
    },
    ClaimCase {
        label: "edge membership",
        perturb: |claim| claim.edges.clear(),
    },
    ClaimCase {
        label: "normalized source path",
        perturb: |claim| claim.sources[0].path = "src/moved.rs".to_owned(),
    },
    ClaimCase {
        label: "exact source digest",
        perturb: |claim| claim.sources[0].digest = [8; 32],
    },
    ClaimCase {
        label: "source membership",
        perturb: |claim| claim.sources.truncate(1),
    },
    ClaimCase {
        label: "source order",
        perturb: |claim| claim.sources.swap(0, 1),
    },
];
