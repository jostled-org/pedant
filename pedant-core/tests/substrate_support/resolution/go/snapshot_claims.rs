//! The baseline Go snapshot claim and the field families its digest must cover.
//!
//! Split from `snapshot_fingerprint.rs` so the table and the case that reads it
//! each stay inside the source-file budget. The table is the subject of exactly
//! one case, which sizes its own pass bar from [`CLAIM_CASES`] — so a row
//! deleted here lowers that bar, and the case asserts the row count to stop it.

#![cfg(feature = "resolution-test-support")]

use std::path::PathBuf;

use pedant_core::resolution::go::{
    GoEdgeFingerprintClaim, GoModuleFingerprintClaim, GoSnapshotFingerprintClaim,
    GoSourceFingerprintClaim, GoUnitFingerprintClaim,
};

/// One perturbed field family and the label its row fails under.
pub struct ClaimCase {
    pub label: &'static str,
    pub perturb: fn(&mut GoSnapshotFingerprintClaim),
}

/// The baseline claim every row is compared against.
///
/// The canonical root is held byte-identical by every row but the one that
/// perturbs it, so a row that changes the fingerprint proves the family it
/// touched is covered rather than proving the root is.
pub fn baseline_claim() -> GoSnapshotFingerprintClaim {
    GoSnapshotFingerprintClaim {
        root: PathBuf::from("/repo"),
        modules: vec![
            GoModuleFingerprintClaim {
                path: "example.com/root".to_owned(),
                directory: String::new(),
                manifest: "go.mod".to_owned(),
                depth: 0,
            },
            GoModuleFingerprintClaim {
                path: "example.com/lib".to_owned(),
                directory: "local/lib".to_owned(),
                manifest: "local/lib/go.mod".to_owned(),
                depth: 1,
            },
        ],
        units: vec![
            GoUnitFingerprintClaim {
                module: 0,
                context: "production".to_owned(),
                import_path: "example.com/root".to_owned(),
                package_name: "root".to_owned(),
                directory: String::new(),
                sources: vec!["root.go".to_owned()],
            },
            GoUnitFingerprintClaim {
                module: 1,
                context: "production".to_owned(),
                import_path: "example.com/lib".to_owned(),
                package_name: "lib".to_owned(),
                directory: "local/lib".to_owned(),
                sources: vec!["local/lib/lib.go".to_owned()],
            },
        ],
        edges: vec![GoEdgeFingerprintClaim {
            source: 0,
            target: 1,
            module_path: "example.com/lib".to_owned(),
            version: "v1.0.0".to_owned(),
        }],
        sources: vec![
            GoSourceFingerprintClaim {
                path: "local/lib/lib.go".to_owned(),
                digest: [1; 32],
                predicates: Vec::new(),
            },
            GoSourceFingerprintClaim {
                path: "root.go".to_owned(),
                digest: [2; 32],
                predicates: vec!["suffix:linux".to_owned()],
            },
        ],
    }
}

/// Every resolution- and graph-relevant family the digest must separate.
pub const CLAIM_CASES: &[ClaimCase] = &[
    ClaimCase {
        label: "canonical root",
        perturb: |claim| claim.root = PathBuf::from("/other"),
    },
    ClaimCase {
        label: "module path",
        perturb: |claim| claim.modules[1].path = "example.com/other".to_owned(),
    },
    ClaimCase {
        label: "module directory",
        perturb: |claim| claim.modules[1].directory = "local/other".to_owned(),
    },
    ClaimCase {
        label: "module manifest",
        perturb: |claim| claim.modules[1].manifest = "local/other/go.mod".to_owned(),
    },
    ClaimCase {
        label: "module depth",
        perturb: |claim| claim.modules[1].depth = 2,
    },
    ClaimCase {
        label: "module count",
        perturb: |claim| {
            claim.modules.truncate(1);
        },
    },
    ClaimCase {
        label: "unit module",
        perturb: |claim| claim.units[1].module = 0,
    },
    ClaimCase {
        label: "unit context",
        perturb: |claim| claim.units[1].context = "internal_test".to_owned(),
    },
    ClaimCase {
        label: "unit import path",
        perturb: |claim| claim.units[1].import_path = "example.com/lib/inner".to_owned(),
    },
    ClaimCase {
        label: "unit package name",
        perturb: |claim| claim.units[1].package_name = "other".to_owned(),
    },
    ClaimCase {
        label: "unit directory",
        perturb: |claim| claim.units[1].directory = "local/other".to_owned(),
    },
    ClaimCase {
        label: "unit source membership",
        perturb: |claim| claim.units[0].sources.push("root_extra.go".to_owned()),
    },
    ClaimCase {
        label: "unit count",
        perturb: |claim| {
            claim.units.truncate(1);
        },
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
        label: "edge module path",
        perturb: |claim| claim.edges[0].module_path = "example.com/other".to_owned(),
    },
    ClaimCase {
        label: "edge version",
        perturb: |claim| claim.edges[0].version = "v2.0.0".to_owned(),
    },
    ClaimCase {
        label: "edge count",
        perturb: |claim| claim.edges.clear(),
    },
    ClaimCase {
        label: "source path",
        perturb: |claim| claim.sources[1].path = "other.go".to_owned(),
    },
    ClaimCase {
        label: "source digest",
        perturb: |claim| claim.sources[1].digest = [3; 32],
    },
    ClaimCase {
        label: "source predicate",
        perturb: |claim| claim.sources[1].predicates = vec!["suffix:darwin".to_owned()],
    },
    ClaimCase {
        label: "source predicate absence",
        perturb: |claim| claim.sources[1].predicates.clear(),
    },
    ClaimCase {
        label: "source count",
        perturb: |claim| {
            claim.sources.truncate(1);
        },
    },
];
