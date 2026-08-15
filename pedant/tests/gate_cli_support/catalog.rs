//! Spawned `list-checks` and `explain` visibility for every structural rule.

use crate::fixture::{ProjectFixture, ROOT_MANIFEST};

/// Every module-boundary rule, its default severity, its listed description,
/// and the rationale `explain` must print.
const STRUCTURAL_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "large-scc",
        "warn",
        "Cyclic component exceeds the configured member limit",
        "cyclic component exceeds max-scc-members",
    ),
    (
        "boundary-crossing-scc",
        "deny",
        "Cycle crosses a declared module boundary",
        "cycle crosses declared module partitions",
    ),
    (
        "misplaced-symbol",
        "warn",
        "Symbol has stronger outgoing affinity to another module",
        "foreign-edge affinity meets the misplaced-symbol threshold",
    ),
    (
        "low-module-cohesion",
        "warn",
        "Module sends too little selected traffic to itself",
        "internal-edge cohesion is below the configured threshold",
    ),
];

/// One retained capability rule and check, which must keep their listing and
/// their explanation exactly as before.
const RETAINED_ROWS: &[(&str, &str)] = &[
    ("build-script-network", "Gate rule: build-script-network"),
    ("nested-if", "Check: nested-if"),
];

/// Every structural rule is listed once and explained once, and the retained
/// catalogs keep their behavior.
pub(crate) fn catalog_is_listed_and_explained_once() {
    let fixture = ProjectFixture::build(&[
        ("Cargo.toml", ROOT_MANIFEST),
        ("src/lib.rs", "pub fn only() {}\n"),
    ]);

    let listed = fixture.run(&["list-checks"]);
    assert!(
        listed.success(),
        "list-checks failed: {}",
        listed.transcript()
    );
    for (name, severity, description, _) in STRUCTURAL_RULES {
        let rows: Vec<&str> = listed
            .stdout
            .lines()
            .filter(|line| line.starts_with(name))
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "{name} must be listed exactly once, got {rows:?}"
        );
        let row = rows[0];
        assert!(
            row.contains(severity) && row.contains(description),
            "{name} lists its exact default severity and description: {row}"
        );
    }

    for (name, _, _, rationale) in STRUCTURAL_RULES {
        let explained = fixture.run(&["explain", name]);
        assert!(
            explained.success(),
            "explain {name} failed: {}",
            explained.transcript()
        );
        assert!(
            explained.stdout.contains(&format!("Gate rule: {name}"))
                && explained.stdout.contains(rationale),
            "explain {name} prints its exact rationale: {}",
            explained.stdout
        );
    }

    for (name, expected) in RETAINED_ROWS {
        let explained = fixture.run(&["explain", name]);
        assert!(
            explained.success() && explained.stdout.contains(expected),
            "explain {name} is unchanged: {}",
            explained.transcript()
        );
        assert!(
            listed.stdout.lines().any(|line| line.starts_with(name)),
            "{name} remains listed"
        );
    }

    let unknown = fixture.run(&["explain", "no-such-rule"]);
    assert_eq!(
        unknown.code(),
        Some(1),
        "an unknown name keeps its refusal: {}",
        unknown.transcript()
    );
    assert!(
        unknown.stderr.contains("Unknown check: no-such-rule"),
        "the refusal names what was asked for: {}",
        unknown.stderr
    );
}
