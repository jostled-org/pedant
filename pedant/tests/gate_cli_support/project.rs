//! Operator journeys through `pedant gate --project`: input modes, target
//! selection, configuration authority, and the toolchain-free Tier 1
//! guarantee. The selected-topology and failure rows live beside them in
//! `topology.rs`, because one module would exceed the 500-line source ceiling.
//!
//! Every row spawns the real binary over a real temporary Cargo repository and
//! reads only what the operator can see.

use std::path::Path;

use crate::fixture::{
    LIBRARY_TARGET, ProjectFixture, RunOptions, SHARING_TARGETS, WORKSPACE_TARGETS,
    crossing_project, install_toolchain_sentinels, json_payload, simple_project,
};
use crate::process_guard::Completed;

/// One argument combination `pedant gate` must refuse before it analyzes
/// anything, and the exact refusal the operator reads.
///
/// The refusal text is part of the row because every one of these exits 2: an
/// unknown flag does too, so a row that asserted the code alone would still
/// pass if `--project` were renamed away.
struct RejectedMode {
    /// The arguments, with `PROJECT` and `SOURCE` replaced by fixture paths.
    args: &'static [&'static str],
    /// The stderr fragment naming why this combination was refused.
    expected: &'static str,
}

const REJECTED_MODES: &[RejectedMode] = &[
    RejectedMode {
        args: &["--project", "PROJECT", "--stdin"],
        expected: "the argument '--project <ROOT>' cannot be used with '--stdin'",
    },
    RejectedMode {
        args: &["--project", "PROJECT", "SOURCE"],
        expected: "the argument '--project <ROOT>' cannot be used with '[FILES]...'",
    },
    RejectedMode {
        args: &["--project", "PROJECT", "--cross-language"],
        expected: "the argument '--project <ROOT>' cannot be used with '--cross-language'",
    },
    RejectedMode {
        args: &["--stdin", "SOURCE"],
        expected: "the argument '--stdin' cannot be used with '[FILES]...'",
    },
    RejectedMode {
        args: &[],
        expected: "the following required arguments were not provided",
    },
];

fn substituted<'a>(row: &[&'a str], project: &'a str, source: &'a str) -> Vec<&'a str> {
    row.iter()
        .map(|argument| match *argument {
            "PROJECT" => project,
            "SOURCE" => source,
            other => other,
        })
        .collect()
}

/// Exactly one input mode is accepted, and file and stdin modes keep their
/// capability output without a target list or structural evidence.
pub(crate) fn input_modes_are_disjoint() {
    let fixture = simple_project();
    let marker = fixture.scratch().join("toolchain-marker");
    let sentinels = fixture.scratch().join("sentinel-bin");
    install_toolchain_sentinels(&sentinels, &marker);
    let options = RunOptions {
        path_prefix: Some(&sentinels),
        ..RunOptions::default()
    };

    let root = crate::fixture::path_text(&fixture.root());
    let source = fixture.path_arg("src/left.rs");
    for row in REJECTED_MODES {
        let args = substituted(row.args, &root, &source);
        let refused = fixture.gate_with(&args, &options);
        assert_eq!(
            refused.code(),
            Some(2),
            "{args:?} must be refused before analysis: {}",
            refused.transcript()
        );
        assert!(
            refused.stdout.is_empty(),
            "{args:?} produced output before its refusal: {}",
            refused.transcript()
        );
        assert!(
            refused.stderr.contains(row.expected),
            "{args:?} must be refused as an input-mode conflict: {}",
            refused.stderr
        );
    }
    assert!(
        !marker.exists(),
        "argument refusal must precede every toolchain invocation"
    );

    legacy_modes_carry_no_project_fields(&fixture, &source);
}

/// File and stdin gate output keeps its exact legacy shape.
fn legacy_modes_carry_no_project_fields(fixture: &ProjectFixture, source: &str) {
    let files = fixture.gate(&[source, "--format", "json"]);
    assert!(files.success(), "file mode failed: {}", files.transcript());
    assert_legacy_payload(&files, "file mode");

    let stdin = fixture.gate_with(
        &["--stdin", "--format", "json"],
        &RunOptions {
            stdin: Some(b"fn item() {}\n"),
            ..RunOptions::default()
        },
    );
    assert!(stdin.success(), "stdin mode failed: {}", stdin.transcript());
    assert_legacy_payload(&stdin, "stdin mode");
}

fn assert_legacy_payload(completed: &Completed, label: &str) {
    let payload = json_payload(completed);
    let object = payload.as_object().expect("the envelope is an object");
    assert!(
        !object.contains_key("analyzed_targets"),
        "{label} must not report analyzed_targets: {}",
        completed.stdout
    );
    assert!(
        !completed.stdout.contains("\"evidence\""),
        "{label} must not carry structural evidence: {}",
        completed.stdout
    );
    assert!(
        object.contains_key("analysis_tier") && object.contains_key("gate_verdicts"),
        "{label} keeps its existing envelope fields: {}",
        completed.stdout
    );
}

/// Selection covers every and only primary workspace target, in project order,
/// under either filesystem creation order.
///
/// Both workspaces are built once by the registered test and shared with the
/// record owner in `output.rs`, which compares the bytes each format emits for
/// the same two fixtures.
pub(crate) fn selects_every_primary_target_in_stable_order(
    forward: &ProjectFixture,
    reversed: &ProjectFixture,
) {
    for (label, fixture) in [("forward", forward), ("reversed", reversed)] {
        let run = fixture.project_gate(&["--format", "json"]);
        assert_eq!(
            run.code(),
            Some(1),
            "{label}: the corpus denies: {}",
            run.transcript()
        );
        let payload = json_payload(&run);
        assert_eq!(
            crate::fixture::analyzed_targets(&payload),
            WORKSPACE_TARGETS,
            "{label} selection order"
        );
        shared_sources_stay_target_scoped(&payload, label);
    }
}

/// One cycle reachable from two selected targets remains two results.
///
/// The measurements are compared with their ordinals removed, because an
/// ordinal is target-local by contract: everything the evidence identifies —
/// labels, anchors, counts — must be equal across the pair, and only the target
/// each result is scoped to may differ.
fn shared_sources_stay_target_scoped(payload: &serde_json::Value, label: &str) {
    let crossings: Vec<&serde_json::Value> = payload["gate_verdicts"]
        .as_array()
        .expect("gate_verdicts is an array")
        .iter()
        .filter(|verdict| verdict["rule"] == "boundary-crossing-scc")
        .map(|verdict| &verdict["evidence"]["evidence"])
        .collect();
    let scoped: Vec<&serde_json::Value> = crossings
        .iter()
        .map(|evidence| &evidence["target"])
        .collect();
    assert_eq!(
        scoped,
        SHARING_TARGETS.iter().collect::<Vec<&&str>>(),
        "{label}: shared sources produce one result per target: {payload}"
    );

    let [first, second] = crossings.as_slice() else {
        panic!("{label}: exactly two results were just required");
    };
    assert_eq!(
        without_ordinals(&first["measurement"]),
        without_ordinals(&second["measurement"]),
        "{label}: the same sources carry the same measurement in both targets"
    );
    assert_eq!(
        without_ordinals(&first["subject"]),
        without_ordinals(&second["subject"]),
        "{label}: the same cycle names the same subject in both targets"
    );
}

/// The same evidence with every target-local ordinal removed.
fn without_ordinals(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(fields) => fields
            .iter()
            .filter(|(key, _)| key.as_str() != "ordinal")
            .map(|(key, held)| (key.clone(), without_ordinals(held)))
            .collect(),
        serde_json::Value::Array(items) => items.iter().map(without_ordinals).collect(),
        other => other.clone(),
    }
}

/// Explicit, project-local, global, and default configuration, in that order.
pub(crate) fn config_precedence_and_failure_contract_are_exact() {
    let fixture = crossing_project();

    // Defaults deny a boundary-crossing cycle.
    assert_eq!(
        fixture.project_gate(&[]).code(),
        Some(1),
        "defaults deny a boundary-crossing cycle"
    );

    // A global config downgrades it; the project has no config of its own yet.
    fixture.write_global_config("[gate.module-boundary]\nboundary-crossing-scc = \"warn\"\n");
    assert!(
        fixture.project_gate(&[]).success(),
        "the global config is the third source"
    );

    // A project-local config outranks the global one.
    fixture.write(
        ".pedant.toml",
        "[gate.module-boundary]\nboundary-crossing-scc = \"deny\"\n",
    );
    assert_eq!(
        fixture.project_gate(&[]).code(),
        Some(1),
        "the canonical project-local config outranks the global one"
    );

    explicit_config_outranks_discovery(&fixture);
    explicit_config_failures_are_fatal(&fixture);
    discovered_config_failures_are_fatal(&fixture);
    disablement_never_suppresses_construction_failures();
}

/// An explicit `--config` path is read relative to the process working
/// directory and outranks every discovered source.
fn explicit_config_outranks_discovery(fixture: &ProjectFixture) {
    std::fs::write(
        fixture.scratch().join("explicit.toml"),
        "[gate.module-boundary]\nenabled = false\n",
    )
    .expect("the explicit config should be writable");
    let run = fixture.project_gate_with(
        &["--config", "explicit.toml"],
        &RunOptions {
            cwd: Some(fixture.scratch()),
            ..RunOptions::default()
        },
    );
    assert!(
        run.success(),
        "an explicit cwd-relative config outranks discovery: {}",
        run.transcript()
    );
}

/// The explicit paths that must be fatal, and the reason each one states.
///
/// An absent explicit path is the arm discovery would otherwise cover for: a
/// missing `.pedant.toml` advances to the global source, while a missing
/// `--config` file is a refusal.
const EXPLICIT_CONFIG_FAILURES: &[(&str, &str)] = &[
    ("absent.toml", "failed to read config file"),
    ("broken.toml", "failed to parse config file"),
];

/// An explicit `--config` path that cannot be used is fatal, whether it is
/// absent or unreadable.
fn explicit_config_failures_are_fatal(fixture: &ProjectFixture) {
    std::fs::write(
        fixture.scratch().join("broken.toml"),
        "[gate.module-boundary]\nnot-a-field = 1\n",
    )
    .expect("the broken config should be writable");
    for (name, reason) in EXPLICIT_CONFIG_FAILURES {
        let refused = fixture.project_gate_with(
            &["--config", name],
            &RunOptions {
                cwd: Some(fixture.scratch()),
                ..RunOptions::default()
            },
        );
        assert_eq!(
            refused.code(),
            Some(2),
            "{name}: an unusable explicit config is fatal: {}",
            refused.transcript()
        );
        assert!(
            refused.stdout.is_empty(),
            "{name}: a fatal config failure emits nothing: {}",
            refused.stdout
        );
        assert!(
            refused.stderr.contains("config file")
                && refused.stderr.contains("cannot be used")
                && refused.stderr.contains(name)
                && refused.stderr.contains(reason),
            "{name}: the refusal names the source and why it failed: {}",
            refused.stderr
        );
    }
}

/// A discovered source that exists but cannot be used is fatal in project mode,
/// while file mode keeps its warning behavior.
fn discovered_config_failures_are_fatal(fixture: &ProjectFixture) {
    fixture.write(".pedant.toml", "[gate.module-boundary]\nnot-a-field = 1\n");
    let refused = fixture.project_gate(&[]);
    assert_eq!(
        refused.code(),
        Some(2),
        "a broken discovered config is fatal in project mode: {}",
        refused.transcript()
    );
    assert!(
        refused.stdout.is_empty(),
        "a fatal config failure emits nothing: {}",
        refused.stdout
    );
    assert!(
        refused.stderr.contains("cannot be used") && refused.stderr.contains(".pedant.toml"),
        "the refusal names the discovered source it could not use: {}",
        refused.stderr
    );

    let source = fixture.path_arg("src/left.rs");
    let warned = fixture.gate_in_root(&[source.as_str()]);
    assert!(
        warned.success(),
        "file mode keeps its warning behavior: {}",
        warned.transcript()
    );
    fixture.remove(".pedant.toml");
}

/// Disablement suppresses evaluation only: construction still fails loudly.
fn disablement_never_suppresses_construction_failures() {
    for disabled in [
        "[gate]\nenabled = false\n\n[gate.module-boundary]\nmax-selected-edges = 0\n",
        "[gate.module-boundary]\nenabled = false\nmax-selected-edges = 0\n",
    ] {
        let fixture = simple_project();
        fixture.write(".pedant.toml", disabled);
        let refused = fixture.project_gate(&[]);
        assert_eq!(
            refused.code(),
            Some(2),
            "disablement must not suppress an analysis refusal: {}",
            refused.transcript()
        );
        assert!(
            refused.stdout.is_empty(),
            "a suppressed evaluation still emits no success payload: {}",
            refused.stdout
        );
    }
}

/// Tier 1 reads the declared repository and invokes no toolchain at all.
pub(crate) fn tier1_invokes_no_toolchain() {
    let fixture = simple_project();
    let marker = fixture.scratch().join("toolchain-marker");
    let sentinels = fixture.scratch().join("sentinel-bin");
    install_toolchain_sentinels(&sentinels, &marker);

    let run = fixture.project_gate_with(
        &["--format", "json"],
        &RunOptions {
            path_prefix: Some(&sentinels),
            ..RunOptions::default()
        },
    );
    assert!(run.success(), "Tier 1 failed: {}", run.transcript());
    let payload = json_payload(&run);
    assert_eq!(payload["analysis_tier"], "syntactic");
    assert_eq!(
        payload["analyzed_targets"]
            .as_array()
            .map(|targets| targets.len()),
        Some(1)
    );
    assert_eq!(payload["analyzed_targets"][0], LIBRARY_TARGET);
    assert_marker_absent(&marker);
}

fn assert_marker_absent(marker: &Path) {
    assert!(
        !marker.exists(),
        "Tier 1 must invoke no Cargo, rustc, or rust-analyzer, marker: {}",
        std::fs::read_to_string(marker).unwrap_or_default()
    );
}
