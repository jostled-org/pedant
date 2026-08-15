//! Exact project-mode text, JSON, and GitHub records, their escaping, their
//! anchoring, and the exit codes they carry.

use crate::fixture::{
    CROSSING_DOWN, CROSSING_UP, LIBRARY_TARGET, ProjectFixture, ROOT_MANIFEST, RunOptions,
    crossing_project, json_payload, simple_project,
};
use crate::process_guard::Completed;

/// The envelope's own top-level keys, in the order the writer emitted them.
///
/// Read off the serialized bytes rather than a re-parsed map, because parsing
/// into a `Value` sorts object keys and would hide a field-order regression.
fn envelope_field_order(payload: &str) -> Vec<&str> {
    payload
        .lines()
        .filter_map(|line| line.strip_prefix("  \""))
        .filter_map(|line| line.split_once("\":"))
        .map(|(key, _)| key)
        .collect()
}

/// The corpus whose only structural root is location-free.
///
/// Four symbols declared straight in the crate root call into the one declared
/// module, so the partition low cohesion is measured for is the unit container
/// itself — the sole node kind graph construction mints without any source
/// anchor. That is the verdict the `None` annotation arm exists for.
fn unanchored_project() -> ProjectFixture {
    ProjectFixture::build(&[
        ("Cargo.toml", ROOT_MANIFEST),
        (
            "src/lib.rs",
            "pub mod inner;\n\npub fn a() { crate::inner::x1(); }\npub fn b() { crate::inner::x2(); }\npub fn c() { crate::inner::x3(); }\npub fn d() { crate::inner::x4(); }\n",
        ),
        (
            "src/inner.rs",
            "pub fn x1() {}\npub fn x2() {}\npub fn x3() {}\npub fn x4() {}\n",
        ),
    ])
}

/// The corpus whose target label and source paths force both escape owners to
/// act, and to act differently on the same bytes.
///
/// The `od,d%1` member directory carries a workflow property separator and a
/// percent sign into every path and label a record is built from. A colon is
/// deliberately absent: it cannot appear in a portable path, and it travels the
/// same `escape_property` branch the comma proves.
fn escaping_project() -> ProjectFixture {
    ProjectFixture::build(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"od,d%1\"]\nresolver = \"3\"\n",
        ),
        (
            "od,d%1/Cargo.toml",
            "[package]\nname = \"odd\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        ),
        ("od,d%1/src/lib.rs", "pub mod left;\npub mod right;\n"),
        ("od,d%1/src/left.rs", CROSSING_UP),
        ("od,d%1/src/right.rs", CROSSING_DOWN),
    ])
}

/// Text, JSON, and GitHub project records are exact and actionable.
///
/// The three record rows read the same repository, so it is built once here:
/// none of them writes to it, and three temporary trees would only prove three
/// times that the same bytes produce the same records.
pub(crate) fn outputs_are_exact_and_actionable() {
    let crossing = crossing_project();
    text_records_state_tier_targets_and_evidence(&crossing);
    json_envelope_is_ordered_and_evidence_bearing(&crossing);
    github_records_are_anchored_and_escaped(&crossing);
    empty_results_still_report_their_targets();
    advisory_only_evidence_exits_zero();
    a_failed_write_exits_two();
}

/// Every format emits the same bytes for two workspaces that differ only in the
/// order their files were created.
///
/// The corpus bears verdicts, and each comparison requires the compared bytes to
/// hold one, so a run that stopped emitting records cannot pass by matching an
/// equally empty peer.
pub(crate) fn records_are_stable_across_creation_order(
    forward: &ProjectFixture,
    reversed: &ProjectFixture,
) {
    for format in ["text", "json", "github"] {
        let first = forward.project_gate(&["--format", format]);
        let second = reversed.project_gate(&["--format", format]);
        assert_eq!(
            first.stdout, second.stdout,
            "{format} output must not depend on filesystem creation order"
        );
        assert!(
            first.stdout.contains("boundary-crossing-scc"),
            "{format}: the compared corpus carries verdicts: {}",
            first.stdout
        );
    }
}

fn text_records_state_tier_targets_and_evidence(fixture: &ProjectFixture) {
    let run = fixture.project_gate(&[]);
    assert_eq!(run.code(), Some(1), "a deny exits 1: {}", run.transcript());
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines.first(), Some(&"analysis-tier: syntactic"));
    assert_eq!(lines.get(1), Some(&"target: \".#lib:demo\""));

    let verdict = lines
        .iter()
        .find(|line| line.starts_with("deny: boundary-crossing-scc — "))
        .unwrap_or_else(|| panic!("a denied crossing line, got: {}", run.stdout));
    assert!(
        verdict
            .contains("cycle crosses declared module partitions; target=\".#lib:demo\"; subject={"),
        "the text line spells evidence through the JSON contract: {verdict}"
    );
    assert!(
        verdict.contains("; measurement={\"kind\":\"component\",\"cyclic\":true,"),
        "the measurement is the compact tagged JSON object: {verdict}"
    );
}

fn json_envelope_is_ordered_and_evidence_bearing(fixture: &ProjectFixture) {
    let run = fixture.project_gate(&["--format", "json"]);
    let payload = json_payload(&run);
    assert_eq!(
        envelope_field_order(&run.stdout),
        [
            "analysis_tier",
            "had_error",
            "gate_verdicts",
            "analyzed_targets"
        ],
        "the project envelope keeps its field order and omits violations"
    );

    assert_eq!(payload["analyzed_targets"][0], LIBRARY_TARGET);
    let verdict = payload["gate_verdicts"]
        .as_array()
        .expect("gate_verdicts is an array")
        .iter()
        .find(|value| value["rule"] == "boundary-crossing-scc")
        .expect("the denied crossing is published");
    let evidence = &verdict["evidence"];
    assert_eq!(evidence["domain"], "module_boundary");
    assert_eq!(evidence["evidence"]["target"], LIBRARY_TARGET);
    assert_eq!(evidence["evidence"]["measurement"]["kind"], "component");
    assert_eq!(evidence["evidence"]["measurement"]["cyclic"], true);
    assert_eq!(
        evidence["evidence"]["measurement"]["partitions"]
            .as_array()
            .map(Vec::len),
        Some(2),
        "the exact partitions that triggered the verdict are retained"
    );
    let subject = &evidence["evidence"]["subject"];
    assert!(
        subject["label"]
            .as_str()
            .is_some_and(|label| label.starts_with("scc::")),
        "a component subject is named after its first member: {subject}"
    );
    assert!(
        subject["location"]["line"]
            .as_u64()
            .is_some_and(|line| line >= 1),
        "a symbol verdict carries a one-based location: {subject}"
    );
}

fn github_records_are_anchored_and_escaped(fixture: &ProjectFixture) {
    let run = fixture.project_gate(&["--format", "github"]);
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(
        lines.first(),
        Some(
            &"::notice title=pedant module-boundary::analysis-tier=syntactic; targets=[\".#lib:demo\"]"
        ),
        "every run emits one workflow summary notice: {}",
        run.stdout
    );
    let annotation = lines
        .iter()
        .find(|line| line.contains("title=boundary-crossing-scc"))
        .unwrap_or_else(|| panic!("a denied crossing annotation, got: {}", run.stdout));
    assert!(
        annotation.starts_with("::error file=src/left.rs,line="),
        "the annotation anchors through the subject location: {annotation}"
    );

    a_location_free_root_is_unanchored_and_identified();
    separators_are_escaped_in_properties_only();
}

/// The exact record a location-free structural root produces.
///
/// Nothing about this line may be inferred: the whole annotation is compared
/// byte for byte, so an unanchored verdict that lost its level, its title, or
/// any part of its identification fails, and so does a run that stopped
/// emitting it at all.
fn a_location_free_root_is_unanchored_and_identified() {
    let fixture = unanchored_project();
    let run = fixture.project_gate(&["--format", "github"]);
    assert!(
        run.success(),
        "an advisory-only root exits 0: {}",
        run.transcript()
    );
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "::notice title=pedant module-boundary::analysis-tier=syntactic; targets=[\".#lib:demo\"]",
            "::warning title=low-module-cohesion::internal-edge cohesion is below the configured threshold; target=\".#lib:demo\"; subject={\"ordinal\":0,\"label\":\"demo\"}; measurement={\"kind\":\"low_module_cohesion\",\"internal_edges\":0,\"boundary_edges\":5}",
        ],
        "a location-free root carries no file/line/col property and stays fully identified: {}",
        run.stdout
    );
}

/// Property values are escaped; message bodies are not, and neither record ever
/// breaks across a line.
///
/// The same repository bytes travel both owners, so one corpus separates them:
/// the comma that would truncate a property is `%2C` there and stays literal in
/// the message beside it, while the percent sign is escaped in both.
fn separators_are_escaped_in_properties_only() {
    let fixture = escaping_project();
    let run = fixture.project_gate(&["--format", "github"]);
    assert_eq!(
        run.code(),
        Some(1),
        "the escaping corpus denies: {}",
        run.transcript()
    );
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "quoted, comma-bearing JSON evidence stays on one record per verdict: {}",
        run.stdout
    );
    assert_eq!(
        lines.first(),
        Some(
            &"::notice title=pedant module-boundary::analysis-tier=syntactic; targets=[\"od,d%251#lib:odd\"]"
        ),
        "a message body escapes the percent sign and keeps the separator literal: {}",
        run.stdout
    );

    let annotation = lines
        .get(1)
        .unwrap_or_else(|| panic!("a denied crossing annotation, got: {}", run.stdout));
    let (properties, message) = annotation
        .split_once("::")
        .and_then(|(_, rest)| rest.split_once("::"))
        .unwrap_or_else(|| panic!("an annotation states properties then a message: {annotation}"));
    assert_eq!(
        properties, "error file=od%2Cd%251/src/left.rs,line=1,col=8,title=boundary-crossing-scc",
        "a property escapes both the separator and the percent sign: {annotation}"
    );
    assert!(
        message.contains("; target=\"od,d%251#lib:odd\""),
        "the same bytes keep their separator in the message body: {annotation}"
    );
}

fn empty_results_still_report_their_targets() {
    let fixture = ProjectFixture::build(&[
        ("Cargo.toml", ROOT_MANIFEST),
        ("src/lib.rs", "pub fn only() {}\n"),
    ]);
    let text = fixture.project_gate(&[]);
    assert!(
        text.success(),
        "a clean project exits 0: {}",
        text.transcript()
    );
    assert_eq!(
        &*text.stdout, "analysis-tier: syntactic\ntarget: \".#lib:demo\"\n",
        "a zero-verdict run is still observable"
    );

    let json = fixture.project_gate(&["--format", "json"]);
    let payload = json_payload(&json);
    assert_eq!(payload["gate_verdicts"].as_array().map(Vec::len), Some(0));
    assert_eq!(payload["analyzed_targets"][0], LIBRARY_TARGET);

    let github = fixture.project_gate(&["--format", "github"]);
    assert_eq!(
        github.stdout.lines().count(),
        1,
        "the summary notice is the whole record: {}",
        github.stdout
    );
}

fn advisory_only_evidence_exits_zero() {
    let fixture = simple_project();
    fixture.write(
        ".pedant.toml",
        "[gate.module-boundary]\nlow-module-cohesion-min-outgoing-edges = 1\nlow-module-cohesion-min-percent = 100\n",
    );
    let run = fixture.project_gate(&["--format", "json"]);
    assert!(
        run.success(),
        "advisory-only evidence exits 0: {}",
        run.transcript()
    );
    assert!(
        json_payload(&run)["gate_verdicts"]
            .as_array()
            .is_some_and(|verdicts| !verdicts.is_empty()),
        "the row produced advisory evidence: {}",
        run.stdout
    );
}

/// The parent closes its stdout reader before the child writes, so the binary
/// must report the failed write and exit 2 rather than claim success.
///
/// This row owns its repository: it is the one run here that is deliberately
/// hostile to the child, and sharing a tree with the record rows would tie
/// their result to it.
fn a_failed_write_exits_two() {
    let fixture = crossing_project();
    let refused = fixture.project_gate_with(
        &["--format", "json"],
        &RunOptions {
            capture_stdout: false,
            ..RunOptions::default()
        },
    );
    assert_write_failure(&refused);
}

fn assert_write_failure(completed: &Completed) {
    assert!(
        !completed.timed_out(),
        "a closed stdout must not hang the child: {}",
        completed.transcript()
    );
    assert_eq!(
        completed.code(),
        Some(2),
        "a write failure exits 2: {}",
        completed.transcript()
    );
    assert!(
        !completed.captured_stdout,
        "the row must close the reader, or it proves nothing about a failed write: {}",
        completed.transcript()
    );
    assert!(
        completed.stderr.contains("error writing gate output"),
        "the failure is reported on stderr: {}",
        completed.transcript()
    );
}
