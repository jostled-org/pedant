//! The composition boundary of the gate family, read from tracked production
//! source only.
//!
//! No plan, specification, log, or lifecycle manifest is consulted here.

use crate::boundaries::GATE_MODULES;
use crate::source::{gate_module, manifest_dir, normalized, read};

/// Topology and project vocabulary only the project owner may name.
const PROJECT_ONLY: &[&str] = &[
    "pedant_graph",
    "RustProject",
    "snapshot_resolution",
    "RustResolver",
    "ResolutionLimits",
];

/// The gate modules allowed to name that vocabulary at all: the orchestration
/// owner, the projection owner, and the refusals that carry their sources.
const PROJECT_OWNERS: &[&str] = &["project.rs", "evidence.rs", "error.rs"];

/// File and stdin dispatch reaches the unchanged capability owner before any
/// project, snapshot, or graph construction can happen.
pub(crate) fn legacy_gate_dispatch_is_graph_free() {
    for module in GATE_MODULES {
        let source = read(&gate_module(module));
        let owned = PROJECT_OWNERS.contains(module);
        for token in PROJECT_ONLY {
            assert!(
                owned || !source.contains(token),
                "{module} must not name {token}: it is not a project owner"
            );
        }
    }

    let dispatcher = read(&gate_module("command.rs"));
    let dispatch = dispatcher
        .split_once("pub(crate) fn run(args: GateArgs")
        .map(|(_, tail)| tail)
        .expect("the gate family states one dispatch entry point");
    let selection = dispatch
        .find("args.input.project")
        .expect("dispatch selects on the project argument");
    let files = dispatch
        .find("run_files")
        .expect("dispatch names the file and stdin owner");
    assert!(
        selection < files,
        "the input mode is selected before either owner runs"
    );

    for module in ["command.rs", "config.rs", "input.rs", "analysis/files.rs"] {
        let source = read(&manifest_dir().join("src").join(module));
        assert!(
            !source.contains("pedant_graph"),
            "{module} must not name a topology type before dispatch"
        );
    }
}

/// Resolution uses its own defaults, every selected target is snapshotted, and
/// unused analysis work limits are zero.
pub(crate) fn project_pipeline_wiring_is_exact() {
    let project = normalized(&gate_module("project.rs"));
    for (claim, call) in [
        (
            "project loading uses the resolution owner's own defaults",
            "RustProject::load(canonical, ResolutionLimits::default())",
        ),
        (
            "every selected target reaches the resolution snapshot",
            ".snapshot_resolution(target.id)",
        ),
        (
            "graph construction receives the node, reference, and raw-edge ceilings",
            "GraphLimits::new( config.max_nodes(), config.max_references(), config.max_edges(), )",
        ),
        (
            "analysis receives its ceilings with traversal and betweenness work at zero",
            "GraphAnalysisLimits::new(config.max_nodes(), config.max_selected_edges(), 0, 0)",
        ),
    ] {
        assert!(project.contains(call), "{claim}: {call} is absent");
    }
    assert!(
        !project.contains("code_relations()"),
        "the selection is stated explicitly rather than taken from the graph's own preset"
    );
}

/// Every project failure reaches one buffered exit-2 owner, and no enablement
/// switch is read before validated projection returns.
pub(crate) fn project_failures_reach_one_exit_owner() {
    let command = read(&gate_module("command.rs"));
    let owner = command
        .split_once("fn run_project(")
        .map(|(_, tail)| tail)
        .expect("the project owner states one entry point");
    let owner = owner
        .split_once("fn run_files(")
        .map(|(head, _)| head)
        .expect("the file owner follows it");
    assert_eq!(
        owner.matches("ExitCode::from(2)").count(),
        1,
        "every project refusal reaches one exit-2 construction site"
    );
    assert!(
        owner.contains("write_project_gate_output"),
        "a successful run reaches the one project output owner"
    );

    let project = normalized(&gate_module("project.rs"));
    let evaluation = project
        .find("evaluate_module_boundary_rules(&input, config)")
        .expect("policy is applied through the core evaluator");
    let projection = project
        .find("evidence::project_target(&analysis")
        .expect("validated projection precedes it");
    assert!(
        projection < evaluation,
        "enablement is consulted only after validated projection returns"
    );
    assert!(
        !project.contains(".enabled") && !project.contains("module_boundary.enabled()"),
        "neither the master nor the nested switch is read by the pipeline owner"
    );
}

/// Every refusal a named case outside `failures::FAILURE_ROWS` covers, in the
/// order of `missing_project_root_is_fatal`,
/// `explicit_config_failures_are_fatal`, and the Tier 2 journey.
const REFUSALS_COVERED_ELSEWHERE: &[&str] = &["ProjectRoot", "Config", "SemanticContext"];

/// Every refusal only a broken internal invariant reaches, so no repository
/// states one: a target naming a package the project authority never minted,
/// and an analysis and a projection that disagree about the topology they read.
const DEFENSIVE_REFUSALS: &[&str] = &["UnknownPackage", "Evidence"];

fn declared_refusals() -> Vec<String> {
    let source = read(&gate_module("error.rs"));
    let (_, body) = source
        .split_once("pub(crate) enum ProjectGateError {")
        .expect("the project refusal enum is declared once");
    body.lines()
        .take_while(|line| *line != "}")
        .filter_map(|line| line.strip_prefix("    "))
        .filter_map(|line| line.strip_suffix(" {"))
        .filter(|name| name.chars().all(char::is_alphanumeric))
        .map(str::to_owned)
        .collect()
}

/// Every project refusal is proved by a failure row, by a named case beside
/// them, or is declared defensive — exactly once.
///
/// The inventory is read from the enum's own source and compared as a whole
/// set, so an eleventh variant fails here rather than arriving uncovered.
pub(crate) fn every_project_refusal_is_covered_or_defensive() {
    let mut claimed: Vec<&str> = crate::failures::covered_refusals();
    claimed.extend_from_slice(REFUSALS_COVERED_ELSEWHERE);
    claimed.extend_from_slice(DEFENSIVE_REFUSALS);
    claimed.sort_unstable();
    let mut declared = declared_refusals();
    declared.sort_unstable();
    assert_eq!(claimed, declared, "every project refusal is covered once");
}

/// The record writers that may not own an evidence grammar of their own.
const RECORD_WRITERS: &[&str] = &["reporter.rs", "github.rs"];

/// Evidence vocabulary only the output description owner may name.
const DESCRIPTION_ONLY: &[&str] = &[
    "serde_json",
    "GateEvidence",
    "ModuleBoundary",
    "verdict.evidence",
];

/// One project output description serves all three formats, every arm routes its
/// failure through an error-mapping owner, and the target list is project-only.
///
/// The operator rows beside this one compare the emitted bytes; they cannot see
/// that text and GitHub reach one serializer rather than two agreeing ones, nor
/// that the text and GitHub arms map a write failure at all — only the JSON arm
/// is reachable through a closed pipe. This states both.
pub(crate) fn project_output_is_one_description_owner() {
    let source = manifest_dir().join("src");
    let output = normalized(&source.join("output.rs"));
    let description = output
        .split_once("fn write_project_gate_output(")
        .map(|(_, tail)| tail)
        .expect("one project output description exists")
        .split_once("fn write_attestation_output(")
        .map(|(head, _)| head)
        .expect("the attestation owner follows it");

    for (claim, call) in [
        (
            "the text arm reaches the project reporter",
            "crate::reporter::report_project_gate(tier, targets, verdicts, stdout)",
        ),
        (
            "the GitHub arm reaches the project annotation writer",
            "crate::github::write_project_gate(tier, targets, verdicts, stdout)",
        ),
        (
            "the target list is carried by the project envelope",
            "analyzed_targets: Some(",
        ),
    ] {
        assert_eq!(
            description.matches(call).count(),
            1,
            "{claim}: {call} appears once"
        );
    }
    for (owner, expected) in [("map_io_error(", 2), ("write_json(", 1)] {
        assert_eq!(
            description.matches(owner).count(),
            expected,
            "{owner} carries exactly {expected} of the three format write failures"
        );
    }
    assert_eq!(
        output.matches("analyzed_targets: Some(").count(),
        1,
        "no legacy envelope may publish a target list"
    );
    assert_eq!(
        output.matches("serde_json::to_string").count(),
        1,
        "the compact spelling has one serialization owner"
    );

    for module in RECORD_WRITERS {
        let writer = normalized(&source.join(module));
        for token in DESCRIPTION_ONLY {
            assert!(
                !writer.contains(token),
                "{module} must not name {token}: evidence is described once, upstream"
            );
        }
        assert_eq!(
            writer
                .matches("crate::output::evidence_fields(verdict)")
                .count(),
            1,
            "{module} spells evidence through the one shared suffix owner"
        );
    }
    assert_eq!(
        normalized(&source.join("github.rs"))
            .matches("crate::output::subject_location(verdict)")
            .count(),
        1,
        "an annotation anchors through the one subject-location owner"
    );
}

/// One semantic context is loaded before target iteration and borrowed by every
/// target.
#[cfg(feature = "semantic")]
pub(crate) fn semantic_context_is_loaded_once_before_iteration() {
    let project = normalized(&gate_module("project.rs"));
    assert_eq!(
        project.matches("SemanticContext::load(").count(),
        1,
        "exactly one semantic context is ever loaded"
    );
    let load = project
        .find("let context = tier_context(&canonical, semantic)?;")
        .expect("the context is loaded in the project entry point");
    let iteration = project
        .find("let verdicts = buffered_verdicts(")
        .expect("target iteration follows it");
    assert!(
        load < iteration,
        "the context is loaded before any target is judged"
    );
    assert!(
        project.contains("context: &TierContext,"),
        "the same context is borrowed by every target"
    );
}
