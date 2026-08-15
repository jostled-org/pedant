//! The composition boundary, read from tracked production source, test source,
//! Cargo manifests, and release workflows only.
//!
//! No plan, specification, log, or lifecycle manifest is consulted here.

use std::fs;
use std::path::{Path, PathBuf};

/// The CLI gate family, which declares and re-exports only from its root.
const GATE_TREE: &str = "src/gate";

/// Every module the gate family is required to hold, sorted.
const GATE_MODULES: &[&str] = &[
    "command.rs",
    "error.rs",
    "evidence.rs",
    "mod.rs",
    "project.rs",
];

/// Every gate CLI support module, sorted.
const GATE_SUPPORT_MODULES: &[&str] = &[
    "capability_modes.rs",
    "catalog.rs",
    "ceilings.rs",
    "failures.rs",
    "fixture.rs",
    "output.rs",
    "ownership.rs",
    "project.rs",
    "semantic.rs",
    "topology.rs",
];

/// The package-shared support tree, which owns exactly one wrapper.
const PACKAGE_SUPPORT_MODULES: &[&str] = &["process_guard.rs"];

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

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    manifest_dir()
        .parent()
        .expect("the workspace root is the package parent")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is tracked: {error}", path.display()))
}

/// One tracked source with every run of whitespace collapsed to one space.
///
/// A wiring claim is about which owner receives which value, not about where
/// the formatter chose to break the line, so every call-shape assertion below
/// reads this form.
fn normalized(path: &Path) -> String {
    read(path)
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

/// Every `.rs` file directly beneath one tree, sorted by file name.
fn module_names(tree: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(tree)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", tree.display()))
        .map(|entry| entry.expect("a directory entry is readable").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .map(|path| {
            path.file_name()
                .expect("a source file has a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();
    found
}

fn assert_inventory(tree: &Path, declared: &[&str]) {
    assert_eq!(
        module_names(tree),
        declared,
        "the inventory of {} is exact",
        tree.display()
    );
}

/// File and stdin dispatch reaches the unchanged capability owner before any
/// project, snapshot, or graph construction can happen.
pub(crate) fn legacy_gate_dispatch_is_graph_free() {
    let gate = manifest_dir().join(GATE_TREE);
    for module in GATE_MODULES {
        let source = read(&gate.join(module));
        let owned = PROJECT_OWNERS.contains(module);
        for token in PROJECT_ONLY {
            assert!(
                owned || !source.contains(token),
                "{module} must not name {token}: it is not a project owner"
            );
        }
    }

    let dispatcher = read(&gate.join("command.rs"));
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
    let project = normalized(&manifest_dir().join(GATE_TREE).join("project.rs"));
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
    let command = read(&manifest_dir().join(GATE_TREE).join("command.rs"));
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

    let project = normalized(&manifest_dir().join(GATE_TREE).join("project.rs"));
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
    let source = read(&manifest_dir().join(GATE_TREE).join("error.rs"));
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
    let project = normalized(&manifest_dir().join(GATE_TREE).join("project.rs"));
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

/// The module, support, dependency, and release boundaries this design states.
pub(crate) fn repository_boundaries_are_exact() {
    assert_inventory(&manifest_dir().join(GATE_TREE), GATE_MODULES);
    assert_inventory(
        &manifest_dir().join("tests/gate_cli_support"),
        GATE_SUPPORT_MODULES,
    );
    assert_inventory(
        &manifest_dir().join("tests/package_support"),
        PACKAGE_SUPPORT_MODULES,
    );

    production_source_holds_no_tests();
    dependency_edge_is_versioned_and_ordered();
    graph_holds_no_policy_owner();
    release_only_manifest_check_is_release_only();
}

fn production_source_holds_no_tests() {
    let mut sources = Vec::new();
    collect_sources(&manifest_dir().join("src"), &mut sources);
    assert!(sources.len() > 10, "the production tree was located");
    for path in &sources {
        let source = read(path);
        assert!(
            !source.contains("#[test]") && !source.contains("mod tests"),
            "{} must hold no inline test",
            path.display()
        );
    }
}

fn collect_sources(root: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", root.display()));
    for entry in entries {
        let path = entry.expect("a directory entry is readable").path();
        match (
            path.is_dir(),
            path.extension().is_some_and(|extension| extension == "rs"),
        ) {
            (true, _) => collect_sources(&path, found),
            (false, true) => found.push(path),
            (false, false) => (),
        }
    }
}

/// The one new first-party edge is a versioned normal path dependency, and the
/// graph still releases before the CLI.
fn dependency_edge_is_versioned_and_ordered() {
    let manifest = read(&manifest_dir().join("Cargo.toml"));
    let edges: Vec<&str> = manifest
        .lines()
        .filter(|line| line.trim_start().starts_with("pedant-graph = "))
        .collect();
    assert_eq!(
        edges,
        ["pedant-graph = { version = \"0.2.0\", path = \"../pedant-graph\" }"],
        "exactly one versioned path edge to the graph package"
    );
    let (normal, rest) = manifest
        .split_once("[dev-dependencies]")
        .expect("the manifest states development dependencies");
    assert!(
        normal.contains("pedant-graph = ") && !rest.contains("pedant-graph = "),
        "the graph edge is a normal dependency"
    );

    let order = read(&workspace_root().join("release-plz.toml"));
    let graph = order
        .find("name = \"pedant-graph\"")
        .expect("the graph package is released");
    let cli = order
        .find("name = \"pedant\"\n")
        .expect("the CLI package is released");
    assert!(graph < cli, "the graph publishes before the CLI package");
}

/// Policy vocabulary the topology library may not own.
const FORBIDDEN_IN_GRAPH: &[&str] = &[
    "GateVerdict",
    "GateSeverity",
    "GateConfig",
    "ModuleBoundaryConfig",
    "ModuleBoundaryInput",
    "evaluate_module_boundary_rules",
];

fn graph_holds_no_policy_owner() {
    let mut sources = Vec::new();
    collect_sources(&workspace_root().join("pedant-graph/src"), &mut sources);
    assert!(sources.len() > 1, "the graph production tree was located");
    for path in &sources {
        let source = read(path);
        let present: Vec<&str> = FORBIDDEN_IN_GRAPH
            .iter()
            .copied()
            .filter(|token| source.contains(token))
            .collect();
        assert!(
            present.is_empty(),
            "{} must not own {present:?}",
            path.display()
        );
    }
}

/// The tagged-manifest immutability check is a release-only gate.
fn release_only_manifest_check_is_release_only() {
    let script = "check_published_manifests.sh";
    let ci = read(&workspace_root().join(".github/workflows/ci.yml"));
    assert!(
        !ci.contains(script),
        "ordinary implementation CI must not run the release-only manifest check"
    );

    let release = read(&workspace_root().join(".github/workflows/release-plz.yml"));
    let readiness = release
        .find("check_release_readiness.sh")
        .expect("the release workflow gates on readiness");
    let manifests = release
        .find(script)
        .expect("the release workflow retains the strict manifest check");
    assert!(
        readiness < manifests,
        "the strict manifest check stays behind release readiness"
    );
}
