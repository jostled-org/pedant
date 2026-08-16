use pedant_mcp::index::{WorkspaceIndex, discover_workspace_root};
use pedant_types::{AnalysisTier, Capability};

/// Repository fixture for the shared Cargo project authority. The `#[path]` is
/// required: cargo links one test executable per `tests/*.rs`, so the support
/// tree must stay a sibling directory rather than become a root of its own.
#[path = "index_support/project_fixture.rs"]
mod project_fixture;

/// The temporary workspaces these cases index. Same `#[path]` reason.
#[path = "index_support/workspace_fixtures.rs"]
mod workspace_fixtures;

/// Where the committed fixture workspaces live, shared with every other root
/// that reads one. Same `#[path]` reason.
#[path = "fixture_support/committed_fixture.rs"]
mod committed_fixture;

/// A writable copy of one of those, shared with `watcher.rs`. Same `#[path]`
/// reason.
#[path = "fixture_support/writable_fixture.rs"]
mod writable_fixture;

/// Incremental reindex behavior. Same `#[path]` reason.
#[path = "index_support/reindex_cases.rs"]
mod reindex_cases;

/// The attribution status the index stores per non-Rust file. Same `#[path]`
/// reason.
#[path = "index_support/attribution_cases.rs"]
mod attribution_cases;

use crate::committed_fixture::fixture_path;
use crate::workspace_fixtures::{
    make_glob_workspace, make_nested_glob_workspace, make_single_crate_workspace,
    make_workspace_with_go_generator,
};

#[test]
fn test_index_discovers_workspace_crates() {
    let root = fixture_path("multi_crate");
    let index = WorkspaceIndex::build(&root, None).unwrap();

    let names: Box<[&str]> = index.crate_names().collect::<Vec<_>>().into_boxed_slice();
    assert!(names.contains(&"lib-a"), "missing lib-a: {names:?}");
    assert!(names.contains(&"lib-b"), "missing lib-b: {names:?}");
}

#[test]
fn test_index_caches_analysis_results() {
    let root = fixture_path("multi_crate");
    let index = WorkspaceIndex::build(&root, None).unwrap();

    let profile = index.crate_profile("lib-a").expect("lib-a not indexed");
    let caps = profile.capabilities();
    assert!(
        caps.contains(&Capability::Network),
        "expected Network capability in lib-a, found: {caps:?}"
    );
}

#[test]
fn test_index_aggregates_crate_profile() {
    let root = fixture_path("multi_crate");
    let index = WorkspaceIndex::build(&root, None).unwrap();

    let profile = index.crate_profile("lib-a").expect("lib-a not indexed");
    let caps = profile.capabilities();
    assert!(
        caps.contains(&Capability::Network),
        "expected Network in lib-a, found: {caps:?}"
    );
    assert!(
        caps.contains(&Capability::FileRead),
        "expected FileRead in lib-a, found: {caps:?}"
    );
}

#[test]
fn test_index_empty_workspace() {
    let root = fixture_path("empty_workspace");
    let index = WorkspaceIndex::build(&root, None).unwrap();

    let names: Box<[&str]> = index.crate_names().collect::<Vec<_>>().into_boxed_slice();
    assert!(names.is_empty(), "expected no crates, found: {names:?}");
}

#[test]
fn test_index_builds_single_crate_workspace() {
    let root = make_single_crate_workspace();
    let index = WorkspaceIndex::build(root.path(), None).unwrap();

    let names: Box<[&str]> = index.crate_names().collect::<Vec<_>>().into_boxed_slice();
    assert_eq!(&*names, &["single-crate"]);
}

#[test]
fn test_index_analyzes_go_source_and_generate_directives() {
    let root = make_workspace_with_go_generator();
    let index = WorkspaceIndex::build(root.path(), None).unwrap();

    let profile = index
        .crate_profile("go-generator")
        .expect("go-generator not indexed");

    assert!(
        profile.capabilities().contains(&Capability::Network),
        "expected Go import capability in aggregate profile"
    );
    assert!(
        profile.findings.iter().any(|finding| {
            finding.capability == Capability::ProcessExec
                && finding.execution_context == Some(pedant_types::ExecutionContext::Generator)
        }),
        "expected go:generate finding in aggregate profile"
    );
}

#[test]
fn test_index_builds_glob_workspace_member_patterns() {
    let root = make_glob_workspace();
    let index = WorkspaceIndex::build(root.path(), None).unwrap();

    let names: Box<[&str]> = index.crate_names().collect::<Vec<_>>().into_boxed_slice();
    assert_eq!(&*names, &["fs-util", "http-util"]);
}

#[test]
fn test_index_builds_nested_glob_workspace_member_patterns() {
    let root = make_nested_glob_workspace();
    let index = WorkspaceIndex::build(root.path(), None).unwrap();

    let names: Box<[&str]> = index.crate_names().collect::<Vec<_>>().into_boxed_slice();
    assert_eq!(&*names, &["alpha-member", "beta-member"]);
}

#[test]
fn mcp_project_discovery_uses_shared_members_and_preserves_recursive_index() {
    let tmp = project_fixture::build_project_workspace();
    let index = WorkspaceIndex::build(tmp.path(), None).unwrap();

    let names: Box<[&str]> = index.crate_names().collect::<Vec<_>>().into_boxed_slice();
    assert_eq!(
        &*names,
        &["member", "root-app"],
        "member discovery must include the root package and exclude non-members"
    );

    let root_caps = index
        .crate_profile("root-app")
        .expect("the root package is a workspace member")
        .capabilities();
    assert!(
        root_caps.contains(&Capability::FileRead),
        "the root package's own sources must be analyzed, found: {root_caps:?}"
    );

    let sibling = tmp
        .path()
        .join("crates/member/src/deep/nested/sibling.rs")
        .to_string_lossy()
        .into_owned();
    assert!(
        index.file_result(&sibling).is_some(),
        "the recursive src/**/*.rs walk must retain undeclared sibling sources"
    );
    let member_caps = index
        .crate_profile("member")
        .expect("member is a workspace member")
        .capabilities();
    assert!(
        member_caps.contains(&Capability::Network),
        "the nested sibling's capabilities must reach the crate profile, found: {member_caps:?}"
    );
}

#[test]
fn test_index_reports_typed_syntactic_tier() {
    let root = fixture_path("multi_crate");
    let index = WorkspaceIndex::build(&root, None).unwrap();

    assert_eq!(index.crate_tier("lib-a"), AnalysisTier::Syntactic);
}

#[test]
fn test_index_gate_verdicts() {
    let root = fixture_path("multi_crate");
    let index = WorkspaceIndex::build(&root, None).unwrap();

    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    let rules: Box<[&str]> = verdicts
        .iter()
        .map(|v| v.rule)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    assert!(
        rules.contains(&"build-script-network"),
        "expected build-script-network verdict, found: {rules:?}"
    );
}

#[test]
fn test_workspace_discovery_from_subdirectory() {
    let root = fixture_path("multi_crate");
    let subdir = root.join("lib-a/src");

    let discovered = discover_workspace_root(&subdir)
        .unwrap()
        .expect("should discover workspace root from subdirectory");

    assert_eq!(
        discovered.canonicalize().unwrap(),
        root.canonicalize().unwrap(),
    );
}
