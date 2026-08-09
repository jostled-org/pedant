//! Every workspace, source text, configuration, and shared assertion the
//! semantic cases read.
//!
//! Stated once. A case that built its own fixture could differ from its
//! neighbours in a second way and pass or fail for the wrong reason.
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use pedant_core::SemanticFileAnalysis;
use pedant_core::check_config::CheckConfig;
use pedant_core::ir;
use pedant_core::ir::DataFlowKind;

use crate::semantic_context_fixture::TestSemanticContext;

pub(crate) fn load_semantic_context(root: &Path) -> Option<TestSemanticContext> {
    crate::semantic_context_fixture::load_semantic_context(root)
}

pub(crate) fn load_fresh_semantic_context(root: &Path) -> Option<TestSemanticContext> {
    crate::semantic_context_fixture::load_fresh_semantic_context(root)
}

pub(crate) fn fixture_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("semantic_workspace")
}

pub(crate) fn fixture_lib_path() -> String {
    fixture_workspace_root()
        .join("src")
        .join("lib.rs")
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn parse_fixture() -> syn::File {
    let lib_path = fixture_workspace_root().join("src").join("lib.rs");
    let source = std::fs::read_to_string(&lib_path).expect("fixture lib.rs should exist");
    syn::parse_file(&source).expect("fixture should parse")
}

pub(crate) fn dataflow_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("dataflow_workspace")
}

pub(crate) fn dataflow_lib_path() -> String {
    dataflow_workspace_root()
        .join("src")
        .join("lib.rs")
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn fixture_source() -> String {
    let lib_path = fixture_workspace_root().join("src").join("lib.rs");
    std::fs::read_to_string(&lib_path).expect("fixture lib.rs should exist")
}

pub(crate) fn clone_in_loop_config() -> CheckConfig {
    CheckConfig {
        check_clone_in_loop: true,
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

pub(crate) fn default_hasher_config() -> CheckConfig {
    CheckConfig {
        check_default_hasher: true,
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

pub(crate) fn dataflow_source() -> String {
    let lib_path = dataflow_workspace_root().join("src").join("lib.rs");
    std::fs::read_to_string(&lib_path).expect("dataflow lib.rs should exist")
}

/// Which of a function summary's three issue lists a row reads.
pub(crate) enum IssueCategory {
    /// Dead stores, discarded results, and the rest of the quality set.
    Quality,
    /// Repeated calls, clones, allocations, and collects.
    Performance,
    /// Locks and spawns.
    Concurrency,
}

/// Load the dataflow fixture's file analysis (shared across tests).
pub(crate) fn dataflow_file_analysis() -> Arc<SemanticFileAnalysis> {
    static ANALYSIS: OnceLock<Arc<SemanticFileAnalysis>> = OnceLock::new();

    Arc::clone(ANALYSIS.get_or_init(|| {
        let root = dataflow_workspace_root();
        let context = load_semantic_context(&root).expect("dataflow workspace should load");
        let file = dataflow_lib_path();
        context
            .analyze_file(&file)
            .expect("should produce file analysis")
    }))
}

/// Assert that `fn_name` produces exactly `expected` findings of `kind`
/// in the given issue category. Panics with a descriptive message on mismatch.
pub(crate) fn assert_function_issue_count(
    analysis: &SemanticFileAnalysis,
    fn_name: &str,
    category: IssueCategory,
    kind: DataFlowKind,
    expected: usize,
) {
    let summary = analysis
        .function(fn_name)
        .unwrap_or_else(|| panic!("should find {fn_name}"));
    let facts = match category {
        IssueCategory::Quality => summary.quality_issues(),
        IssueCategory::Performance => summary.performance_issues(),
        IssueCategory::Concurrency => summary.concurrency_issues(),
    };
    let matched: Vec<_> = facts.iter().filter(|f| f.kind == kind).collect();
    assert_eq!(
        matched.len(),
        expected,
        "expected {expected} {kind:?} in {fn_name}(), got: {matched:?}"
    );
}

pub(crate) fn count_by_kind(
    facts: &[ir::DataFlowFact],
) -> std::collections::BTreeMap<Box<str>, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for fact in facts {
        *counts
            .entry(format!("{:?}", fact.kind).into_boxed_str())
            .or_insert(0) += 1;
    }
    counts
}
