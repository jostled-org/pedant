//! Regression tests for issue #57: the MCP index must honor `.pedant.toml`
//! check config, run the project-level checks, and expose violation severity.

use std::fs;
use std::path::Path;

use pedant_mcp::index::WorkspaceIndex;
use pedant_mcp::tools::{QueryViolationsParams, query_violations};
use serde_json::Value;

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

/// Build a single-member workspace named `demo` with the given `.pedant.toml`
/// and library source, returning the temp dir (kept alive) and the index.
fn workspace_with(
    pedant_toml: &str,
    files: &[(&str, &str)],
) -> (tempfile::TempDir, WorkspaceIndex) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(
        &root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"demo\"]\n",
    );
    write_file(
        &root.join("demo/Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(&root.join(".pedant.toml"), pedant_toml);
    for (rel, contents) in files {
        write_file(&root.join(rel), contents);
    }
    let index = WorkspaceIndex::build(root, None).unwrap();
    (tmp, index)
}

fn violations_json(scope: &str, index: &WorkspaceIndex) -> Value {
    let result = query_violations(
        QueryViolationsParams {
            scope: scope.into(),
            check: None,
            category: None,
        },
        index,
    );
    assert_ne!(result.is_error, Some(true), "query_violations errored");
    let text: String = result
        .content
        .iter()
        .filter_map(|c| match c {
            rmcp::model::ContentBlock::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect();
    serde_json::from_str(&text).expect("violations output is valid JSON")
}

/// Defect 1: a check enabled ONLY via `.pedant.toml` must fire through MCP.
/// Before the fix the index built with `Config::default()`, so `forbid_calls`
/// never ran and this violation never appeared.
#[test]
fn forbid_calls_from_config_is_honored() {
    let toml = "[forbid_calls]\nenabled = true\npatterns = [\".unwrap()\"]\n";
    let src = "pub fn parse(s: &str) -> usize { s.parse::<usize>().unwrap() }\n";
    let (_tmp, index) = workspace_with(toml, &[("demo/src/lib.rs", src)]);

    let violations = violations_json("demo", &index);
    let items = violations.as_array().expect("array of violations");
    let has_forbidden_call = items
        .iter()
        .any(|v| v["check"].as_str() == Some("forbidden-call"));
    assert!(
        has_forbidden_call,
        "expected a forbidden-call violation from the configured forbid_calls rule, got: {violations}"
    );
}

/// Defect 2: a project-level check (conflicting-module-root, which only runs via
/// `check_project`) must surface through MCP's workspace scope. It also defaults
/// off, so this simultaneously proves the config is honored.
#[test]
fn project_level_conflicting_module_root_surfaces() {
    let toml = "check_conflicting_module_root = true\n";
    let files = [
        ("demo/src/lib.rs", "pub mod foo;\n"),
        ("demo/src/foo.rs", "pub fn a() {}\n"),
        ("demo/src/foo/mod.rs", "pub fn b() {}\n"),
    ];
    let (_tmp, index) = workspace_with(toml, &files);

    let violations = violations_json("workspace", &index);
    let items = violations.as_array().expect("array of violations");
    let has_conflict = items
        .iter()
        .any(|v| v["check"].as_str() == Some("conflicting-module-root"));
    assert!(
        has_conflict,
        "expected a conflicting-module-root project violation, got: {violations}"
    );
}

/// Issue #63: the cross-file type-footprint check (#56) must run through MCP.
/// A type whose inherent methods span two files is a god-object the per-file
/// pass cannot see; only the project pass, given every file's shape, catches it.
/// Before shapes were threaded, MCP passed `file_shapes: &[]` and this produced
/// nothing.
#[test]
fn cross_file_high_method_count_surfaces() {
    let toml = "check_high_method_count = true\nmax_methods = 3\n";
    let methods_a = (0..3)
        .map(|i| format!("    pub fn a{i}(&self) -> usize {{ self.n + {i} }}"))
        .collect::<Vec<_>>()
        .join("\n");
    let methods_b = (0..3)
        .map(|i| format!("    pub fn b{i}(&self) -> usize {{ self.n + {i} }}"))
        .collect::<Vec<_>>()
        .join("\n");
    let files = [
        (
            "demo/src/lib.rs",
            "pub mod a;\npub mod b;\npub struct God { pub n: usize }\n",
        ),
        (
            "demo/src/a.rs",
            &format!("use super::God;\nimpl God {{\n{methods_a}\n}}\n"),
        ),
        (
            "demo/src/b.rs",
            &format!("use super::God;\nimpl God {{\n{methods_b}\n}}\n"),
        ),
    ];
    let (_tmp, index) = workspace_with(toml, &files);

    let violations = violations_json("workspace", &index);
    let items = violations.as_array().expect("array of violations");
    let has_god_object = items
        .iter()
        .any(|v| v["check"].as_str() == Some("high-method-count"));
    assert!(
        has_god_object,
        "expected a cross-file high-method-count violation (6 methods over the limit of 3), got: {violations}"
    );
}

/// Defect 3: every violation carries a `severity` field, serialized lowercase.
#[test]
fn violations_expose_severity() {
    let toml = "[forbid_calls]\nenabled = true\npatterns = [\".unwrap()\"]\n";
    let src = "pub fn parse(s: &str) -> usize { s.parse::<usize>().unwrap() }\n";
    let (_tmp, index) = workspace_with(toml, &[("demo/src/lib.rs", src)]);

    let violations = violations_json("demo", &index);
    let first = &violations.as_array().expect("array")[0];
    let severity = first
        .get("severity")
        .expect("violation output must include a severity field");
    assert!(
        matches!(severity.as_str(), Some("warn" | "deny")),
        "severity must serialize as a lowercase label, got: {severity}"
    );
}
