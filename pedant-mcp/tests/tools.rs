//! Contract tests for every `pedant-mcp` tool.
//!
//! This root owns the tool surface: what each tool answers over the fixture
//! workspace, which tools are registered, and that the schema list and the
//! dispatcher read one registry. It stays one of the crate's integration
//! executables — each tool family owns a file under `tools_support/` that this
//! root declares with `#[path]`, which Cargo links into this same binary
//! instead of a new one.
//!
//! The Rust language-token predicate stays at this root: Step 1.6 selects it by
//! bare name and the owner-registration table lists it unqualified, so a module
//! path would rename it.

use pedant_mcp::registry;
use pedant_mcp::tools::{SearchByCapabilityParams, search_by_capability};
use serde_json::Value;

/// Where the committed fixture workspaces live, shared with every other root
/// that reads one. The `#[path]` is required: cargo links one test executable
/// per `tests/*.rs`, so a shared support file is declared by each root rather
/// than reached through a library.
#[path = "fixture_support/committed_fixture.rs"]
mod committed_fixture;

/// The one indexed fixture workspace, and the readers for a tool's answer.
#[path = "tools_support/tool_fixture.rs"]
mod tool_fixture;

/// What the four query tools answer over the fixture workspace.
#[path = "tools_support/query_cases.rs"]
mod query_cases;

/// What `explain_finding` answers, and the parameter name its schema states.
#[path = "tools_support/explain_cases.rs"]
mod explain_cases;

/// What `audit_crate` reports, including the flow arrays it carries.
#[path = "tools_support/audit_cases.rs"]
mod audit_cases;

/// The registered tool set, and the one registry schema and dispatch share.
#[path = "tools_support/registry_cases.rs"]
mod registry_cases;

/// What `find_structural_duplicates` groups, and what it declines to group.
#[path = "tools_support/duplicates_cases.rs"]
mod duplicates_cases;

/// What the tools report for non-Rust sources.
#[path = "tools_support/language_cases.rs"]
mod language_cases;

use tool_fixture::{fixture_index, is_error, result_text};

// ---------------------------------------------------------------------------
// Rust language token: refused with its reason, no tool-surface change
// ---------------------------------------------------------------------------

#[test]
fn rust_language_token_is_refused_without_tool_surface_change() {
    let index = fixture_index();

    // No producer tags a finding `rust`: `pedant-core` builds every Rust
    // finding with `language: None`, and `pedant-lang` answers Rust with an
    // empty profile. Accepting the token would filter every finding out and
    // return an empty array, which a caller cannot tell from "no crate uses
    // this capability" — so the refusal names the missing answer instead. The
    // published schema never listed `rust`, so no advertised input changes.
    let result = search_by_capability(
        SearchByCapabilityParams {
            pattern: "network".into(),
            language: Some("rust".into()),
        },
        &index,
    );
    assert!(
        is_error(&result),
        "the `rust` language token is refused: {}",
        result_text(&result)
    );
    assert!(
        result_text(&result).contains("Rust findings carry no language tag"),
        "the refusal says why the answer is unavailable: {}",
        result_text(&result)
    );

    // The pattern itself does match crates, so the refusal is about the token
    // and not about an empty corpus.
    let unfiltered = search_by_capability(
        SearchByCapabilityParams {
            pattern: "network".into(),
            language: None,
        },
        &index,
    );
    let unfiltered: Vec<Value> = serde_json::from_str(&result_text(&unfiltered))
        .expect("the unfiltered search returns a result array");
    assert!(
        !unfiltered.is_empty(),
        "the pattern itself matches crates without a language filter"
    );

    let unknown = search_by_capability(
        SearchByCapabilityParams {
            pattern: "network".into(),
            language: Some("ada".into()),
        },
        &index,
    );
    assert!(
        is_error(&unknown),
        "an unknown token is still refused: {}",
        result_text(&unknown)
    );

    let names: Box<[&str]> = registry::all_tools()
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect::<Vec<_>>()
        .into_boxed_slice();
    assert_eq!(
        &*names,
        [
            "query_capabilities",
            "query_gate_verdicts",
            "query_violations",
            "search_by_capability",
            "explain_finding",
            "audit_crate",
            "find_structural_duplicates",
        ],
        "the registered tool set is unchanged"
    );
    assert_eq!(
        registry::dispatchable_names().len(),
        names.len(),
        "every registered tool stays dispatchable"
    );
}
