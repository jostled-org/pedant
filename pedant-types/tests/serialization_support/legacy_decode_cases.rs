//! The `build_script` boolean, and the `execution_context` enum that replaced it.
//!
//! Baselines written before the split still carry the boolean, so decoding must
//! map it. The two fields can also arrive together, and then they either agree
//! or the document is self-contradictory — accepting the contradiction would
//! pick one silently, so it is a decode error instead.

use pedant_types::{CapabilityFinding, ExecutionContext};

#[test]
fn capability_finding_build_script_migration() {
    // Legacy JSON with "build_script": true should deserialize to BuildHook
    let legacy_json = r#"{
        "capability": "network",
        "location": {"file": "build.rs", "line": 10, "column": 1},
        "evidence": "reqwest::get",
        "build_script": true
    }"#;
    let finding: CapabilityFinding = serde_json::from_str(legacy_json).unwrap();
    assert_eq!(
        finding.execution_context,
        Some(ExecutionContext::BuildHook),
        "build_script: true should map to ExecutionContext::BuildHook"
    );
    assert!(finding.language.is_none());

    // Legacy JSON with "build_script": false should deserialize to None
    let legacy_false = r#"{
        "capability": "file_read",
        "location": {"file": "src/lib.rs", "line": 5, "column": 1},
        "evidence": "std::fs::read",
        "build_script": false
    }"#;
    let finding_false: CapabilityFinding = serde_json::from_str(legacy_false).unwrap();
    assert_eq!(finding_false.execution_context, None);

    // Consistent legacy and new fields may coexist.
    let both_consistent_json = r#"{
        "capability": "network",
        "location": {"file": "build.rs", "line": 10, "column": 1},
        "evidence": "reqwest::get",
        "build_script": true,
        "execution_context": "build_hook"
    }"#;
    let finding_both: CapabilityFinding = serde_json::from_str(both_consistent_json).unwrap();
    assert_eq!(
        finding_both.execution_context,
        Some(ExecutionContext::BuildHook)
    );

    // Contradictory legacy and new fields are rejected.
    let both_json = r#"{
        "capability": "network",
        "location": {"file": "build.rs", "line": 10, "column": 1},
        "evidence": "reqwest::get",
        "build_script": true,
        "execution_context": "runtime"
    }"#;
    let error = serde_json::from_str::<CapabilityFinding>(both_json)
        .expect_err("contradictory execution_context and build_script should fail");
    assert!(
        error
            .to_string()
            .contains("contradicts legacy build_script=true"),
        "unexpected error: {error}"
    );
}

#[test]
fn capability_finding_rejects_build_hook_with_legacy_false() {
    let contradictory_json = r#"{
        "capability": "network",
        "location": {"file": "build.rs", "line": 10, "column": 1},
        "evidence": "reqwest::get",
        "build_script": false,
        "execution_context": "build_hook"
    }"#;

    let error = serde_json::from_str::<CapabilityFinding>(contradictory_json)
        .expect_err("build_hook with build_script=false should fail");
    assert!(
        error
            .to_string()
            .contains("contradicts legacy build_script=false"),
        "unexpected error: {error}"
    );
}
