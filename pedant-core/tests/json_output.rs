use std::sync::Arc;

use pedant_core::json_format::JsonViolation;
use pedant_core::violation::{Violation, ViolationType};

fn make_violations() -> Vec<Violation> {
    vec![
        Violation::new(
            ViolationType::MaxDepth,
            Arc::from("foo.rs"),
            5,
            1,
            "nesting depth 4 exceeds limit 3".to_string(),
        ),
        Violation::new(
            ViolationType::ForbiddenCall {
                pattern: Arc::from("unwrap"),
            },
            Arc::from("bar.rs"),
            10,
            8,
            "forbidden call: unwrap".to_string(),
        ),
    ]
}

#[test]
fn json_output_has_expected_fields() {
    let violations = make_violations();
    let json_violations: Vec<JsonViolation<'_>> =
        violations.iter().map(JsonViolation::from).collect();
    let serialized = serde_json::to_value(&json_violations).unwrap();
    let parsed = serialized.as_array().unwrap();

    assert_eq!(parsed.len(), 2);

    let first = &parsed[0];
    assert_eq!(first["type"], "max-depth");
    assert_eq!(first["check"], "max-depth");
    assert_eq!(first["category"], "nesting");
    assert_eq!(first["file"], "foo.rs");
    assert_eq!(first["line"], 5);
    assert_eq!(first["column"], 1);
    assert!(first["message"].as_str().unwrap().contains("nesting depth"));
    assert!(first.get("pattern").is_none());

    let second = &parsed[1];
    assert_eq!(second["type"], "forbidden-call");
    assert_eq!(second["check"], "forbidden-call");
    assert_eq!(second["category"], "forbid_calls");
    assert_eq!(second["pattern"], "unwrap");
}

#[test]
fn json_output_empty_violations() {
    let violations: Vec<Violation> = vec![];
    let json_violations: Vec<JsonViolation<'_>> =
        violations.iter().map(JsonViolation::from).collect();
    let serialized = serde_json::to_value(&json_violations).unwrap();
    let parsed = serialized.as_array().unwrap();

    assert!(parsed.is_empty());
}
