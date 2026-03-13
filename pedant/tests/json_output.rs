use std::sync::Arc;

use pedant::reporter::{OutputFormat, Reporter};
use pedant::violation::{Violation, ViolationType};

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
    let reporter = Reporter::new(OutputFormat::Json, false);
    let mut buf = Vec::new();
    reporter.report(&violations, &mut buf).unwrap();

    let parsed: Vec<serde_json::Value> = serde_json::from_slice(&buf).unwrap();
    assert_eq!(parsed.len(), 2);

    let first = &parsed[0];
    assert_eq!(first["type"], "max-depth");
    assert_eq!(first["check"], "nesting");
    assert_eq!(first["file"], "foo.rs");
    assert_eq!(first["line"], 5);
    assert_eq!(first["column"], 1);
    assert!(first["message"].as_str().unwrap().contains("nesting depth"));
    assert!(first.get("pattern").is_none());

    let second = &parsed[1];
    assert_eq!(second["type"], "forbidden-call");
    assert_eq!(second["check"], "forbid_calls");
    assert_eq!(second["pattern"], "unwrap");
}

#[test]
fn json_output_empty_violations() {
    let reporter = Reporter::new(OutputFormat::Json, false);
    let mut buf = Vec::new();
    reporter.report(&[], &mut buf).unwrap();

    let parsed: Vec<serde_json::Value> = serde_json::from_slice(&buf).unwrap();
    assert!(parsed.is_empty());
}
