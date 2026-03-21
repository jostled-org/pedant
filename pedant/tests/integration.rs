mod common;

#[test]
fn test_let_underscore_result_in_list_checks() {
    let output = common::run_pedant(&["--list-checks"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(
        stdout.contains("let-underscore-result"),
        "expected --list-checks to include let-underscore-result, got:\n{stdout}"
    );
}

#[test]
fn test_let_underscore_result_explain() {
    let output = common::run_pedant(&["--explain", "let-underscore-result"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(
        stdout.contains("Result"),
        "expected --explain output to mention Result, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Silently discarding"),
        "expected --explain output to contain the problem description, got:\n{stdout}"
    );
}
