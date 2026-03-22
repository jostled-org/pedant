use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

/// Spawns the pedant-mcp binary in the given directory.
fn spawn_server(cwd: &Path) -> Child {
    let binary = env!("CARGO_BIN_EXE_pedant-mcp");
    Command::new(binary)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn pedant-mcp")
}

/// Sends a JSON-RPC message via stdin (newline-delimited).
async fn send(child: &mut Child, msg: &Value) {
    let stdin = child.stdin.as_mut().expect("no stdin");
    let line = serde_json::to_string(msg).expect("serialize failed");
    stdin
        .write_all(format!("{line}\n").as_bytes())
        .await
        .expect("write failed");
    stdin.flush().await.expect("flush failed");
}

/// Reads a single JSON-RPC response line from stdout with a configurable timeout.
async fn recv_with_timeout(
    reader: &mut BufReader<tokio::process::ChildStdout>,
    timeout_secs: u64,
) -> Value {
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        reader.read_line(&mut line),
    )
    .await
    .expect("timeout reading from server")
    .expect("read failed");
    serde_json::from_str(line.trim()).unwrap_or_else(|e| {
        panic!("invalid JSON from server: {e}\nline: {line}");
    })
}

/// Reads a single JSON-RPC response line from stdout.
async fn recv(reader: &mut BufReader<tokio::process::ChildStdout>) -> Value {
    recv_with_timeout(reader, 10).await
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Sends initialize + initialized notification, returns the initialize response.
async fn initialize_with_timeout(
    child: &mut Child,
    reader: &mut BufReader<tokio::process::ChildStdout>,
    timeout_secs: u64,
) -> Value {
    let init_request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "0.1.0"
            }
        }
    });
    send(child, &init_request).await;
    let response = recv_with_timeout(reader, timeout_secs).await;

    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    send(child, &initialized).await;

    response
}

/// Sends initialize + initialized notification with default timeout.
async fn initialize(
    child: &mut Child,
    reader: &mut BufReader<tokio::process::ChildStdout>,
) -> Value {
    initialize_with_timeout(child, reader, 10).await
}

// ---------------------------------------------------------------------------
// 3.T1: stdio initialize handshake
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stdio_initialize_handshake() {
    let fixture = fixture_path("multi_crate");
    let mut child = spawn_server(&fixture);
    let stdout = child.stdout.take().expect("no stdout");
    let mut reader = BufReader::new(stdout);

    let response = initialize(&mut child, &mut reader).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(
        response["result"]["capabilities"].is_object(),
        "expected server capabilities: {response}"
    );
    assert!(
        response["result"]["serverInfo"].is_object(),
        "expected server info: {response}"
    );

    drop(child.stdin.take());
    let _ = child.wait().await;
}

// ---------------------------------------------------------------------------
// 3.T2: tools/list returns all registered tools
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stdio_tools_list() {
    let fixture = fixture_path("multi_crate");
    let mut child = spawn_server(&fixture);
    let stdout = child.stdout.take().expect("no stdout");
    let mut reader = BufReader::new(stdout);

    initialize(&mut child, &mut reader).await;

    let list_request = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    send(&mut child, &list_request).await;
    let response = recv(&mut reader).await;

    assert_eq!(response["id"], 2);
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools should be an array");
    assert!(
        tools.len() >= 6,
        "expected at least 6 tools, got {}",
        tools.len()
    );

    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in [
        "query_capabilities",
        "query_gate_verdicts",
        "query_violations",
        "search_by_capability",
        "explain_finding",
        "audit_crate",
    ] {
        assert!(
            names.contains(&expected),
            "missing tool {expected}, found: {names:?}"
        );
    }

    drop(child.stdin.take());
    let _ = child.wait().await;
}

// ---------------------------------------------------------------------------
// 3.T3: tools/call query_capabilities
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stdio_tools_call_query_capabilities() {
    let fixture = fixture_path("multi_crate");
    let mut child = spawn_server(&fixture);
    let stdout = child.stdout.take().expect("no stdout");
    let mut reader = BufReader::new(stdout);

    initialize(&mut child, &mut reader).await;

    let call_request = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "query_capabilities",
            "arguments": {
                "scope": "lib-a"
            }
        }
    });
    send(&mut child, &call_request).await;
    let response = recv(&mut reader).await;

    assert_eq!(response["id"], 3);
    let content = &response["result"]["content"];
    assert!(content.is_array(), "expected content array: {response}");

    let text = content[0]["text"].as_str().expect("expected text content");
    assert!(
        text.contains("network"),
        "expected network capability in response: {text}"
    );

    drop(child.stdin.take());
    let _ = child.wait().await;
}

// ---------------------------------------------------------------------------
// 3.T4: tools/call audit_crate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stdio_tools_call_audit_crate() {
    let fixture = fixture_path("multi_crate");
    let mut child = spawn_server(&fixture);
    let stdout = child.stdout.take().expect("no stdout");
    let mut reader = BufReader::new(stdout);

    initialize(&mut child, &mut reader).await;

    let call_request = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "audit_crate",
            "arguments": {
                "crate_name": "lib-a"
            }
        }
    });
    send(&mut child, &call_request).await;
    let response = recv(&mut reader).await;

    assert_eq!(response["id"], 4);
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("expected text content");
    let audit: Value = serde_json::from_str(text).expect("expected JSON in text content");
    assert!(
        audit.get("capabilities").is_some(),
        "expected capabilities in audit: {text}"
    );
    assert!(
        audit.get("gate_verdicts").is_some(),
        "expected gate_verdicts in audit: {text}"
    );
    assert!(
        audit.get("tier").is_some(),
        "expected tier in audit: {text}"
    );

    drop(child.stdin.take());
    let _ = child.wait().await;
}

// ---------------------------------------------------------------------------
// 3.T5: unknown tool returns error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stdio_unknown_tool_returns_error() {
    let fixture = fixture_path("multi_crate");
    let mut child = spawn_server(&fixture);
    let stdout = child.stdout.take().expect("no stdout");
    let mut reader = BufReader::new(stdout);

    initialize(&mut child, &mut reader).await;

    let call_request = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "nonexistent_tool",
            "arguments": {}
        }
    });
    send(&mut child, &call_request).await;
    let response = recv(&mut reader).await;

    assert_eq!(response["id"], 5);
    // Either an error response or a tool result with isError=true
    let has_error = response.get("error").is_some() || response["result"]["isError"] == json!(true);
    assert!(has_error, "expected error for unknown tool: {response}");

    drop(child.stdin.take());
    let _ = child.wait().await;
}

// ---------------------------------------------------------------------------
// 5.T1: self-analysis via MCP (pedant analyzes its own workspace)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_self_analysis_via_mcp() {
    // Use pedant's own workspace root (parent of pedant-mcp)
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant-mcp should be inside a workspace");

    let mut child = spawn_server(workspace_root);
    let stdout = child.stdout.take().expect("no stdout");
    let mut reader = BufReader::new(stdout);

    // Full workspace indexing takes longer than fixture tests
    initialize_with_timeout(&mut child, &mut reader, 30).await;

    // Query capabilities for pedant-core
    let cap_request = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "query_capabilities",
            "arguments": {
                "scope": "pedant-core"
            }
        }
    });
    send(&mut child, &cap_request).await;
    let cap_response = recv(&mut reader).await;

    assert_eq!(cap_response["id"], 10);
    let cap_text = cap_response["result"]["content"][0]["text"]
        .as_str()
        .expect("expected text content for capabilities");

    // pedant-core uses std::fs (FileRead) and contains crypto detection string constants (Crypto)
    assert!(
        cap_text.contains("file_read"),
        "expected file_read capability in pedant-core: {cap_text}"
    );

    // Audit pedant-core
    let audit_request = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "audit_crate",
            "arguments": {
                "crate_name": "pedant-core"
            }
        }
    });
    send(&mut child, &audit_request).await;
    let audit_response = recv(&mut reader).await;

    assert_eq!(audit_response["id"], 11);
    let audit_text = audit_response["result"]["content"][0]["text"]
        .as_str()
        .expect("expected text content for audit");
    let audit: Value = serde_json::from_str(audit_text).expect("expected JSON in audit text");

    assert!(
        audit.get("capabilities").is_some(),
        "expected capabilities in audit: {audit_text}"
    );
    assert!(
        audit.get("gate_verdicts").is_some(),
        "expected gate_verdicts in audit: {audit_text}"
    );
    assert!(
        audit.get("tier").is_some(),
        "expected tier in audit: {audit_text}"
    );

    drop(child.stdin.take());
    let _ = child.wait().await;
}

// ---------------------------------------------------------------------------
// 3.T6: binary exits with error when no workspace found
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_binary_no_workspace_exits_with_error() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let binary = env!("CARGO_BIN_EXE_pedant-mcp");

    let output = Command::new(binary)
        .current_dir(temp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("failed to run pedant-mcp");

    assert!(
        !output.status.success(),
        "expected non-zero exit code, got: {}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("workspace") || stderr.contains("Cargo.toml"),
        "expected workspace error in stderr: {stderr}"
    );
}
