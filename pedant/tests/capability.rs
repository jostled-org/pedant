use pedant::visitor::{CheckConfig, analyze};
use pedant_types::Capability;

fn permissive_config() -> CheckConfig {
    CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

#[test]
fn test_network_capability_detected() {
    let source = include_str!("fixtures/network_capability.rs");
    let result = analyze("network_capability.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_filesystem_capability_detected() {
    let source = include_str!("fixtures/filesystem_capability.rs");
    let result = analyze("filesystem_capability.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::FileRead));
}

#[test]
fn test_process_capability_detected() {
    let source = include_str!("fixtures/process_capability.rs");
    let result = analyze("process_capability.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::ProcessExec));
}

#[test]
fn test_env_capability_detected() {
    let source = include_str!("fixtures/env_capability.rs");
    let result = analyze("env_capability.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::EnvAccess));
}

#[test]
fn test_clean_code_no_capabilities() {
    let source = include_str!("fixtures/clean.rs");
    let result = analyze("clean.rs", source, &permissive_config()).unwrap();

    assert!(result.capabilities.findings.is_empty());
}

#[test]
fn test_multiple_capabilities_detected() {
    let source = r#"
use std::net::TcpStream;
use std::fs;

fn do_things() {
    let _stream = TcpStream::connect("127.0.0.1:80");
    let _content = fs::read_to_string("file.txt");
}
"#;
    let result = analyze("multi.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::Network));
    assert!(caps.contains(&Capability::FileRead));
}

#[test]
fn test_glob_use_detected() {
    let source = "use std::net::*;\n";
    let result = analyze("glob.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_fs_write_function_detected() {
    let source = r#"
fn write_file() {
    let _ = std::fs::write("out.txt", "data");
}
"#;
    let result = analyze("fs_write.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::FileWrite));
    assert!(!caps.contains(&Capability::FileRead));
}

#[test]
fn test_third_party_network_crate() {
    let source = "use reqwest::Client;\n";
    let result = analyze("reqwest.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_grouped_use_detected() {
    let source = "use std::process::{Command, Stdio};\n";
    let result = analyze("grouped.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::ProcessExec));
}

#[test]
fn test_finding_has_correct_evidence() {
    let source = "use std::net::TcpStream;\n";
    let result = analyze("evidence.rs", source, &permissive_config()).unwrap();

    assert_eq!(result.capabilities.findings.len(), 1);
    assert_eq!(
        result.capabilities.findings[0].evidence.as_ref(),
        "std::net::TcpStream"
    );
    assert_eq!(
        result.capabilities.findings[0].capability,
        Capability::Network
    );
}
