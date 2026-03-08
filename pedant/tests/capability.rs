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

#[test]
fn test_ffi_capability_extern_block() {
    let source = r#"
extern "C" {
    fn my_c_function(x: i32) -> i32;
}
"#;
    let result = analyze("ffi.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Ffi));
    assert!(
        result
            .capabilities
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "extern block")
    );
}

#[test]
fn test_ffi_capability_link_attribute() {
    let source = include_str!("fixtures/ffi_capability.rs");
    let result = analyze("ffi_link.rs", source, &permissive_config()).unwrap();
    let ffi_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Ffi)
        .collect();
    assert!(ffi_findings.len() >= 2);
}

#[test]
fn test_ffi_capability_libc_import() {
    let source = "use libc::getpid;\n";
    let result = analyze("libc.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Ffi));
}

#[test]
fn test_unsafe_block_detected() {
    let source = r#"
fn foo() {
    let _val = unsafe { 42 };
}
"#;
    let result = analyze("unsafe_block.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::UnsafeCode));
    assert!(
        result
            .capabilities
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "unsafe block")
    );
}

#[test]
fn test_unsafe_fn_detected() {
    let source = r#"
unsafe fn dangerous() -> i32 {
    42
}
"#;
    let result = analyze("unsafe_fn.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::UnsafeCode));
    assert!(
        result
            .capabilities
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "unsafe fn")
    );
}

#[test]
fn test_unsafe_impl_detected() {
    let source = r#"
struct MyType;
unsafe impl Send for MyType {}
"#;
    let result = analyze("unsafe_impl.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::UnsafeCode));
    assert!(
        result
            .capabilities
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "unsafe impl")
    );
}

#[test]
fn test_hardcoded_url_detected() {
    let source = r#"
fn foo() {
    let _url = "https://api.example.com/v1/data";
}
"#;
    let result = analyze("url.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_hardcoded_ip_detected() {
    let source = r#"
fn foo() {
    let _ip = "192.168.1.1:8080";
}
"#;
    let result = analyze("ip.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_ipv6_detected() {
    let source = r#"
fn foo() {
    let _ip = "[::1]:8080";
}
"#;
    let result = analyze("ipv6.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_short_string_not_flagged() {
    let source = r#"
fn foo() {
    let _s = "hello";
}
"#;
    let result = analyze("short.rs", source, &permissive_config()).unwrap();
    let net_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Network)
        .collect();
    assert!(net_findings.is_empty());
}

#[test]
fn test_pem_key_material_detected() {
    let source = r#"
fn foo() {
    let _key = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----";
}
"#;
    let result = analyze("pem.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Crypto));
}

#[test]
fn test_crypto_crate_import_detected() {
    let source = "use ring::aead;\n";
    let result = analyze("ring.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Crypto));
}

#[test]
fn test_system_time_detected() {
    let source = "use std::time::SystemTime;\n";
    let result = analyze("systime.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::SystemTime));
}

#[test]
fn test_chrono_detected() {
    let source = "use chrono::Utc;\n";
    let result = analyze("chrono.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::SystemTime));
}

#[test]
fn test_proc_macro_detected() {
    let source = r#"
#[proc_macro]
fn my_macro(input: TokenStream) -> TokenStream {
    input
}
"#;
    let result = analyze("proc_macro.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::ProcMacro));
    assert!(
        result
            .capabilities
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "#[proc_macro]")
    );
}

#[test]
fn test_proc_macro_derive_detected() {
    let source = r#"
#[proc_macro_derive(Foo)]
fn my_derive(input: TokenStream) -> TokenStream {
    input
}
"#;
    let result = analyze("proc_macro_derive.rs", source, &permissive_config()).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::ProcMacro));
    assert!(
        result
            .capabilities
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "#[proc_macro_derive]")
    );
}
