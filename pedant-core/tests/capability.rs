use pedant_core::capabilities::{detect_capabilities, truncate_evidence};
use pedant_core::check_config::CheckConfig;
use pedant_core::ir;
use pedant_core::lint::analyze;
use pedant_types::{Capability, FindingOrigin};

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
    let result = analyze("network_capability.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_filesystem_capability_detected() {
    let source = include_str!("fixtures/filesystem_capability.rs");
    let result = analyze(
        "filesystem_capability.rs",
        source,
        &permissive_config(),
        None,
    )
    .unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::FileRead));
}

#[test]
fn test_process_capability_detected() {
    let source = include_str!("fixtures/process_capability.rs");
    let result = analyze("process_capability.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::ProcessExec));
}

#[test]
fn test_env_capability_detected() {
    let source = include_str!("fixtures/env_capability.rs");
    let result = analyze("env_capability.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::EnvAccess));
}

#[test]
fn test_clean_code_no_capabilities() {
    let source = include_str!("fixtures/clean.rs");
    let result = analyze("clean.rs", source, &permissive_config(), None).unwrap();

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
    let result = analyze("multi.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::Network));
    assert!(caps.contains(&Capability::FileRead));
}

#[test]
fn test_glob_use_detected() {
    let source = "use std::net::*;\n";
    let result = analyze("glob.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("fs_write.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::FileWrite));
    assert!(!caps.contains(&Capability::FileRead));
}

#[test]
fn test_third_party_network_crate() {
    let source = "use reqwest::Client;\n";
    let result = analyze("reqwest.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_grouped_use_detected() {
    let source = "use std::process::{Command, Stdio};\n";
    let result = analyze("grouped.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();

    assert!(caps.contains(&Capability::ProcessExec));
}

#[test]
fn test_finding_has_correct_evidence() {
    let source = "use std::net::TcpStream;\n";
    let result = analyze("evidence.rs", source, &permissive_config(), None).unwrap();

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
    let result = analyze("ffi.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("ffi_link.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("libc.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("unsafe_block.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("unsafe_fn.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("unsafe_impl.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("url.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("ip.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("ipv6.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("short.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("pem.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Crypto));
}

#[test]
fn test_crypto_crate_import_detected() {
    let source = "use ring::aead;\n";
    let result = analyze("ring.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Crypto));
}

#[test]
fn test_system_time_detected() {
    let source = "use std::time::SystemTime;\n";
    let result = analyze("systime.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::SystemTime));
}

#[test]
fn test_chrono_detected() {
    let source = "use chrono::Utc;\n";
    let result = analyze("chrono.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("proc_macro.rs", source, &permissive_config(), None).unwrap();
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
    let result = analyze("proc_macro_derive.rs", source, &permissive_config(), None).unwrap();
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

// --- Build script tagging tests ---

#[test]
fn test_build_script_findings_tagged() {
    let source = r#"
use std::process::Command;

fn main() {
    Command::new("cc").status().unwrap();
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("build.rs", &syntax, None);

    let profile_build =
        detect_capabilities(&ir_data, Some(pedant_types::ExecutionContext::BuildHook));
    assert!(
        profile_build.findings.iter().all(|f| f.is_build_hook()),
        "all findings should have execution_context=BuildHook"
    );

    let profile_normal = detect_capabilities(&ir_data, None);
    assert!(
        profile_normal
            .findings
            .iter()
            .all(|f| f.execution_context.is_none()),
        "all findings should have execution_context=None"
    );
}

#[test]
fn test_build_script_network_detection() {
    let source = include_str!("fixtures/build_script_network.rs");
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("build.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, Some(pedant_types::ExecutionContext::BuildHook));

    let net_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Network && f.is_build_hook())
        .collect();
    assert!(
        !net_findings.is_empty(),
        "should detect Network capability in build script"
    );
}

#[test]
fn test_build_script_process_detection() {
    let source = include_str!("fixtures/build_script_process.rs");
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("build.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, Some(pedant_types::ExecutionContext::BuildHook));

    let proc_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::ProcessExec && f.is_build_hook())
        .collect();
    assert!(
        !proc_findings.is_empty(),
        "should detect ProcessExec capability in build script"
    );
}

#[test]
fn test_existing_findings_default_false() {
    let source = "use std::net::TcpStream;\n";
    let result = analyze("lib.rs", source, &permissive_config(), None).unwrap();

    assert!(
        result
            .capabilities
            .findings
            .iter()
            .all(|f| f.execution_context.is_none()),
        "existing findings should have execution_context=None"
    );
}

// --- Evidence truncation tests ---

#[test]
fn test_truncate_evidence_short_passthrough() {
    let short = "abcdefghijklmnopqrstuvwxyz1234";
    assert_eq!(truncate_evidence(short), short);
}

#[test]
fn test_truncate_evidence_long_truncated() {
    let long = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    let result = truncate_evidence(long);
    assert!(result.len() < long.len());
    assert!(result.starts_with("a1b2c3d4e5f6a1b2"));
    assert!(result.ends_with("a1b2"));
    assert!(result.contains('\u{2026}')); // ellipsis
}

// --- Hex key detection tests ---

#[test]
fn test_hex_key_64_chars_detected() {
    let source = include_str!("fixtures/hex_key_material.rs");
    let result = analyze("hex_key.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        !crypto_findings.is_empty(),
        "should detect Crypto from 64-char hex key"
    );
    // Evidence should be truncated (the 64-char string is > 40 chars)
    assert!(
        crypto_findings
            .iter()
            .any(|f| f.evidence.contains('\u{2026}')),
        "evidence should be truncated for long hex key"
    );
}

#[test]
fn test_hex_key_128_chars_detected() {
    let source = include_str!("fixtures/hex_key_material.rs");
    let result = analyze("hex_key128.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    // Should have findings for both the 64-char and 128-char keys
    assert!(
        crypto_findings.len() >= 2,
        "should detect Crypto from both 64-char and 128-char hex keys, found {}",
        crypto_findings.len()
    );
}

#[test]
fn test_hex_short_not_flagged() {
    let source = r#"
fn foo() {
    let _hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
}
"#;
    let result = analyze("hex_short.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        crypto_findings.is_empty(),
        "32-char hex string should not trigger Crypto detection"
    );
}

#[test]
fn test_hex_odd_length_not_flagged() {
    // 65-char hex: odd length prevents hex key detection.
    // Note: base58 detection may still fire (65 chars falls in Solana range,
    // and hex chars are a subset of base58). This test verifies the hex
    // checker rejects odd lengths — base58 findings are expected.
    let source = r#"
fn foo() {
    let _odd = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a";
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("hex_odd.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, None);
    // Should have at most 1 finding (base58), not 2 (hex would be a second)
    let crypto_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        crypto_findings.len() <= 1,
        "65-char odd-length hex string should not trigger hex key detection (found {} crypto findings)",
        crypto_findings.len()
    );
}

#[test]
fn test_hex_mixed_case_detected() {
    let source = r#"
fn foo() {
    let _key = "aAbBcCdDeEfF0011aAbBcCdDeEfF0011aAbBcCdDeEfF0011aAbBcCdDeEfF0011";
}
"#;
    let result = analyze("hex_mixed.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(
        caps.contains(&Capability::Crypto),
        "mixed-case 64-char hex string should trigger Crypto detection"
    );
}

// --- Base58 key detection tests ---

#[test]
fn test_bitcoin_wif_detected() {
    let source = include_str!("fixtures/base58_key_material.rs");
    let result = analyze("base58.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        !crypto_findings.is_empty(),
        "should detect Crypto from Bitcoin WIF key"
    );
}

#[test]
fn test_bitcoin_wif_k_prefix_detected() {
    let source = r#"
fn foo() {
    let _key = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
}
"#;
    let result = analyze("wif_k.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(
        caps.contains(&Capability::Crypto),
        "52-char WIF key starting with 'K' should trigger Crypto detection"
    );
}

#[test]
fn test_solana_keypair_detected() {
    let source = include_str!("fixtures/base58_key_material.rs");
    let result = analyze("solana.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    // Should have findings for both the WIF key and the Solana keypair
    assert!(
        crypto_findings.len() >= 2,
        "should detect Crypto from both WIF and Solana keys, found {}",
        crypto_findings.len()
    );
}

#[test]
fn test_short_base58_not_flagged() {
    let source = r#"
fn foo() {
    let _addr = "1A1zP1eP5QGefi2DM";
}
"#;
    let result = analyze("base58_short.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        crypto_findings.is_empty(),
        "20-char base58 string should not trigger Crypto detection"
    );
}

#[test]
fn test_base58_with_invalid_chars_not_flagged() {
    // Contains '0', 'O', 'I', 'l' which are NOT in base58 alphabet
    let source = r#"
fn foo() {
    let _not_key = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVq0OIl";
}
"#;
    let result = analyze("base58_invalid.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        crypto_findings.is_empty(),
        "base58 string with invalid chars (0, O, I, l) should not trigger Crypto detection"
    );
}

// --- Key prefix detection tests ---

#[test]
fn test_age_secret_key_detected() {
    let source = include_str!("fixtures/key_prefix_material.rs");
    let result = analyze("age_key.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        crypto_findings
            .iter()
            .any(|f| f.evidence.starts_with("AGE-SECRET-KEY-1")),
        "should detect AGE-SECRET-KEY-1 prefix"
    );
}

#[test]
fn test_xprv_key_detected() {
    let source = include_str!("fixtures/key_prefix_material.rs");
    let result = analyze("xprv.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        crypto_findings
            .iter()
            .any(|f| f.evidence.starts_with("xprv")),
        "should detect xprv key prefix"
    );
}

#[test]
fn test_ethereum_private_key_detected() {
    let source = r#"
fn foo() {
    let _key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
}
"#;
    let result = analyze("eth_key.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        !crypto_findings.is_empty(),
        "should detect 0x + 64 hex chars as Ethereum private key"
    );
}

#[test]
fn test_near_ed25519_key_detected() {
    let source = r#"
fn foo() {
    let _key = "ed25519:3D4YudUahN1nawWogh6LMPvoRPW8QHr9AJsByJsXk7gn";
}
"#;
    let result = analyze("near_key.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(
        caps.contains(&Capability::Crypto),
        "should detect ed25519: prefix as NEAR key"
    );
}

// --- Credential prefix detection tests ---

#[test]
fn test_aws_access_key_detected() {
    let source = include_str!("fixtures/credential_material.rs");
    let result = analyze("aws_key.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        crypto_findings.iter().any(|f| f.evidence.contains("AKIA")),
        "should detect AKIA prefix as AWS access key"
    );
}

#[test]
fn test_github_pat_detected() {
    let source = r#"
fn foo() {
    let _token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
}
"#;
    let result = analyze("ghp.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(
        caps.contains(&Capability::Crypto),
        "should detect ghp_ prefix as GitHub PAT"
    );
}

#[test]
fn test_stripe_secret_key_detected() {
    let source = r#"
fn foo() {
    let _key = "sk_live_abcdefghijklmnopqrstuvwx";
}
"#;
    let result = analyze("stripe.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(
        caps.contains(&Capability::Crypto),
        "should detect sk_live_ prefix as Stripe secret key"
    );
}

#[test]
fn test_short_0x_not_flagged() {
    let source = r#"
fn foo() {
    let _val = "0xdeadbeef12";
}
"#;
    let result = analyze("short_0x.rs", source, &permissive_config(), None).unwrap();
    let crypto_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(
        crypto_findings.is_empty(),
        "0x + 10 hex chars should not trigger key prefix detection"
    );
}

#[test]
fn test_existing_pem_still_works() {
    // Regression: verify PEM and crypto import detection still work
    let pem_source = r#"
fn foo() {
    let _key = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----";
}
"#;
    let pem_result = analyze("pem_regress.rs", pem_source, &permissive_config(), None).unwrap();
    assert!(
        pem_result
            .capabilities
            .capabilities()
            .contains(&Capability::Crypto)
    );

    let import_source = "use ring::aead;\n";
    let import_result =
        analyze("ring_regress.rs", import_source, &permissive_config(), None).unwrap();
    assert!(
        import_result
            .capabilities
            .capabilities()
            .contains(&Capability::Crypto)
    );
}

// --- Finding origin metadata tests ---

#[test]
fn import_finding_has_import_origin() {
    let source = "use std::net::TcpStream;\n";
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("import_origin.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, None);

    assert_eq!(profile.findings.len(), 1);
    assert_eq!(
        profile.findings[0].origin,
        Some(FindingOrigin::Import),
        "use-path finding should have Import origin"
    );
}

#[test]
fn string_literal_finding_has_string_literal_origin() {
    let source = r#"
fn foo() {
    let _url = "https://api.example.com/v1/data";
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("string_origin.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, None);

    let net_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Network)
        .collect();
    assert_eq!(net_findings.len(), 1);
    assert_eq!(
        net_findings[0].origin,
        Some(FindingOrigin::StringLiteral),
        "URL string finding should have StringLiteral origin"
    );
}

#[test]
fn key_material_finding_has_string_literal_origin() {
    let source = r#"
fn foo() {
    let _key = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----";
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("pem_origin.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, None);

    let crypto_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();
    assert!(!crypto_findings.is_empty());
    assert!(
        crypto_findings
            .iter()
            .all(|f| f.origin == Some(FindingOrigin::StringLiteral)),
        "PEM key material finding should have StringLiteral origin"
    );
}

#[test]
fn attribute_finding_has_attribute_origin() {
    let source = r#"
#[proc_macro]
fn my_macro(input: TokenStream) -> TokenStream {
    input
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("attr_origin.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, None);

    let proc_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::ProcMacro)
        .collect();
    assert_eq!(proc_findings.len(), 1);
    assert_eq!(
        proc_findings[0].origin,
        Some(FindingOrigin::Attribute),
        "proc_macro attribute finding should have Attribute origin"
    );
}

#[test]
fn unsafe_block_finding_has_code_site_origin() {
    let source = r#"
fn foo() {
    let _val = unsafe { 42 };
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("unsafe_origin.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, None);

    let unsafe_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::UnsafeCode)
        .collect();
    assert_eq!(unsafe_findings.len(), 1);
    assert_eq!(
        unsafe_findings[0].origin,
        Some(FindingOrigin::CodeSite),
        "unsafe block finding should have CodeSite origin"
    );
}

#[test]
fn extern_block_finding_has_code_site_origin() {
    let source = r#"
extern "C" {
    fn my_c_function(x: i32) -> i32;
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("extern_origin.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, None);

    let ffi_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Ffi)
        .collect();
    assert_eq!(ffi_findings.len(), 1);
    assert_eq!(
        ffi_findings[0].origin,
        Some(FindingOrigin::CodeSite),
        "extern block finding should have CodeSite origin"
    );
}

#[test]
fn link_attribute_finding_has_attribute_origin() {
    let source = r#"
#[link(name = "mylib")]
extern "C" {
    fn my_c_function(x: i32) -> i32;
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("link_origin.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, None);

    let attr_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.origin == Some(FindingOrigin::Attribute))
        .collect();
    assert!(
        !attr_findings.is_empty(),
        "#[link] finding should have Attribute origin"
    );
}

// --- Self-analysis validation ---

#[test]
fn test_self_analysis_no_false_positives() {
    let source = include_str!("../../pedant-core/src/capabilities.rs");
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("capabilities.rs", &syntax, None);
    let profile = detect_capabilities(&ir_data, None);

    let crypto_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .collect();

    // The only expected Crypto finding is from the PEM check string "-----BEGIN "
    assert!(
        crypto_findings.len() == 1,
        "expected exactly 1 Crypto finding (PEM check string) from self-analysis, found {}: {:#?}",
        crypto_findings.len(),
        crypto_findings
    );
    assert!(
        crypto_findings[0].evidence.contains("-----BEGIN "),
        "the single Crypto finding should be the PEM check string, got: {}",
        crypto_findings[0].evidence
    );
}
