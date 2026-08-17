#![cfg(feature = "checks")]

/// Rust callable ownership of capability evidence.
///
/// The `#[path]` is required. Default resolution would place the file in
/// `tests/capability/`, which pedant's `conflicting-module-root` rule rejects
/// beside `capability.rs`, and its advice — fold the root into
/// `capability/mod.rs` — does not apply to a cargo test root, since cargo builds
/// a test executable per `tests/*.rs` and would stop building this one. A
/// sibling directory satisfies both: cargo declares no target for it, because it
/// holds no `main.rs`.
#[path = "capability_support/symbol_cases.rs"]
mod symbol_cases;

/// The shape of a hand-written capability expectation and the assertions that
/// hold an analysis to one. Same `#[path]` reason as [`symbol_cases`].
#[path = "capability_support/symbol_expectations.rs"]
mod symbol_expectations;

/// The Rust sources the cases below analyze. Same `#[path]` reason as
/// [`symbol_cases`].
#[path = "capability_support/sources.rs"]
mod sources;

use pedant_core::capabilities::{detect_capabilities, truncate_evidence};
use pedant_core::ir;
use pedant_core::lint::analyze;
use pedant_types::{Capability, FindingOrigin};

use crate::symbol_expectations::permissive_config;

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

    assert!(result.capabilities.profile.findings.is_empty());
}

#[test]
fn test_multiple_capabilities_detected() {
    let source = sources::NET_AND_FS_IMPORTS_SOURCE;
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
    let source = sources::FS_WRITE_CALL_SOURCE;
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

    assert_eq!(result.capabilities.profile.findings.len(), 1);
    assert_eq!(
        result.capabilities.profile.findings[0].evidence.as_ref(),
        "std::net::TcpStream"
    );
    assert_eq!(
        result.capabilities.profile.findings[0].capability,
        Capability::Network
    );
}

#[test]
fn test_ffi_capability_extern_block() {
    let source = sources::EXTERN_BLOCK_SOURCE;
    let result = analyze("ffi.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Ffi));
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "extern block")
    );
}

#[test]
fn test_ffi_capability_link_attribute() {
    let source = include_str!("fixtures/ffi_capability.rs");
    let result = analyze("ffi_link.rs", source, &permissive_config(), None).unwrap();
    let ffi_finding_count = result
        .capabilities
        .profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Ffi)
        .count();
    assert!(ffi_finding_count >= 2);
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
    let source = sources::UNSAFE_BLOCK_SOURCE;
    let result = analyze("unsafe_block.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::UnsafeCode));
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "unsafe block")
    );
}

#[test]
fn test_unsafe_fn_detected() {
    let source = sources::UNSAFE_FN_SOURCE;
    let result = analyze("unsafe_fn.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::UnsafeCode));
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "unsafe fn")
    );
}

#[test]
fn test_unsafe_impl_detected() {
    let source = sources::UNSAFE_IMPL_SOURCE;
    let result = analyze("unsafe_impl.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::UnsafeCode));
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "unsafe impl")
    );
}

#[test]
fn test_hardcoded_url_detected() {
    let source = sources::HTTPS_URL_SOURCE;
    let result = analyze("url.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_hardcoded_ip_detected() {
    let source = sources::IPV4_SOCKET_ADDRESS_SOURCE;
    let result = analyze("ip.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_ipv6_detected() {
    let source = sources::IPV6_SOCKET_ADDRESS_SOURCE;
    let result = analyze("ipv6.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_oid_string_is_not_network() {
    // "2.5.4.10" is an X.500 OID (organizationName). Four dotted decimals, all
    // <=255, so the old heuristic read it as a bare IPv4 with no port.
    let source = sources::X500_OID_SOURCE;
    let result = analyze("oid.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(
        !caps.contains(&Capability::Network),
        "an OID literal must not be classified as network, got {caps:?}"
    );
}

#[test]
fn test_rust_path_string_is_not_network() {
    // A `::`-separated path has many `::`; valid IPv6 has at most one.
    let source = sources::RUST_PATH_STRING_SOURCE;
    let result = analyze("path.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(
        !caps.contains(&Capability::Network),
        "a `::`-separated path must not be classified as network, got {caps:?}"
    );
}

#[test]
fn test_version_string_is_not_network() {
    // A dotted version quad is also IPv4-shaped without a port.
    let source = sources::DOTTED_VERSION_SOURCE;
    let result = analyze("ver.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(
        !caps.contains(&Capability::Network),
        "a version literal must not be classified as network, got {caps:?}"
    );
}

#[test]
fn test_short_string_not_flagged() {
    let source = sources::SHORT_STRING_SOURCE;
    let result = analyze("short.rs", source, &permissive_config(), None).unwrap();
    assert!(
        !result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Network)
    );
}

#[test]
fn test_pem_key_material_detected() {
    let source = sources::PEM_PRIVATE_KEY_SOURCE;
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
    let source = sources::PROC_MACRO_ATTRIBUTE_SOURCE;
    let result = analyze("proc_macro.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::ProcMacro));
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "#[proc_macro]")
    );
}

#[test]
fn test_proc_macro_derive_detected() {
    let source = sources::PROC_MACRO_DERIVE_ATTRIBUTE_SOURCE;
    let result = analyze("proc_macro_derive.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(caps.contains(&Capability::ProcMacro));
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.evidence.as_ref() == "#[proc_macro_derive]")
    );
}

// --- Build script tagging tests ---

#[test]
fn test_build_script_findings_tagged() {
    let source = sources::BUILD_SCRIPT_COMMAND_SOURCE;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("build.rs", &syntax, None);

    let analysis_build =
        detect_capabilities(&ir_data, Some(pedant_types::ExecutionContext::BuildHook));
    assert!(
        analysis_build
            .profile
            .findings
            .iter()
            .all(|f| f.is_build_hook()),
        "all findings should have execution_context=BuildHook"
    );

    let analysis_normal = detect_capabilities(&ir_data, None);
    assert!(
        analysis_normal
            .profile
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
    let analysis = detect_capabilities(&ir_data, Some(pedant_types::ExecutionContext::BuildHook));

    assert!(
        analysis
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Network && f.is_build_hook()),
        "should detect Network capability in build script"
    );
}

#[test]
fn test_build_script_process_detection() {
    let source = include_str!("fixtures/build_script_process.rs");
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("build.rs", &syntax, None);
    let analysis = detect_capabilities(&ir_data, Some(pedant_types::ExecutionContext::BuildHook));

    assert!(
        analysis
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::ProcessExec && f.is_build_hook()),
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
            .profile
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
    let findings = &result.capabilities.profile.findings;
    assert!(
        findings.iter().any(|f| f.capability == Capability::Crypto),
        "should detect Crypto from 64-char hex key"
    );
    // Evidence should be truncated (the 64-char string is > 40 chars)
    assert!(
        findings
            .iter()
            .any(|f| f.capability == Capability::Crypto && f.evidence.contains('\u{2026}')),
        "evidence should be truncated for long hex key"
    );
}

#[test]
fn test_hex_key_128_chars_detected() {
    let source = include_str!("fixtures/hex_key_material.rs");
    let result = analyze("hex_key128.rs", source, &permissive_config(), None).unwrap();
    let crypto_count = result
        .capabilities
        .profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .count();
    // Should have findings for both the 64-char and 128-char keys
    assert!(
        crypto_count >= 2,
        "should detect Crypto from both 64-char and 128-char hex keys, found {crypto_count}"
    );
}

#[test]
fn test_hex_short_not_flagged() {
    let source = sources::HEX_32_CHAR_SOURCE;
    let result = analyze("hex_short.rs", source, &permissive_config(), None).unwrap();
    assert!(
        !result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Crypto),
        "32-char hex string should not trigger Crypto detection"
    );
}

#[test]
fn test_hex_odd_length_not_flagged() {
    // 65-char hex: odd length prevents hex key detection.
    // Note: base58 detection may still fire (65 chars falls in Solana range,
    // and hex chars are a subset of base58). This test verifies the hex
    // checker rejects odd lengths — base58 findings are expected.
    let source = sources::HEX_ODD_LENGTH_SOURCE;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("hex_odd.rs", &syntax, None);
    let analysis = detect_capabilities(&ir_data, None);
    // Should have at most 1 finding (base58), not 2 (hex would be a second)
    let crypto_count = analysis
        .profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .count();
    assert!(
        crypto_count <= 1,
        "65-char odd-length hex string should not trigger hex key detection (found {crypto_count} crypto findings)"
    );
}

#[test]
fn test_hex_mixed_case_detected() {
    let source = sources::HEX_64_CHAR_MIXED_CASE_SOURCE;
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
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Crypto),
        "should detect Crypto from Bitcoin WIF key"
    );
}

#[test]
fn test_bitcoin_wif_k_prefix_detected() {
    let source = sources::BITCOIN_WIF_K_PREFIX_SOURCE;
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
    let crypto_count = result
        .capabilities
        .profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Crypto)
        .count();
    // Should have findings for both the WIF key and the Solana keypair
    assert!(
        crypto_count >= 2,
        "should detect Crypto from both WIF and Solana keys, found {crypto_count}"
    );
}

#[test]
fn test_short_base58_not_flagged() {
    let source = sources::SHORT_BASE58_SOURCE;
    let result = analyze("base58_short.rs", source, &permissive_config(), None).unwrap();
    assert!(
        !result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Crypto),
        "20-char base58 string should not trigger Crypto detection"
    );
}

#[test]
fn test_base58_with_invalid_chars_not_flagged() {
    // Contains '0', 'O', 'I', 'l' which are NOT in base58 alphabet
    let source = sources::BASE58_WITH_INVALID_CHARS_SOURCE;
    let result = analyze("base58_invalid.rs", source, &permissive_config(), None).unwrap();
    assert!(
        !result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Crypto),
        "base58 string with invalid chars (0, O, I, l) should not trigger Crypto detection"
    );
}

// --- Key prefix detection tests ---

#[test]
fn test_age_secret_key_detected() {
    let source = include_str!("fixtures/key_prefix_material.rs");
    let result = analyze("age_key.rs", source, &permissive_config(), None).unwrap();
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Crypto
                && f.evidence.starts_with("AGE-SECRET-KEY-1")),
        "should detect AGE-SECRET-KEY-1 prefix"
    );
}

#[test]
fn test_xprv_key_detected() {
    let source = include_str!("fixtures/key_prefix_material.rs");
    let result = analyze("xprv.rs", source, &permissive_config(), None).unwrap();
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Crypto && f.evidence.starts_with("xprv")),
        "should detect xprv key prefix"
    );
}

#[test]
fn test_ethereum_private_key_detected() {
    let source = sources::ETHEREUM_PRIVATE_KEY_SOURCE;
    let result = analyze("eth_key.rs", source, &permissive_config(), None).unwrap();
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Crypto),
        "should detect 0x + 64 hex chars as Ethereum private key"
    );
}

#[test]
fn test_near_ed25519_key_detected() {
    let source = sources::NEAR_ED25519_KEY_SOURCE;
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
    assert!(
        result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Crypto && f.evidence.contains("AKIA")),
        "should detect AKIA prefix as AWS access key"
    );
}

#[test]
fn test_github_pat_detected() {
    let source = sources::GITHUB_PAT_SOURCE;
    let result = analyze("ghp.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(
        caps.contains(&Capability::Crypto),
        "should detect ghp_ prefix as GitHub PAT"
    );
}

#[test]
fn test_stripe_secret_key_detected() {
    let source = sources::STRIPE_SECRET_KEY_SOURCE;
    let result = analyze("stripe.rs", source, &permissive_config(), None).unwrap();
    let caps = result.capabilities.capabilities();
    assert!(
        caps.contains(&Capability::Crypto),
        "should detect sk_live_ prefix as Stripe secret key"
    );
}

#[test]
fn test_short_0x_not_flagged() {
    let source = sources::SHORT_0X_HEX_SOURCE;
    let result = analyze("short_0x.rs", source, &permissive_config(), None).unwrap();
    assert!(
        !result
            .capabilities
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Crypto),
        "0x + 10 hex chars should not trigger key prefix detection"
    );
}

#[test]
fn test_existing_pem_still_works() {
    // Regression: verify PEM and crypto import detection still work
    let pem_source = sources::PEM_PRIVATE_KEY_SOURCE;
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
    let analysis = detect_capabilities(&ir_data, None);

    assert_eq!(analysis.profile.findings.len(), 1);
    assert_eq!(
        analysis.profile.findings[0].origin,
        Some(FindingOrigin::Import),
        "use-path finding should have Import origin"
    );
}

#[test]
fn string_literal_finding_has_string_literal_origin() {
    let source = sources::HTTPS_URL_SOURCE;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("string_origin.rs", &syntax, None);
    let analysis = detect_capabilities(&ir_data, None);

    let net_findings: Box<[_]> = analysis
        .profile
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
    let source = sources::PEM_PRIVATE_KEY_SOURCE;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("pem_origin.rs", &syntax, None);
    let analysis = detect_capabilities(&ir_data, None);

    assert!(
        analysis
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Crypto)
    );
    assert!(
        analysis
            .profile
            .findings
            .iter()
            .filter(|f| f.capability == Capability::Crypto)
            .all(|f| f.origin == Some(FindingOrigin::StringLiteral)),
        "PEM key material finding should have StringLiteral origin"
    );
}

#[test]
fn attribute_finding_has_attribute_origin() {
    let source = sources::PROC_MACRO_ATTRIBUTE_SOURCE;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("attr_origin.rs", &syntax, None);
    let analysis = detect_capabilities(&ir_data, None);

    let proc_findings: Box<[_]> = analysis
        .profile
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
    let source = sources::UNSAFE_BLOCK_SOURCE;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("unsafe_origin.rs", &syntax, None);
    let analysis = detect_capabilities(&ir_data, None);

    let unsafe_findings: Box<[_]> = analysis
        .profile
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
    let source = sources::EXTERN_BLOCK_SOURCE;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("extern_origin.rs", &syntax, None);
    let analysis = detect_capabilities(&ir_data, None);

    let ffi_findings: Box<[_]> = analysis
        .profile
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
    let source = sources::LINK_ATTRIBUTE_EXTERN_BLOCK_SOURCE;
    let syntax = syn::parse_file(source).unwrap();
    let ir_data = ir::extract("link_origin.rs", &syntax, None);
    let analysis = detect_capabilities(&ir_data, None);

    assert!(
        analysis
            .profile
            .findings
            .iter()
            .any(|f| f.origin == Some(FindingOrigin::Attribute)),
        "#[link] finding should have Attribute origin"
    );
}

// --- Self-analysis validation ---

#[test]
fn test_self_analysis_no_false_positives() {
    let source = [
        include_str!("../../pedant-core/src/capabilities/mod.rs"),
        include_str!("../../pedant-core/src/capabilities/detection.rs"),
        include_str!("../../pedant-core/src/capabilities/paths.rs"),
        include_str!("../../pedant-core/src/capabilities/strings.rs"),
    ]
    .concat();
    let syntax = syn::parse_file(&source).unwrap();
    let ir_data = ir::extract("capabilities.rs", &syntax, None);
    let analysis = detect_capabilities(&ir_data, None);

    let crypto_findings: Box<[_]> = analysis
        .profile
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
