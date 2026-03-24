use std::borrow::Cow;
use std::sync::Arc;

use pedant_types::{Capability, CapabilityFinding, CapabilityProfile, SourceLocation};

use crate::ir::FileIr;

/// Validator: receives (full value, suffix after prefix) and returns whether it matches.
type PrefixValidator = fn(&str, &str) -> bool;

// --- Prefix tables for path-based capability resolution ---

const NETWORK_PREFIXES: &[(&str, Capability)] = &[
    ("std::net", Capability::Network),
    ("tokio::net", Capability::Network),
    ("reqwest", Capability::Network),
    ("hyper", Capability::Network),
    ("ureq", Capability::Network),
    ("curl", Capability::Network),
    ("tungstenite", Capability::Network),
];

const FILESYSTEM_PREFIXES: &[(&str, Capability)] = &[
    ("std::fs", Capability::FileRead),
    ("tokio::fs", Capability::FileRead),
    ("walkdir", Capability::FileRead),
    ("glob", Capability::FileRead),
    ("tempfile", Capability::FileWrite),
];

const PROCESS_PREFIXES: &[(&str, Capability)] = &[
    ("std::process", Capability::ProcessExec),
    ("tokio::process", Capability::ProcessExec),
    ("duct", Capability::ProcessExec),
];

const ENV_PREFIXES: &[(&str, Capability)] = &[
    ("std::env::var", Capability::EnvAccess),
    ("std::env::vars", Capability::EnvAccess),
    ("dotenvy", Capability::EnvAccess),
    ("envy", Capability::EnvAccess),
];

const FFI_PREFIXES: &[(&str, Capability)] = &[
    ("libc", Capability::Ffi),
    ("nix", Capability::Ffi),
    ("winapi", Capability::Ffi),
    ("windows_sys", Capability::Ffi),
];

const CRYPTO_PREFIXES: &[(&str, Capability)] = &[
    ("ring", Capability::Crypto),
    ("rustls", Capability::Crypto),
    ("openssl", Capability::Crypto),
    ("aes", Capability::Crypto),
    ("sha2", Capability::Crypto),
    ("hmac", Capability::Crypto),
    ("ed25519_dalek", Capability::Crypto),
    ("x25519_dalek", Capability::Crypto),
];

const SYSTEM_TIME_PREFIXES: &[(&str, Capability)] = &[
    ("std::time::SystemTime", Capability::SystemTime),
    ("std::time::Instant", Capability::SystemTime),
    ("chrono", Capability::SystemTime),
    ("time", Capability::SystemTime),
];

const ALL_PREFIX_TABLES: &[&[(&str, Capability)]] = &[
    NETWORK_PREFIXES,
    FILESYSTEM_PREFIXES,
    PROCESS_PREFIXES,
    ENV_PREFIXES,
    FFI_PREFIXES,
    CRYPTO_PREFIXES,
    SYSTEM_TIME_PREFIXES,
];

/// Specific function-level overrides for filesystem capability splitting.
const FS_WRITE_FUNCTIONS: &[&str] = &[
    "std::fs::copy",
    "std::fs::create_dir",
    "std::fs::create_dir_all",
    "std::fs::hard_link",
    "std::fs::remove_dir",
    "std::fs::remove_dir_all",
    "std::fs::remove_file",
    "std::fs::rename",
    "std::fs::set_permissions",
    "std::fs::write",
    "tokio::fs::copy",
    "tokio::fs::create_dir",
    "tokio::fs::create_dir_all",
    "tokio::fs::hard_link",
    "tokio::fs::remove_dir",
    "tokio::fs::remove_dir_all",
    "tokio::fs::remove_file",
    "tokio::fs::rename",
    "tokio::fs::set_permissions",
    "tokio::fs::write",
];

use crate::ir::PATH_SEPARATOR;

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || (path.starts_with(prefix)
            && path
                .as_bytes()
                .get(prefix.len()..prefix.len() + PATH_SEPARATOR.len())
                == Some(PATH_SEPARATOR.as_bytes()))
}

/// Map a use-path to its capability, checking write-function overrides first.
fn resolve_capabilities(path: &str) -> Option<Capability> {
    if FS_WRITE_FUNCTIONS.binary_search(&path).is_ok() {
        return Some(Capability::FileWrite);
    }

    ALL_PREFIX_TABLES
        .iter()
        .flat_map(|table| table.iter())
        .find_map(|(prefix, capability)| path_matches_prefix(path, prefix).then_some(*capability))
}

const URL_SCHEMES: &[&str] = &["http://", "https://", "ws://", "wss://"];

/// Heuristic: URLs, IPv4 with port, or IPv6 addresses.
fn check_string_for_endpoint(value: &str) -> bool {
    if value.len() < 8 {
        return false;
    }
    URL_SCHEMES.iter().any(|s| value.starts_with(s))
        || looks_like_ipv4(value)
        || looks_like_ipv6(value)
}

fn strip_port_suffix(s: &str) -> Option<&str> {
    let pos = s.rfind(':')?;
    let (host, port) = s.split_at(pos);
    port[1..].parse::<u16>().ok().map(|_| host)
}

fn looks_like_ipv4(s: &str) -> bool {
    let host = match (s.rfind(':'), strip_port_suffix(s)) {
        (Some(_), Some(h)) => h,
        (Some(_), None) => return false,
        (None, _) => s,
    };
    let mut parts = host.split('.');
    let mut count = 0;
    let valid = parts.all(|p| {
        count += 1;
        p.parse::<u8>().is_ok()
    });
    valid && count == 4
}

fn extract_ipv6_body(s: &str) -> &str {
    match s.strip_prefix('[') {
        Some(inner) => inner
            .strip_suffix(']')
            .or_else(|| inner.rfind("]:").map(|pos| &inner[..pos]))
            .unwrap_or(inner),
        None => s,
    }
}

fn looks_like_ipv6(s: &str) -> bool {
    let trimmed = extract_ipv6_body(s);
    if trimmed.len() < 3 {
        return false;
    }
    let mut groups = trimmed.split(':');
    let mut count = 0;
    let valid = groups.all(|g| {
        count += 1;
        g.is_empty() || g.chars().all(|c| c.is_ascii_hexdigit())
    });
    valid && count > 2
}

/// Heuristic: looks for PEM block header prefix.
fn check_string_for_pem(value: &str) -> bool {
    value.contains("-----BEGIN ")
}

/// Truncate long evidence strings to avoid leaking full keys.
///
/// Strings ≤ 40 chars are returned unchanged. Longer strings return the first
/// 16 chars, an ellipsis, and the last 4 chars.
pub fn truncate_evidence(value: &str) -> Cow<'_, str> {
    match value.len() <= 40 {
        true => Cow::Borrowed(value),
        false => {
            let char_count = value.chars().count();
            let tail_offset = char_count.saturating_sub(4);
            let mut indices = value.char_indices();
            let head_end = indices.nth(16).map_or(value.len(), |(i, _)| i);
            let skip = tail_offset.saturating_sub(17);
            let tail_start = indices.nth(skip).map_or(0, |(i, _)| i);
            Cow::Owned(format!("{}…{}", &value[..head_end], &value[tail_start..]))
        }
    }
}

/// Check whether a string is a hex-encoded key at a known private key size.
///
/// Returns true for even-length pure hex strings of 64, 96, or ≥ 128 chars.
fn check_string_for_hex_key(value: &str) -> bool {
    let len = value.len();
    if len < 64 || len % 2 != 0 {
        return false;
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    matches!(len, 64 | 96) || len >= 128
}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn is_base58(value: &str) -> bool {
    value.bytes().all(|b| BASE58_ALPHABET.contains(&b))
}

/// Check whether a string is a base58-encoded private key.
///
/// Matches Bitcoin WIF keys (51–52 chars, first char in {5, K, L}) and
/// Solana keypairs (64–88 base58 chars).
fn check_string_for_base58_key(value: &str) -> bool {
    let len = value.len();
    match value.as_bytes().first() {
        Some(b'5' | b'K' | b'L') if (51..=52).contains(&len) => is_base58(value),
        _ if (64..=88).contains(&len) => is_base58(value),
        _ => false,
    }
}

/// Check whether a string starts with a known cryptographic key prefix.
///
/// Matches AGE-SECRET-KEY-1, xprv (BIP32), ed25519: (NEAR), and 0x + 64 hex (Ethereum).
fn check_string_for_key_prefix(value: &str) -> bool {
    const KEY_PREFIXES: &[(&str, PrefixValidator)] = &[
        ("AGE-SECRET-KEY-1", |v, _| v.len() > 16),
        ("xprv", |v, suffix| v.len() >= 111 && is_base58(suffix)),
        ("ed25519:", |v, _| v.len() > 8),
        ("0x", |v, suffix| {
            v.len() == 66 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
        }),
    ];
    KEY_PREFIXES.iter().any(|(prefix, validate)| {
        value
            .strip_prefix(prefix)
            .is_some_and(|suffix| validate(value, suffix))
    })
}

/// Check whether a string starts with a known credential prefix.
///
/// Matches AWS access keys (AKIA), GitHub tokens (ghp_, gho_, ghs_, ghr_),
/// and Stripe/OpenAI-style secrets (sk-, sk_live_, sk_test_).
/// Validates that the suffix is at least 24 ASCII alphanumeric characters.
/// Shared by sk_live_, sk_test_, and sk- credential prefixes.
fn validate_sk_suffix(_full: &str, suffix: &str) -> bool {
    suffix.len() >= 24 && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn check_string_for_credential_prefix(value: &str) -> bool {
    const CREDENTIAL_PREFIXES: &[(&str, PrefixValidator)] = &[
        ("AKIA", |v, suffix| {
            v.len() == 20
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        }),
        ("sk_live_", validate_sk_suffix),
        ("sk_test_", validate_sk_suffix),
        ("sk-", validate_sk_suffix),
    ];
    // GitHub tokens use a 4-char prefix checked separately.
    match starts_with_github_prefix(value) {
        true => value.len() == 40 && value[4..].bytes().all(|b| b.is_ascii_alphanumeric()),
        false => CREDENTIAL_PREFIXES.iter().any(|(prefix, validate)| {
            value
                .strip_prefix(prefix)
                .is_some_and(|suffix| validate(value, suffix))
        }),
    }
}

fn starts_with_github_prefix(value: &str) -> bool {
    matches!(value.get(..4), Some("ghp_" | "gho_" | "ghs_" | "ghr_"))
}

// --- IR-based capability detection ---

/// Scan all IR facts for capability usage and produce a profile.
///
/// When `build_script` is true, every finding is tagged with `build_script: true`.
pub fn detect_capabilities(ir: &FileIr, build_script: bool) -> CapabilityProfile {
    let file_path = &ir.file_path;
    let mut findings = Vec::new();

    detect_use_paths(ir, file_path, build_script, &mut findings);
    detect_unsafe_sites(ir, file_path, build_script, &mut findings);
    detect_extern_blocks(ir, file_path, build_script, &mut findings);
    detect_attributes(ir, file_path, build_script, &mut findings);
    detect_string_literals(ir, file_path, build_script, &mut findings);

    CapabilityProfile {
        findings: findings.into_boxed_slice(),
    }
}

fn emit(
    findings: &mut Vec<CapabilityFinding>,
    capability: Capability,
    file: &Arc<str>,
    line: usize,
    column: usize,
    evidence: &str,
    build_script: bool,
) {
    findings.push(CapabilityFinding {
        capability,
        location: SourceLocation {
            file: Arc::clone(file),
            line,
            column: column + 1,
        },
        evidence: Arc::from(evidence),
        build_script,
        reachable: None,
    });
}

/// Shared helper: iterate IR facts, map each to zero or more capability findings, and emit them.
fn detect_from_facts<'a, T: 'a>(
    facts: &'a [T],
    file_path: &Arc<str>,
    build_script: bool,
    findings: &mut Vec<CapabilityFinding>,
    mut mapper: impl FnMut(&'a T) -> Option<(Capability, usize, usize, &'a str)>,
) {
    for fact in facts {
        if let Some((capability, line, column, evidence)) = mapper(fact) {
            emit(
                findings,
                capability,
                file_path,
                line,
                column,
                evidence,
                build_script,
            );
        }
    }
}

fn detect_use_paths(
    ir: &FileIr,
    file_path: &Arc<str>,
    build_script: bool,
    findings: &mut Vec<CapabilityFinding>,
) {
    detect_from_facts(
        &ir.use_paths,
        file_path,
        build_script,
        findings,
        |use_path| {
            resolve_capabilities(&use_path.path).map(|cap| {
                (
                    cap,
                    use_path.span.line,
                    use_path.span.column,
                    use_path.path.as_ref(),
                )
            })
        },
    );
}

fn detect_unsafe_sites(
    ir: &FileIr,
    file_path: &Arc<str>,
    build_script: bool,
    findings: &mut Vec<CapabilityFinding>,
) {
    detect_from_facts(
        &ir.unsafe_sites,
        file_path,
        build_script,
        findings,
        |site| {
            Some((
                Capability::UnsafeCode,
                site.span.line,
                site.span.column,
                site.evidence.as_ref(),
            ))
        },
    );
}

fn detect_extern_blocks(
    ir: &FileIr,
    file_path: &Arc<str>,
    build_script: bool,
    findings: &mut Vec<CapabilityFinding>,
) {
    detect_from_facts(
        &ir.extern_blocks,
        file_path,
        build_script,
        findings,
        |block| {
            Some((
                Capability::Ffi,
                block.span.line,
                block.span.column,
                "extern block",
            ))
        },
    );
}

fn detect_attributes(
    ir: &FileIr,
    file_path: &Arc<str>,
    build_script: bool,
    findings: &mut Vec<CapabilityFinding>,
) {
    detect_from_facts(&ir.attributes, file_path, build_script, findings, |attr| {
        let (cap, evidence) = match &*attr.name {
            "link" => (Capability::Ffi, "#[link]"),
            "proc_macro" => (Capability::ProcMacro, "#[proc_macro]"),
            "proc_macro_derive" => (Capability::ProcMacro, "#[proc_macro_derive]"),
            "proc_macro_attribute" => (Capability::ProcMacro, "#[proc_macro_attribute]"),
            _ => return None,
        };
        Some((cap, attr.span.line, attr.span.column, evidence))
    });
}

/// Key-material checks that are mutually exclusive (a string matches at most one).
const KEY_MATERIAL_CHECKS: &[fn(&str) -> bool] = &[
    check_string_for_hex_key,
    check_string_for_base58_key,
    check_string_for_key_prefix,
    check_string_for_credential_prefix,
];

/// String literal detection entry: checker function and capability.
struct StringLiteralCheck {
    checker: fn(&str) -> bool,
    capability: Capability,
}

const STRING_LITERAL_CHECKS: &[StringLiteralCheck] = &[
    StringLiteralCheck {
        checker: check_string_for_endpoint,
        capability: Capability::Network,
    },
    StringLiteralCheck {
        checker: check_string_for_pem,
        capability: Capability::Crypto,
    },
];

fn detect_string_literals(
    ir: &FileIr,
    file_path: &Arc<str>,
    build_script: bool,
    findings: &mut Vec<CapabilityFinding>,
) {
    for lit in &ir.string_literals {
        let line = lit.span.line;
        let column = lit.span.column;

        if let Some(check) = STRING_LITERAL_CHECKS
            .iter()
            .find(|check| (check.checker)(&lit.value))
        {
            emit(
                findings,
                check.capability,
                file_path,
                line,
                column,
                &lit.value,
                build_script,
            );
        }
        if KEY_MATERIAL_CHECKS.iter().any(|check| check(&lit.value)) {
            let evidence = truncate_evidence(&lit.value);
            emit(
                findings,
                Capability::Crypto,
                file_path,
                line,
                column,
                &evidence,
                build_script,
            );
        }
    }
}
