use std::sync::Arc;

use pedant_types::{Capability, CapabilityFinding, CapabilityProfile, SourceLocation};

use crate::ir::FileIr;

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

/// Resolve a use-path or qualified path to a capability, if any.
fn resolve_capabilities(path: &str) -> Option<Capability> {
    debug_assert!(
        FS_WRITE_FUNCTIONS.windows(2).all(|w| w[0] <= w[1]),
        "FS_WRITE_FUNCTIONS must be sorted for binary_search"
    );
    if FS_WRITE_FUNCTIONS.binary_search(&path).is_ok() {
        return Some(Capability::FileWrite);
    }

    ALL_PREFIX_TABLES
        .iter()
        .flat_map(|table| table.iter())
        .find_map(|(prefix, capability)| path_matches_prefix(path, prefix).then_some(*capability))
}

const URL_SCHEMES: &[&str] = &["http://", "https://", "ws://", "wss://"];

/// Check whether a string literal looks like a network endpoint.
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

/// Check whether a string literal looks like a PEM block.
fn check_string_for_pem(value: &str) -> bool {
    value.contains("-----BEGIN ")
}

// --- IR-based capability detection ---

/// Detect capabilities from pre-extracted IR facts.
pub fn detect_capabilities(ir: &FileIr) -> CapabilityProfile {
    let file_path = &ir.file_path;
    let mut findings = Vec::new();

    detect_use_paths(ir, file_path, &mut findings);
    detect_unsafe_sites(ir, file_path, &mut findings);
    detect_extern_blocks(ir, file_path, &mut findings);
    detect_attributes(ir, file_path, &mut findings);
    detect_string_literals(ir, file_path, &mut findings);

    CapabilityProfile {
        findings: findings.into_boxed_slice(),
    }
}

fn record(
    findings: &mut Vec<CapabilityFinding>,
    capability: Capability,
    file: &Arc<str>,
    line: usize,
    column: usize,
    evidence: &str,
) {
    findings.push(CapabilityFinding {
        capability,
        location: SourceLocation {
            file: Arc::clone(file),
            line,
            column,
        },
        evidence: Arc::from(evidence),
    });
}

/// Shared helper: iterate IR facts, map each to zero or more capability findings, and record them.
fn detect_from_facts<'a, T: 'a>(
    facts: &'a [T],
    file_path: &Arc<str>,
    findings: &mut Vec<CapabilityFinding>,
    mut mapper: impl FnMut(&'a T) -> Option<(Capability, usize, usize, &'a str)>,
) {
    for fact in facts {
        if let Some((capability, line, column, evidence)) = mapper(fact) {
            record(findings, capability, file_path, line, column, evidence);
        }
    }
}

fn detect_use_paths(ir: &FileIr, file_path: &Arc<str>, findings: &mut Vec<CapabilityFinding>) {
    detect_from_facts(&ir.use_paths, file_path, findings, |use_path| {
        resolve_capabilities(&use_path.path).map(|cap| {
            (
                cap,
                use_path.span.line,
                use_path.span.column + 1,
                use_path.path.as_ref(),
            )
        })
    });
}

fn detect_unsafe_sites(ir: &FileIr, file_path: &Arc<str>, findings: &mut Vec<CapabilityFinding>) {
    detect_from_facts(&ir.unsafe_sites, file_path, findings, |site| {
        Some((
            Capability::UnsafeCode,
            site.span.line,
            site.span.column + 1,
            site.evidence.as_ref(),
        ))
    });
}

fn detect_extern_blocks(ir: &FileIr, file_path: &Arc<str>, findings: &mut Vec<CapabilityFinding>) {
    detect_from_facts(&ir.extern_blocks, file_path, findings, |block| {
        Some((
            Capability::Ffi,
            block.span.line,
            block.span.column + 1,
            "extern block",
        ))
    });
}

fn detect_attributes(ir: &FileIr, file_path: &Arc<str>, findings: &mut Vec<CapabilityFinding>) {
    detect_from_facts(&ir.attributes, file_path, findings, |attr| {
        let (cap, evidence) = match &*attr.name {
            "link" => (Capability::Ffi, "#[link]"),
            "proc_macro" => (Capability::ProcMacro, "#[proc_macro]"),
            "proc_macro_derive" => (Capability::ProcMacro, "#[proc_macro_derive]"),
            "proc_macro_attribute" => (Capability::ProcMacro, "#[proc_macro_attribute]"),
            _ => return None,
        };
        Some((cap, attr.span.line, attr.span.column + 1, evidence))
    });
}

fn detect_string_literals(
    ir: &FileIr,
    file_path: &Arc<str>,
    findings: &mut Vec<CapabilityFinding>,
) {
    for lit in &ir.string_literals {
        let line = lit.span.line;
        let column = lit.span.column + 1;

        if check_string_for_endpoint(&lit.value) {
            record(
                findings,
                Capability::Network,
                file_path,
                line,
                column,
                &lit.value,
            );
        }
        if check_string_for_pem(&lit.value) {
            record(
                findings,
                Capability::Crypto,
                file_path,
                line,
                column,
                &lit.value,
            );
        }
    }
}
