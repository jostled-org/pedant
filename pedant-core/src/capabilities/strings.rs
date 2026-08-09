use std::borrow::Cow;

use pedant_types::Capability;

use super::validation::PrefixValidator;

pub(super) type StringLiteralCheck = (fn(&str) -> bool, Capability);

const URL_SCHEMES: &[&str] = &["http://", "https://", "ws://", "wss://"];

fn check_string_for_endpoint(value: &str) -> bool {
    if value.len() < 8 {
        return false;
    }
    URL_SCHEMES.iter().any(|scheme| value.starts_with(scheme))
        || looks_like_ipv4(value)
        || looks_like_ipv6(value)
}

fn strip_port_suffix(value: &str) -> Option<&str> {
    let position = value.rfind(':')?;
    let (host, port) = value.split_at(position);
    port[1..].parse::<u16>().ok().map(|_| host)
}

fn looks_like_ipv4(value: &str) -> bool {
    let Some(host) = strip_port_suffix(value) else {
        return false;
    };
    let mut parts = host.split('.');
    let mut count = 0;
    let valid = parts.all(|part| {
        count += 1;
        part.parse::<u8>().is_ok()
    });
    valid && count == 4
}

fn extract_ipv6_body(value: &str) -> &str {
    match value.strip_prefix('[') {
        Some(inner) => inner
            .strip_suffix(']')
            .or_else(|| inner.rfind("]:").map(|position| &inner[..position]))
            .unwrap_or(inner),
        None => value,
    }
}

fn looks_like_ipv6(value: &str) -> bool {
    let trimmed = extract_ipv6_body(value);
    if trimmed.len() < 3 || trimmed.split("::").count() > 2 {
        return false;
    }
    let mut groups = trimmed.split(':');
    let mut count = 0;
    let valid = groups.all(|group| {
        count += 1;
        group.is_empty() || group.chars().all(|character| character.is_ascii_hexdigit())
    });
    valid && count > 2
}

fn check_string_for_pem(value: &str) -> bool {
    value.contains("-----BEGIN ")
}

/// Truncate long evidence strings to avoid leaking full keys.
///
/// Strings of at most 40 bytes are returned unchanged. Longer strings retain
/// the first 16 characters and last 4 characters around an ellipsis.
pub fn truncate_evidence(value: &str) -> Cow<'_, str> {
    match value.len() <= 40 {
        true => Cow::Borrowed(value),
        false => {
            let char_count = value.chars().count();
            let tail_offset = char_count.saturating_sub(4);
            let mut indices = value.char_indices();
            let head_end = indices.nth(16).map_or(value.len(), |(index, _)| index);
            let skip = tail_offset.saturating_sub(17);
            let tail_start = indices.nth(skip).map_or(0, |(index, _)| index);
            Cow::Owned(format!("{}…{}", &value[..head_end], &value[tail_start..]))
        }
    }
}

fn check_string_for_hex_key(value: &str) -> bool {
    let len = value.len();
    if len < 64 || !len.is_multiple_of(2) {
        return false;
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }
    matches!(len, 64 | 96) || len >= 128
}

const fn base58_table() -> [bool; 256] {
    let mut table = [false; 256];
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut index = 0;
    while index < alphabet.len() {
        table[alphabet[index] as usize] = true;
        index += 1;
    }
    table
}

const BASE58_TABLE: [bool; 256] = base58_table();

fn is_base58(value: &str) -> bool {
    value.bytes().all(|byte| BASE58_TABLE[byte as usize])
}

fn check_string_for_base58_key(value: &str) -> bool {
    let len = value.len();
    match value.as_bytes().first() {
        Some(b'5' | b'K' | b'L') if (51..=52).contains(&len) => is_base58(value),
        _ if (64..=88).contains(&len) => is_base58(value),
        _ => false,
    }
}

fn check_string_for_key_prefix(value: &str) -> bool {
    const KEY_PREFIXES: &[(&str, PrefixValidator)] = &[
        ("AGE-SECRET-KEY-1", |full, _| full.len() > 16),
        ("xprv", |full, suffix| {
            full.len() >= 111 && is_base58(suffix)
        }),
        ("ed25519:", |full, _| full.len() > 8),
        ("0x", |full, suffix| {
            full.len() == 66 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        }),
    ];
    KEY_PREFIXES.iter().any(|(prefix, validate)| {
        value
            .strip_prefix(prefix)
            .is_some_and(|suffix| validate(value, suffix))
    })
}

fn validate_sk_suffix(_full: &str, suffix: &str) -> bool {
    suffix.len() >= 24 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn check_string_for_credential_prefix(value: &str) -> bool {
    const CREDENTIAL_PREFIXES: &[(&str, PrefixValidator)] = &[
        ("AKIA", |full, suffix| {
            full.len() == 20
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        }),
        ("sk_live_", validate_sk_suffix),
        ("sk_test_", validate_sk_suffix),
        ("sk-", validate_sk_suffix),
    ];
    match starts_with_github_prefix(value) {
        true => value.len() == 40 && value[4..].bytes().all(|byte| byte.is_ascii_alphanumeric()),
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

pub(super) const KEY_MATERIAL_CHECKS: &[fn(&str) -> bool] = &[
    check_string_for_hex_key,
    check_string_for_base58_key,
    check_string_for_key_prefix,
    check_string_for_credential_prefix,
];

pub(super) const STRING_LITERAL_CHECKS: &[StringLiteralCheck] = &[
    (check_string_for_endpoint, Capability::Network),
    (check_string_for_pem, Capability::Crypto),
];
