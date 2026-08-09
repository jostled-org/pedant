use pedant_types::Capability;

use crate::ir::PATH_SEPARATOR;

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

const FS_WRITE_SUFFIXES: &[&str] = &[
    "copy",
    "create_dir",
    "create_dir_all",
    "hard_link",
    "remove_dir",
    "remove_dir_all",
    "remove_file",
    "rename",
    "set_permissions",
    "write",
];

const FS_WRITE_PREFIXES: &[&str] = &["std::fs::", "tokio::fs::"];

fn is_fs_write_function(path: &str) -> bool {
    FS_WRITE_PREFIXES.iter().any(|prefix| {
        path.strip_prefix(prefix)
            .is_some_and(|suffix| FS_WRITE_SUFFIXES.contains(&suffix))
    })
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || (path.starts_with(prefix)
            && path
                .as_bytes()
                .get(prefix.len()..prefix.len() + PATH_SEPARATOR.len())
                == Some(PATH_SEPARATOR.as_bytes()))
}

pub(super) fn resolve_capabilities(path: &str) -> Option<Capability> {
    if is_fs_write_function(path) {
        return Some(Capability::FileWrite);
    }

    ALL_PREFIX_TABLES
        .iter()
        .flat_map(|table| table.iter())
        .find_map(|(prefix, capability)| path_matches_prefix(path, prefix).then_some(*capability))
}
