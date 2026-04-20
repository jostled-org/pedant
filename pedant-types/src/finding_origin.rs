use serde::{Deserialize, Serialize};

/// How a capability finding was detected in source code.
///
/// Gate rules use this to distinguish, for example, a crypto import
/// (`use sha2::Digest`) from embedded key material (`"0xac09..."`).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FindingOrigin {
    /// Detected via a `use` path (e.g., `use std::net::TcpStream`).
    Import,
    /// Detected via a string literal (URL, IP address, PEM header, key material).
    StringLiteral,
    /// Detected via an attribute (e.g., `#[link]`, `#[proc_macro]`).
    Attribute,
    /// Detected via an `unsafe` block, `unsafe fn`, `unsafe impl`, or `extern` block.
    CodeSite,
    /// Detected in a Cargo.toml build hook or similar manifest-level directive.
    ManifestHook,
}
