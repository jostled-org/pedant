use thiserror::Error;

/// Failure modes during workspace indexing.
#[derive(Debug, Error)]
pub enum IndexError {
    /// Disk I/O failure.
    #[error("failed to read {path}: {source}")]
    Io {
        /// Absolute path of the unreadable file.
        path: Box<str>,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// TOML syntax or schema error.
    #[error("failed to parse {path}: {source}")]
    TomlParse {
        /// Path of the malformed TOML file.
        path: Box<str>,
        /// Underlying parse error.
        source: toml::de::Error,
    },
    /// `syn` could not parse a Rust source file.
    #[error("failed to parse Rust source {path}: {source}")]
    RustParse {
        /// Path of the unparseable source file.
        path: Box<str>,
        /// Underlying parse error.
        source: pedant_core::ParseError,
    },
    /// Cargo.toml exists but has no `package.name` field.
    #[error("{path} missing required package.name field")]
    MissingPackageName {
        /// Path of the Cargo.toml without a package name.
        path: Box<str>,
    },
}
