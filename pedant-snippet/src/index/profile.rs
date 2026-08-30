//! Which languages this build can read, and which of them it can resolve.
//!
//! The two vectors are part of the index's identity rather than metadata about
//! it. A build that links no Python grammar cannot see a Python file, so it
//! states a smaller corpus for the same repository; a build that links no Rust
//! resolver sees the same Rust files and answers different questions about
//! them. Either difference is a different index, and hashing both vectors is
//! what makes that difference visible instead of a silent disagreement between
//! two installs.

use pedant_types::Language;

/// Every language this build links a structure inventory for, sorted.
///
/// The order is the enum's own, so two builds with the same set state the same
/// vector whatever order their features were spelled in.
pub(crate) const ENABLED_LANGUAGES: &[Language] = &[
    #[cfg(feature = "lang-rust")]
    Language::Rust,
    #[cfg(feature = "lang-python")]
    Language::Python,
    #[cfg(feature = "lang-javascript")]
    Language::JavaScript,
    #[cfg(feature = "lang-typescript")]
    Language::TypeScript,
    #[cfg(feature = "lang-go")]
    Language::Go,
    #[cfg(feature = "lang-bash")]
    Language::Bash,
];

/// Every language this build links a project resolver and graph producer for.
///
/// A subset of [`ENABLED_LANGUAGES`] by construction: each graph feature
/// selects its own language feature, so a build cannot resolve a language it
/// cannot read.
pub(crate) const GRAPH_COVERAGE: &[Language] = &[
    #[cfg(feature = "graph-rust")]
    Language::Rust,
    #[cfg(feature = "graph-go")]
    Language::Go,
];

/// Whether this build links a structure inventory for `language`.
pub(crate) fn reads(language: Language) -> bool {
    ENABLED_LANGUAGES.contains(&language)
}

/// Whether this build links a project resolver and graph producer for
/// `language`.
pub(crate) fn resolves(language: Language) -> bool {
    GRAPH_COVERAGE.contains(&language)
}
