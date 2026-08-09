//! Function signature shared by prefixed string-evidence validators.

/// Validate a complete string and the suffix after its recognized prefix.
pub(super) type PrefixValidator = fn(&str, &str) -> bool;
