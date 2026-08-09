//! Validated Cargo package versions.

use std::fmt;
use std::sync::Arc;

/// A package version that parsed as SemVer when the project was loaded.
///
/// No package view exists with an absent or invalid version, so a consumer can
/// attest the borrowed text without revalidating it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoPackageVersion {
    text: Arc<str>,
}

impl CargoPackageVersion {
    /// Validate declared version text as SemVer.
    pub(super) fn parse(text: &str) -> Result<Self, semver::Error> {
        semver::Version::parse(text)?;
        Ok(Self {
            text: Arc::from(text),
        })
    }

    /// The exact declared version text.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for CargoPackageVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}
