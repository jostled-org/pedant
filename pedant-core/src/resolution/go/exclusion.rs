//! One `exclude` directive from the root manifest.

/// One `exclude` directive from the root manifest.
///
/// An exclusion refuses an exact required version. It never selects a
/// substitute: this tier states what the manifests declare and runs no
/// minimal-version selection.
#[derive(Debug)]
pub struct GoExclusion {
    pub(super) path: Box<str>,
    pub(super) version: Box<str>,
}

impl GoExclusion {
    /// The excluded module path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The excluded version.
    pub fn version(&self) -> &str {
        &self.version
    }
}
