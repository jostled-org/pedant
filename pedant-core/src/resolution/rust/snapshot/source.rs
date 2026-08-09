//! The source view: one snapshotted Rust file, its exact bytes, and its IR.

use std::sync::Arc;

use crate::ir::FileIr;

/// One Rust source a snapshot reached, read and parsed exactly once.
#[derive(Debug)]
pub struct RustSource {
    pub(super) path: Arc<str>,
    pub(super) text: Arc<str>,
    pub(super) digest: [u8; 32],
    pub(super) ir: FileIr,
}

impl RustSource {
    /// The repository-relative, `/`-separated path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The same path, shared rather than copied, for the spans that name it.
    pub(in crate::resolution::rust) fn shared_path(&self) -> &Arc<str> {
        &self.path
    }

    /// The exact UTF-8 text this snapshot read.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// SHA-256 of the exact bytes behind [`Self::text`].
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The one-pass IR extracted while the source was snapshotted.
    pub fn ir(&self) -> &FileIr {
        &self.ir
    }
}

/// The source at `path`, when the sorted slice holds one.
pub(super) fn find<'a>(sources: &'a [RustSource], path: &str) -> Option<&'a RustSource> {
    sources
        .binary_search_by(|source| (*source.path).cmp(path))
        .ok()
        .and_then(|index| sources.get(index))
}
