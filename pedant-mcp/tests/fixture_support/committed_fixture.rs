//! Where this crate's committed fixture workspaces live.
//!
//! Four test roots ask the same question — `index.rs`, `watcher.rs`,
//! `tools.rs`, and `integration.rs` — so the answer is stated once and each
//! root declares this file with `#[path]`. Cargo links one test executable per
//! `tests/*.rs`, so a shared support file has to be declared by every root that
//! needs it rather than reached through a library.

use std::path::{Path, PathBuf};

/// The committed fixture workspace `name`, where it sits in the source tree.
///
/// Committed rather than copied: a case that mutates a workspace asks
/// [`crate::writable_fixture::copy_fixture_to_temp`] for its own copy instead.
pub(crate) fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}
