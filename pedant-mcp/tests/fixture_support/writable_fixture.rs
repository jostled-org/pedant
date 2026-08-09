//! A writable copy of a committed fixture workspace.
//!
//! A case that edits, adds, or renames files cannot touch the committed
//! fixture, so it works in a temporary tree that owns its own copy. Both roots
//! that mutate — `index.rs` and `watcher.rs` — declare this file with `#[path]`
//! for the same reason [`crate::committed_fixture`] states.

use std::fs;
use std::path::Path;

use crate::committed_fixture::fixture_path;

/// Copy the committed fixture workspace `name` into a temporary directory that
/// owns it.
pub(crate) fn copy_fixture_to_temp(name: &str) -> tempfile::TempDir {
    let src = fixture_path(name);
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    copy_dir_recursive(&src, tmp.path()).expect("failed to copy fixture");
    tmp
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        match entry.file_type()?.is_dir() {
            true => {
                fs::create_dir_all(&target)?;
                copy_dir_recursive(&entry.path(), &target)?;
            }
            false => {
                fs::copy(entry.path(), &target)?;
            }
        }
    }
    Ok(())
}
