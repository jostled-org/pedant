use std::fs;
use std::path::Path;

use super::error::{SupplyChainError, path_text};

/// Read a directory into a name-ordered listing so hashes stay reproducible.
pub(super) fn read_dir_sorted(path: &Path) -> Result<Vec<fs::DirEntry>, SupplyChainError> {
    let mut entries = fs::read_dir(path)
        .map_err(read_dir_error(path))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(read_dir_error(path))?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

pub(super) fn read_dir_error(path: &Path) -> impl Fn(std::io::Error) -> SupplyChainError {
    let path = path_text(path);
    move |source| SupplyChainError::ReadDir {
        path: path.clone(),
        source,
    }
}

/// Classify an entry, mapping IO failures onto the owning directory.
pub(super) fn entry_file_type(
    entry: &fs::DirEntry,
    parent: &Path,
) -> Result<fs::FileType, SupplyChainError> {
    entry.file_type().map_err(read_dir_error(parent))
}
