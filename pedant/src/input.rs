//! Resolution of CLI path arguments into a concrete file list.
//!
//! Callers name files or directories; directories are searched recursively for
//! anything pedant can classify. Doing this here rather than leaving it to shell
//! globbing keeps every caller — CLI, CI step, composite action — on identical
//! discovery rules. A `**` glob is not a portable substitute: it needs bash 4's
//! `globstar`, and where that is off (macOS ships bash 3.2) it silently degrades
//! to `*` and skips every nested file without a word.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use pedant_lang::FileClassification;

/// Marker file that cargo and other build tools write into cache directories.
const CACHE_DIR_TAG: &str = "CACHEDIR.TAG";

/// JavaScript dependency tree, never project source.
const NODE_MODULES: &str = "node_modules";

/// Failure while turning CLI path arguments into a file list.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InputError {
    /// A path named on the command line does not exist.
    #[error("path does not exist: {path}")]
    NotFound {
        /// The offending path, as the caller wrote it.
        path: Box<str>,
    },
    /// A directory could not be read while recursing.
    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        /// The directory that could not be read.
        path: Box<str>,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The given paths exist but hold nothing pedant can analyze.
    #[error("no analyzable files found under: {paths}")]
    Empty {
        /// The paths that were searched.
        paths: Box<str>,
    },
}

/// Accumulates resolved files, collapsing paths that name the same file.
#[derive(Default)]
struct Resolved {
    seen: BTreeSet<PathBuf>,
    files: Vec<String>,
}

impl Resolved {
    /// Record a file, ignoring it if an earlier path already named it.
    ///
    /// De-duplication keys on the canonical path, so a file reachable from two
    /// roots is analyzed once instead of having every violation reported twice.
    /// The path is *stored* as the caller wrote it: annotations must stay
    /// relative to the working directory for a forge to anchor them to a diff.
    fn insert(&mut self, path: &Path) {
        let key = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if self.seen.insert(key) {
            self.files.push(path.display().to_string());
        }
    }

    fn into_sorted(mut self) -> Vec<String> {
        self.files.sort();
        self.files
    }
}

/// A file is analyzable when pedant recognizes it as source or as a manifest.
fn is_analyzable(path: &Path) -> bool {
    !matches!(
        pedant_lang::classify_path(path),
        FileClassification::Unsupported
    )
}

/// Whether recursion should descend into `dir`.
///
/// Build directories are identified by the `CACHEDIR.TAG` marker cargo writes,
/// not by the name `target`: a crate may legitimately hold a `src/target/`
/// module, and skipping it by name would drop real source without a word.
fn is_skipped_dir(dir: &Path) -> bool {
    let name = dir.file_name().and_then(|name| name.to_str()).unwrap_or("");
    name.starts_with('.') || name == NODE_MODULES || dir.join(CACHE_DIR_TAG).exists()
}

fn read_dir_error(dir: &Path) -> impl FnOnce(std::io::Error) -> InputError + '_ {
    move |source| InputError::ReadDir {
        path: dir.display().to_string().into_boxed_str(),
        source,
    }
}

/// Recursively collect analyzable files beneath `dir`.
fn walk(dir: &Path, acc: &mut Resolved) -> Result<(), InputError> {
    for entry in fs::read_dir(dir).map_err(read_dir_error(dir))? {
        let path = entry.map_err(read_dir_error(dir))?.path();
        match (path.is_dir(), is_analyzable(&path)) {
            (true, _) if is_skipped_dir(&path) => {}
            (true, _) => walk(&path, acc)?,
            (false, true) => acc.insert(&path),
            (false, false) => {}
        }
    }
    Ok(())
}

/// Expand CLI path arguments into a sorted, de-duplicated file list.
///
/// A file named explicitly is always kept, even where it sits inside a directory
/// that recursion would skip: naming it is a clearer signal of intent than the
/// skip heuristics are. Directories are searched recursively.
pub(crate) fn resolve(paths: &[String]) -> Result<Vec<String>, InputError> {
    let mut acc = Resolved::default();

    for path in paths {
        let candidate = Path::new(path.as_str());
        match (candidate.is_dir(), candidate.exists()) {
            (true, _) => walk(candidate, &mut acc)?,
            (false, true) => acc.insert(candidate),
            (false, false) => {
                return Err(InputError::NotFound {
                    path: path.as_str().into(),
                });
            }
        }
    }

    let files = acc.into_sorted();
    match files.is_empty() {
        true => Err(InputError::Empty {
            paths: paths.join(", ").into_boxed_str(),
        }),
        false => Ok(files),
    }
}
