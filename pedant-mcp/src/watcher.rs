use std::io::Write;
use std::path::Path;
use std::sync::{Arc, RwLock};

use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use thiserror::Error;

use crate::index::{IndexError, WorkspaceIndex};

/// Failure modes for the file watcher subsystem.
#[derive(Debug, Error)]
pub enum WatcherError {
    /// The workspace index `RwLock` was poisoned by a panicking thread.
    #[error("index lock poisoned")]
    LockPoisoned,
    /// The OS file notification layer reported an error.
    #[error("file watcher error: {0}")]
    Notify(#[from] notify::Error),
    /// Incremental reindex failed for a changed file.
    #[error("failed to reindex {path}: {source}")]
    Reindex {
        /// Path of the file that could not be reindexed.
        path: Box<str>,
        /// Underlying index update failure.
        source: IndexError,
    },
}

/// Begin watching crate `src/` dirs and `build.rs` for `.rs` file changes.
///
/// Returns the watcher handle; dropping it stops watching.
pub fn start_watcher(
    index: &Arc<RwLock<WorkspaceIndex>>,
) -> Result<RecommendedWatcher, WatcherError> {
    let watch_roots: Vec<std::path::PathBuf> = {
        let idx = index.read().map_err(|_| WatcherError::LockPoisoned)?;
        idx.crate_roots().map(Path::to_path_buf).collect()
    };

    let index = Arc::clone(index);
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        let event = match res {
            Ok(e) => e,
            Err(error) => {
                report_watcher_error(&WatcherError::Notify(error));
                return;
            }
        };
        handle_fs_event(&event, &index);
    })?;

    for root in &watch_roots {
        let src_dir = root.join("src");
        if src_dir.is_dir() {
            watcher.watch(&src_dir, RecursiveMode::Recursive)?;
        }
        let build_rs = root.join("build.rs");
        if build_rs.is_file() {
            watcher.watch(&build_rs, RecursiveMode::NonRecursive)?;
        }
    }

    Ok(watcher)
}

/// Process a single filesystem event, updating the index as needed.
///
/// Every Rust-source event is applied in delivery order. Skipping a later event
/// can leave the index at an intermediate state from a multi-event write.
fn handle_fs_event(event: &Event, index: &Arc<RwLock<WorkspaceIndex>>) {
    let actionable: Box<[&std::path::Path]> = event
        .paths
        .iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .map(|path| path.as_path())
        .collect();

    if actionable.is_empty() {
        return;
    }

    let mut idx = match index.write() {
        Ok(guard) => guard,
        Err(_) => {
            report_watcher_error(&WatcherError::LockPoisoned);
            return;
        }
    };

    for path in actionable {
        match event.kind {
            EventKind::Remove(_) => {
                idx.remove_file(path);
            }
            EventKind::Modify(ModifyKind::Name(_)) => {
                handle_rename_like_modify(path, &mut idx);
            }
            EventKind::Create(_) | EventKind::Modify(_) => {
                reindex_changed_file(path, &mut idx);
            }
            _ => {}
        }
    }
}

fn handle_rename_like_modify(path: &Path, index: &mut WorkspaceIndex) {
    match path.exists() {
        true => reindex_changed_file(path, index),
        false => {
            index.remove_file(path);
        }
    }
}

fn reindex_changed_file(path: &Path, index: &mut WorkspaceIndex) {
    match index.reindex_file(path) {
        Ok(()) => {}
        Err(source) => {
            index.mark_file_degraded(path, &source);
            report_watcher_error(&WatcherError::Reindex {
                path: path.to_string_lossy().into(),
                source,
            });
        }
    }
}

fn report_watcher_error(error: &WatcherError) {
    drop(writeln!(std::io::stderr(), "warning: {error}"));
}
