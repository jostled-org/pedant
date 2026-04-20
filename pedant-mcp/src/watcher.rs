use std::io::Write;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use pedant_core::Config;
use thiserror::Error;

use crate::index::{IndexError, WorkspaceIndex};

/// Minimum interval between reindex operations for the same file.
const DEBOUNCE_INTERVAL_MS: u128 = 100;

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
    config: Arc<Config>,
) -> Result<RecommendedWatcher, WatcherError> {
    let watch_roots: Vec<std::path::PathBuf> = {
        let idx = index.read().map_err(|_| WatcherError::LockPoisoned)?;
        idx.crate_roots().map(Path::to_path_buf).collect()
    };

    let index = Arc::clone(index);
    let last_reindex: Arc<RwLock<std::collections::BTreeMap<std::path::PathBuf, Instant>>> =
        Arc::new(RwLock::new(std::collections::BTreeMap::new()));
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        let event = match res {
            Ok(e) => e,
            Err(error) => {
                report_watcher_error(&WatcherError::Notify(error));
                return;
            }
        };
        handle_fs_event(&event, &index, &config, &last_reindex);
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
/// Events within `DEBOUNCE_INTERVAL_MS` of the last reindex for the same file
/// are skipped to avoid redundant work from rapid successive writes.
fn handle_fs_event(
    event: &Event,
    index: &Arc<RwLock<WorkspaceIndex>>,
    config: &Config,
    last_reindex: &Arc<RwLock<std::collections::BTreeMap<std::path::PathBuf, Instant>>>,
) {
    let now = Instant::now();

    // Check debounce timestamps before acquiring the expensive index write lock.
    let actionable: Vec<&std::path::Path> = {
        let timestamps = match last_reindex.read() {
            Ok(guard) => guard,
            Err(_) => {
                report_watcher_error(&WatcherError::LockPoisoned);
                return;
            }
        };
        event
            .paths
            .iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "rs"))
            .filter(|p| {
                timestamps.get(p.as_path()).is_none_or(|last| {
                    now.duration_since(*last).as_millis() >= DEBOUNCE_INTERVAL_MS
                })
            })
            .map(|p| p.as_path())
            .collect()
    };

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

    let mut timestamps = match last_reindex.write() {
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
                timestamps.remove(path);
            }
            EventKind::Modify(ModifyKind::Name(_)) => {
                handle_rename_like_modify(path, &mut idx, config, &mut timestamps, now);
            }
            EventKind::Create(_) | EventKind::Modify(_) => {
                reindex_changed_file(path, &mut idx, config, &mut timestamps, now);
            }
            _ => {}
        }
    }
}

fn handle_rename_like_modify(
    path: &Path,
    index: &mut WorkspaceIndex,
    config: &Config,
    timestamps: &mut std::collections::BTreeMap<std::path::PathBuf, Instant>,
    now: Instant,
) {
    match path.exists() {
        true => reindex_changed_file(path, index, config, timestamps, now),
        false => {
            index.remove_file(path);
            timestamps.remove(path);
        }
    }
}

fn reindex_changed_file(
    path: &Path,
    index: &mut WorkspaceIndex,
    config: &Config,
    timestamps: &mut std::collections::BTreeMap<std::path::PathBuf, Instant>,
    now: Instant,
) {
    match index.reindex_file(path, config) {
        Ok(()) => {
            timestamps.insert(path.to_path_buf(), now);
        }
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
