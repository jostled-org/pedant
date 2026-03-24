use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use pedant_core::Config;
use thiserror::Error;

use crate::index::WorkspaceIndex;

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
            Err(_) => return,
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
    let has_rs = event
        .paths
        .iter()
        .any(|p| p.extension().is_some_and(|ext| ext == "rs"));

    match has_rs {
        true => {}
        false => return,
    }

    let now = Instant::now();

    // Check debounce timestamps before acquiring the expensive index write lock.
    let actionable: Vec<&std::path::Path> = {
        let timestamps = match last_reindex.read() {
            Ok(guard) => guard,
            Err(_) => return,
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
        Err(_) => return,
    };

    let mut timestamps = match last_reindex.write() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    for path in &actionable {
        match event.kind {
            EventKind::Remove(_) => {
                idx.remove_file(path);
                timestamps.remove(*path);
            }
            EventKind::Create(_) | EventKind::Modify(_) => {
                drop(idx.reindex_file(path, config));
                timestamps.insert(path.to_path_buf(), now);
            }
            _ => {}
        }
    }
}
