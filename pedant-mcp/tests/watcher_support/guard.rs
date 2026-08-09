//! One owner for a live watcher, its shared index, and the workspace it walks.
//!
//! The guard exists so a watcher can never outlive the temporary directory it
//! watches. Teardown drops the event source first, waits under a bound until
//! the index has exactly one owner — proving the watcher's callback and its
//! thread are gone — and only then releases the workspace. Observation helpers
//! return `Result` while the watcher is live so a failure tears down before it
//! is asserted on.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use pedant_mcp::index::WorkspaceIndex;

/// Bound on every wait this guard performs.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval for both index observation and teardown.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Owns the watcher, the shared index, and the temporary workspace.
///
/// `W` is the concrete watcher `start_watcher` returns. It stays generic
/// because the notification backend is an implementation detail of
/// `pedant-mcp` that an integration test cannot name.
pub(crate) struct WatcherGuard<W> {
    watcher: Option<W>,
    index: Arc<RwLock<WorkspaceIndex>>,
    workspace: Option<tempfile::TempDir>,
    root: PathBuf,
}

impl<W> WatcherGuard<W> {
    /// Take ownership of a started watcher and everything it depends on.
    ///
    /// `index` must be the only other handle to the shared index, so the
    /// teardown ownership check is exact.
    pub(crate) fn adopt(
        workspace: tempfile::TempDir,
        root: PathBuf,
        index: Arc<RwLock<WorkspaceIndex>>,
        watcher: W,
    ) -> Self {
        Self {
            watcher: Some(watcher),
            index,
            workspace: Some(workspace),
            root,
        }
    }

    /// Canonical workspace root the watcher and index agree on.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Read one fact from the index while the watcher is live.
    ///
    /// A state the watcher is required to hold already is read once instead of
    /// waited for: [`Self::wait_for`] would retry a fact that has to be true on
    /// the first look, and would report a timeout for what is a wrong answer.
    pub(crate) fn read<T>(&self, view: impl FnOnce(&WorkspaceIndex) -> T) -> Result<T, Box<str>> {
        self.index
            .read()
            .map_err(|_| Box::<str>::from("index lock poisoned"))
            .map(|index| view(&index))
    }

    /// Wait until the index satisfies `predicate`, or report the bound failure.
    pub(crate) fn wait_for(
        &self,
        description: &str,
        predicate: impl Fn(&WorkspaceIndex) -> bool,
    ) -> Result<(), Box<str>> {
        let deadline = Instant::now() + TEARDOWN_TIMEOUT;
        loop {
            match (self.read(&predicate)?, Instant::now() < deadline) {
                (true, _) => return Ok(()),
                (false, true) => thread::sleep(POLL_INTERVAL),
                (false, false) => {
                    return Err(format!("watcher never reached state: {description}").into());
                }
            }
        }
    }

    /// Stop watching, prove no watcher thread retains the index, then release
    /// the workspace. Returns an error instead of panicking so the caller can
    /// assert after teardown finishes.
    pub(crate) fn shut_down(mut self) -> Result<(), Box<str>> {
        let outcome = self.tear_down();
        drop(self.workspace.take());
        outcome
    }

    /// Drop the event source and wait for sole ownership of the index.
    fn tear_down(&mut self) -> Result<(), Box<str>> {
        drop(self.watcher.take());
        let deadline = Instant::now() + TEARDOWN_TIMEOUT;
        loop {
            match (Arc::strong_count(&self.index), Instant::now() < deadline) {
                (1, _) => return Ok(()),
                (_, true) => thread::sleep(POLL_INTERVAL),
                (count, false) => {
                    return Err(format!(
                        "watcher still holds the index after shutdown: {count} owners"
                    )
                    .into());
                }
            }
        }
    }
}

impl<W> Drop for WatcherGuard<W> {
    /// Bounded teardown on the panic and early-return paths too: the event
    /// source always goes first, then the workspace.
    fn drop(&mut self) {
        drop(self.watcher.take());
        drop(self.workspace.take());
    }
}
