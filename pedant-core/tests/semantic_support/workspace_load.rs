//! Serialization of rust-analyzer workspace construction in this test binary.

use std::path::Path;
use std::sync::{Condvar, Mutex, MutexGuard};

use pedant_core::SemanticContext;

const MAX_CONCURRENT_WORKSPACE_LOADS: usize = 1;

struct WorkspaceLoadOwner {
    active: Mutex<usize>,
    available: Condvar,
}

impl WorkspaceLoadOwner {
    const fn new() -> Self {
        Self {
            active: Mutex::new(0),
            available: Condvar::new(),
        }
    }

    fn acquire(&self) -> WorkspaceLoadPermit<'_> {
        let mut active = recovered_lock(&self.active);
        while *active >= MAX_CONCURRENT_WORKSPACE_LOADS {
            active = match self.available.wait(active) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        *active += 1;
        WorkspaceLoadPermit { owner: self }
    }
}

struct WorkspaceLoadPermit<'a> {
    owner: &'a WorkspaceLoadOwner,
}

impl Drop for WorkspaceLoadPermit<'_> {
    fn drop(&mut self) {
        let mut active = recovered_lock(&self.owner.active);
        *active = active.saturating_sub(1);
        self.owner.available.notify_one();
    }
}

static WORKSPACE_LOADS: WorkspaceLoadOwner = WorkspaceLoadOwner::new();

pub(crate) fn load(root: &Path) -> Option<SemanticContext> {
    let permit = WORKSPACE_LOADS.acquire();
    let context = SemanticContext::load(root);
    drop(permit);
    context
}

pub(crate) fn recovered_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
