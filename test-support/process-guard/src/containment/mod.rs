//! Operating-system containment for one child process tree.
//!
//! One question runs through every module here: what does the tree a guarded
//! child rooted still hold? Each host answers it with its own object — a
//! process group on Unix, a Job Object on Windows — and the surface below is
//! spelled the same on both, so a caller states the claim once and the host
//! decides what enforces it.
//!
//! Both hosts contain the tree before child code can run. Unix applies its
//! process group before exec. Windows starts the child suspended, assigns its
//! Job Object, and resumes it only after assignment succeeds.
//!
//! What both hosts do owe is one direction on every liveness question: an
//! answer that went unread reads as *present*, never as gone. Absence is the
//! one answer that lets a caller stop waiting and call a tree clean, so no
//! refusal, no unnameable identity, and no truncated read may give it.

mod adopt;
mod cleanup;
mod error;
#[cfg(windows)]
mod job_members;
mod liveness;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use adopt::adopt_child;
pub use error::ContainmentError;
pub use liveness::{tree_is_live, wait_until_gone, wait_until_released};
#[cfg(unix)]
use unix::process_is_running;
#[cfg(unix)]
pub use unix::{ChildContainment, ContainedProcessTree, configure_child};
#[cfg(windows)]
use windows::process_is_running;
#[cfg(windows)]
pub use windows::{ChildContainment, ContainedProcessTree, configure_child};
