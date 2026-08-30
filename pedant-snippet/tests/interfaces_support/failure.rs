//! The budget every live-child operation is held to, and why one did not answer.
//!
//! Nothing this root does to a child is unbounded. A read, a write, a wait, and
//! a drain each finish inside one budget or say which one they were, because a
//! harness that parked forever on a server that stopped talking would report a
//! hung suite rather than the failing predicate underneath it.
//!
//! The failure is stated here rather than beside the child harness because
//! three owners produce one: the harness that spawns and reaps, the containment
//! that adopts and ends a process tree, and the client that reads a protocol
//! over the pipes between them.

use std::future::Future;
use std::time::Duration;

use pedant_process_guard::ContainmentError;
use tokio::time::timeout;

/// Every read, write, and wait in this harness is bounded by this budget.
pub const BUDGET: Duration = Duration::from_secs(30);

/// Why a live-child operation could not produce its result.
///
/// Every mode names the operation it belongs to. A message that said only
/// "child I/O failed: No such file or directory" would leave a reader unable to
/// tell a spawn that never found the binary from a read that lost its pipe.
#[derive(Debug)]
pub enum Failure {
    /// The operating system refused the named spawn, read, write, or wait.
    Io {
        /// The operation the harness was performing.
        operation: &'static str,
        /// What the operating system reported.
        error: std::io::Error,
    },
    /// The operating system refused to create or end the child's process tree.
    Containment(ContainmentError),
    /// The named operation did not finish inside [`BUDGET`].
    Timeout(&'static str),
    /// The child produced output this harness cannot interpret.
    Protocol(Box<str>),
}

impl Failure {
    /// Name the case a live-child failure belongs to.
    ///
    /// [`Failure`] names the operation — the spawn, the run, the recv — and a
    /// journey loop runs the same operation once per row, so the operation alone
    /// cannot say which row stopped. This folds the row in: `label` is the case,
    /// `detail` the run it made. The `format!` runs on the error path only, so a
    /// journey that answers allocates nothing here.
    pub fn during(self, label: &str, detail: &str) -> Self {
        Self::Protocol(format!("{label} ({detail}): {self}").into())
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { operation, error } => write!(formatter, "{operation} failed: {error}"),
            Self::Containment(error) => write!(formatter, "the containment failed: {error}"),
            Self::Timeout(operation) => {
                write!(formatter, "{operation} exceeded {}s", BUDGET.as_secs())
            }
            Self::Protocol(detail) => write!(formatter, "protocol failure: {detail}"),
        }
    }
}

/// One I/O failure, named by the operation that produced it.
pub fn io(operation: &'static str) -> impl Fn(std::io::Error) -> Failure {
    move |error| Failure::Io { operation, error }
}

/// Await `work` inside [`BUDGET`], naming `operation` in either failure.
pub async fn bounded<T>(
    operation: &'static str,
    work: impl Future<Output = std::io::Result<T>>,
) -> Result<T, Failure> {
    timeout(BUDGET, work)
        .await
        .map_err(|_| Failure::Timeout(operation))?
        .map_err(io(operation))
}
