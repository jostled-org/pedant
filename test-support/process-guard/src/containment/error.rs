//! Every way an operating system can refuse to create or control containment.

use thiserror::Error;

/// An operating-system refusal while creating or controlling containment.
#[derive(Debug, Error)]
pub enum ContainmentError {
    /// A Unix child process id could not name its process group.
    #[error("process-group adoption failed for child {pid}: {source}")]
    InvalidProcessGroupId {
        /// The child process id.
        pid: u32,
        /// The failed integer conversion.
        #[source]
        source: std::num::TryFromIntError,
    },
    /// A Unix child does not lead the process group it would be contained by.
    ///
    /// Containment on that host *is* the process group the child leads, and a
    /// child leads one only when its command passed through `configure_child`.
    /// An unconfigured child stays in its parent's group, where every later
    /// question is answered about the parent rather than about the tree.
    #[error("child {pid} leads no process group of its own; the kernel reports group {group}")]
    UnledProcessGroup {
        /// The child process id.
        pid: u32,
        /// The process group the kernel reports for the child, or -1 when it
        /// refused the question.
        group: i32,
    },
    /// Unix refused to determine whether an exited child's group remains.
    #[error("process-group inspection failed for child {pid}: {source}")]
    ProcessGroupInspection {
        /// The child process id.
        pid: u32,
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// A Windows child handle named no process id.
    #[error("the child handle names no process id: {source}")]
    UnnamedChild {
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Windows refused to create a Job Object.
    #[error("job creation failed: {source}")]
    JobCreation {
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Windows refused the kill-on-close Job Object configuration.
    #[error("job limit configuration failed: {source}")]
    JobConfiguration {
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Windows refused to assign the child to its Job Object.
    #[error("job assignment failed: {source}")]
    JobAssignment {
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Windows could not enumerate the suspended child's primary thread.
    #[error("failed to enumerate the suspended child thread: {source}")]
    ThreadEnumeration {
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Windows found no thread owned by the suspended child.
    #[error("the suspended child {pid} has no primary thread")]
    MissingPrimaryThread {
        /// The child process id.
        pid: u32,
    },
    /// Windows could not open the suspended child's primary thread.
    #[error("failed to open suspended thread {thread}: {source}")]
    ThreadOpen {
        /// The thread id.
        thread: u32,
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Windows could not resume the child after assigning its Job Object.
    #[error("failed to resume suspended thread {thread}: {source}")]
    ThreadResume {
        /// The thread id.
        thread: u32,
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Windows resumed a thread whose suspension state did not match the
    /// configured child contract.
    #[error("suspended thread {thread} had unexpected suspend count {count}")]
    UnexpectedThreadSuspendCount {
        /// The thread id.
        thread: u32,
        /// The count returned by `ResumeThread` before it decremented it.
        count: u32,
    },
    /// Unix refused to terminate the process group.
    #[error("process-group termination failed: {source}")]
    ProcessGroupTermination {
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Windows refused to terminate the Job Object.
    #[error("job termination failed: {source}")]
    JobTermination {
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// An adoption refusal was followed by failed cleanup of the child it left.
    ///
    /// One variant carrying the refusal, rather than a `*Cleanup` twin of every
    /// refusal that can leave a child behind. The cleanup is the same act
    /// whichever refusal ordered it, and the twins needed a mapper whose
    /// catch-all arm dropped the cleanup error rather than reporting it.
    #[error("{refusal}; uncontained child cleanup failed: {cleanup}")]
    Cleanup {
        /// The refusal that left the child uncontained.
        #[source]
        refusal: Box<ContainmentError>,
        /// The cleanup failure.
        cleanup: std::io::Error,
    },
}
