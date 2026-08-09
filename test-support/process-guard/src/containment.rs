use std::process::{Child, Command};
use std::time::{Duration, Instant};

use thiserror::Error;

const PROCESS_POLL: Duration = Duration::from_millis(25);

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
    /// Invalid process-group adoption was followed by failed child cleanup.
    #[error(
        "process-group adoption failed for child {pid}: {source}; uncontained child cleanup failed: {cleanup}"
    )]
    InvalidProcessGroupIdCleanup {
        /// The child process id.
        pid: u32,
        /// The failed integer conversion.
        #[source]
        source: std::num::TryFromIntError,
        /// The cleanup failure.
        cleanup: std::io::Error,
    },
    /// Windows refused to create a Job Object.
    #[error("job creation failed: {source}")]
    JobCreation {
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Job creation and subsequent child cleanup both failed.
    #[error("job creation failed: {source}; uncontained child cleanup failed: {cleanup}")]
    JobCreationCleanup {
        /// The job creation error.
        #[source]
        source: std::io::Error,
        /// The cleanup failure.
        cleanup: std::io::Error,
    },
    /// Windows refused the kill-on-close Job Object configuration.
    #[error("job limit configuration failed: {source}")]
    JobConfiguration {
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Job configuration and subsequent child cleanup both failed.
    #[error(
        "job limit configuration failed: {source}; uncontained child cleanup failed: {cleanup}"
    )]
    JobConfigurationCleanup {
        /// The job configuration error.
        #[source]
        source: std::io::Error,
        /// The cleanup failure.
        cleanup: std::io::Error,
    },
    /// Windows refused to assign the child to its Job Object.
    #[error("job assignment failed: {source}")]
    JobAssignment {
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Job assignment and subsequent child cleanup both failed.
    #[error("job assignment failed: {source}; uncontained child cleanup failed: {cleanup}")]
    JobAssignmentCleanup {
        /// The job assignment error.
        #[source]
        source: std::io::Error,
        /// The cleanup failure.
        cleanup: std::io::Error,
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
}

/// Configure a command so its future child can become a contained tree root.
#[cfg(unix)]
pub fn configure_child(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

/// Windows containment is assigned immediately after spawn.
#[cfg(windows)]
pub fn configure_child(_command: &mut Command) {}

/// The operating-system object that owns one child process tree.
#[cfg(unix)]
pub struct ContainedProcessTree {
    group_id: i32,
}

#[cfg(unix)]
impl ContainedProcessTree {
    /// Adopt a child configured by configure_child.
    pub fn adopt(child: &mut Child) -> Result<Self, ContainmentError> {
        let pid = child.id();
        let group_id =
            i32::try_from(pid).map_err(|source| invalid_process_group(pid, source, child))?;
        Ok(Self { group_id })
    }

    /// Kill every process in the contained tree.
    pub fn terminate(&self) -> Result<(), ContainmentError> {
        // SAFETY: killpg reads a process-group id and signal number. The id
        // belongs to the configured child this object adopted.
        let sent = unsafe { libc::killpg(self.group_id, libc::SIGKILL) };
        let source = std::io::Error::last_os_error();
        match (sent == 0, source.raw_os_error() == Some(libc::ESRCH)) {
            (true, _) | (false, true) => Ok(()),
            (false, false) => Err(ContainmentError::ProcessGroupTermination { source }),
        }
    }
}

#[cfg(unix)]
fn invalid_process_group(
    pid: u32,
    source: std::num::TryFromIntError,
    child: &mut Child,
) -> ContainmentError {
    match cleanup_uncontained_child(child) {
        Some(cleanup) => ContainmentError::InvalidProcessGroupIdCleanup {
            pid,
            source,
            cleanup,
        },
        None => ContainmentError::InvalidProcessGroupId { pid, source },
    }
}

/// Whether a process is still present.
#[cfg(unix)]
pub fn process_is_running(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal zero checks existence and permission without delivering a
    // signal or writing memory.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Wait until a watched process is gone or the budget expires.
pub fn wait_until_gone(pid: u32, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        match (process_is_running(pid), Instant::now() >= deadline) {
            (false, _) => return true,
            (true, true) => return false,
            (true, false) => std::thread::sleep(PROCESS_POLL),
        }
    }
}

/// The Windows Job Object that owns one child process tree.
#[cfg(windows)]
pub struct ContainedProcessTree {
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl ContainedProcessTree {
    /// Create, configure, and assign a Job Object to the child.
    pub fn adopt(child: &mut Child) -> Result<Self, ContainmentError> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        // SAFETY: the returned handle is checked before use and closed on
        // every configuration or assignment failure.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            let source = std::io::Error::last_os_error();
            return Err(job_creation(source, child));
        }

        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let size = match u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()) {
            Ok(size) => size,
            Err(source) => {
                // SAFETY: job is the live handle created above.
                unsafe { CloseHandle(job) };
                let source = std::io::Error::new(std::io::ErrorKind::InvalidInput, source);
                return Err(job_configuration(source, child));
            }
        };
        // SAFETY: job is live and limits is fully initialized for the
        // requested information class.
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                size,
            )
        };
        if configured == 0 {
            let source = std::io::Error::last_os_error();
            // SAFETY: job is the live handle created above.
            unsafe { CloseHandle(job) };
            return Err(job_configuration(source, child));
        }

        // SAFETY: both handles are live. Assignment either succeeds or leaves
        // this function to close the job and report the OS error.
        let assigned = unsafe { AssignProcessToJobObject(job, child.as_raw_handle().cast()) };
        if assigned == 0 {
            let source = std::io::Error::last_os_error();
            // SAFETY: job is the live handle created above.
            unsafe { CloseHandle(job) };
            return Err(job_assignment(source, child));
        }
        Ok(Self { job })
    }

    /// Kill every process in the contained Job Object.
    pub fn terminate(&self) -> Result<(), ContainmentError> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        // SAFETY: job remains live until this object's Drop.
        match unsafe { TerminateJobObject(self.job, 1) } {
            0 => Err(ContainmentError::JobTermination {
                source: std::io::Error::last_os_error(),
            }),
            _ => Ok(()),
        }
    }
}

#[cfg(windows)]
fn job_creation(source: std::io::Error, child: &mut Child) -> ContainmentError {
    match cleanup_uncontained_child(child) {
        Some(cleanup) => ContainmentError::JobCreationCleanup { source, cleanup },
        None => ContainmentError::JobCreation { source },
    }
}

#[cfg(windows)]
fn job_configuration(source: std::io::Error, child: &mut Child) -> ContainmentError {
    match cleanup_uncontained_child(child) {
        Some(cleanup) => ContainmentError::JobConfigurationCleanup { source, cleanup },
        None => ContainmentError::JobConfiguration { source },
    }
}

#[cfg(windows)]
fn job_assignment(source: std::io::Error, child: &mut Child) -> ContainmentError {
    match cleanup_uncontained_child(child) {
        Some(cleanup) => ContainmentError::JobAssignmentCleanup { source, cleanup },
        None => ContainmentError::JobAssignment { source },
    }
}

fn cleanup_uncontained_child(child: &mut Child) -> Option<std::io::Error> {
    match child.try_wait() {
        Ok(Some(_)) => None,
        Ok(None) => kill_and_reap(child),
        Err(error) => Some(error),
    }
}

fn kill_and_reap(child: &mut Child) -> Option<std::io::Error> {
    match child.kill() {
        Ok(()) => child.wait().err(),
        Err(error) => Some(error),
    }
}

#[cfg(windows)]
impl Drop for ContainedProcessTree {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        // SAFETY: job is owned by this object and closed exactly once.
        unsafe { CloseHandle(self.job) };
    }
}

/// Whether a process is still present.
#[cfg(windows)]
pub fn process_is_running(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const STILL_ACTIVE: u32 = 259;

    // SAFETY: the handle is checked, queried into initialized storage, and
    // closed before returning.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut status = 0_u32;
        let read = GetExitCodeProcess(handle, &raw mut status);
        CloseHandle(handle);
        read != 0 && status == STILL_ACTIVE
    }
}
