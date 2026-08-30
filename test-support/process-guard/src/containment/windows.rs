//! Containment on a host whose process tree is a Job Object.
//!
//! A Windows tree is an anonymous Job Object held by its owner. Liveness is
//! asked through that owner so another process cannot retain the Job handle and
//! defeat kill-on-close cleanup.
//!
//! The child starts suspended. Adoption creates and configures its Job Object,
//! assigns the suspended process, and resumes its primary thread only after the
//! assignment succeeds. No child code can start a descendant outside the job.

use std::process::{Child, Command};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
    SetLastError, WIN32_ERROR,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, GetExitCodeProcess, GetProcessId, OpenProcess, OpenThread,
    PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread, THREAD_SUSPEND_RESUME,
};

use super::error::ContainmentError;
use super::job_members::job_holds_a_live_member;

/// Configure a command to start suspended until its Job Object owns it.
pub fn configure_child(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    command.creation_flags(CREATE_SUSPENDED);
}

/// What this host names a spawned child by, for the purpose of containing it.
///
/// An opaque struct rather than a published `RawHandle` alias. The alias made
/// `adopting` a safe function taking `*mut c_void`, which every value of that
/// type type-checks against, so a safe caller could hand it any pointer and
/// have this crate assign the process behind it to a job. The one constructor
/// is unsafe instead, and a caller states its handle's validity once, where it
/// holds the child that proves it.
#[derive(Clone, Copy, Debug)]
pub struct ChildContainment {
    handle: std::os::windows::io::RawHandle,
}

impl ChildContainment {
    /// Name a child by the process handle its owner holds.
    ///
    /// # Safety
    ///
    /// `handle` must be an open handle to a process started with
    /// `CREATE_SUSPENDED`, carrying at least `PROCESS_SET_QUOTA` and
    /// `PROCESS_TERMINATE` access. It must stay open while this name is used.
    pub unsafe fn from_raw_handle(handle: std::os::windows::io::RawHandle) -> Self {
        Self { handle }
    }
}

/// The Windows Job Object that owns one child process tree.
pub struct ContainedProcessTree {
    root_pid: u32,
    job: HANDLE,
}

impl ContainedProcessTree {
    /// Create, configure, and assign a Job Object, named by the child's handle.
    ///
    /// Nothing is cleaned up here: a caller that named a child rather than
    /// lending one is the only owner in a position to end it.
    ///
    /// Each step owns its own refusal and hands the job it was given to
    /// [`closing`] when it refuses, so a fourth step cannot leak the handle by
    /// forgetting a rule written beside the three before it.
    pub fn adopting(child: ChildContainment) -> Result<Self, ContainmentError> {
        let root_pid = process_id(child)?;
        let created = created_job()?;
        let configured = configured_job(created)?;
        let assigned = assigned_job(configured, child)?;
        let job = resumed_job(assigned, root_pid)?;
        Ok(Self { root_pid, job })
    }

    /// The process id this tree is named by.
    ///
    /// Published because each consumer's wrapper reports it: the containment is
    /// what named the tree, so a wrapper that also recorded the pid held a
    /// second record of one identity with nothing keeping the two in step.
    pub fn root(&self) -> u32 {
        self.root_pid
    }

    /// Kill every process in the contained Job Object.
    pub fn terminate(&self) -> Result<(), ContainmentError> {
        // SAFETY: job remains live until this object's Drop.
        match unsafe { TerminateJobObject(self.job, 1) } {
            0 => Err(ContainmentError::JobTermination {
                source: std::io::Error::last_os_error(),
            }),
            _ => Ok(()),
        }
    }

    /// Whether the owned Job Object still holds a live member.
    pub(super) fn is_running(&self) -> bool {
        job_holds_a_live_member(self.job)
    }
}

/// End the tree, then release the handle that named it.
///
/// Explicit termination provides deterministic teardown. Kill-on-close covers
/// process exit paths that cannot run Rust cleanup.
impl Drop for ContainedProcessTree {
    fn drop(&mut self) {
        std::mem::drop(self.terminate());
        // SAFETY: job is owned by this object and closed exactly once, here.
        unsafe { CloseHandle(self.job) };
    }
}

/// Create the anonymous Job Object this tree owns.
fn created_job() -> Result<HANDLE, ContainmentError> {
    // SAFETY: null security and name pointers request an anonymous Job Object.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    match job.is_null() {
        true => Err(ContainmentError::JobCreation {
            source: std::io::Error::last_os_error(),
        }),
        false => Ok(job),
    }
}

/// The width `SetInformationJobObject` takes the extended-limit structure at.
///
/// A compile-time constant of about 144 bytes on every layout this crate builds
/// for, proved here rather than converted at each adoption. A runtime
/// conversion that cannot fail still needed an arm to file the impossible case
/// under, and the only fitting variant was `JobConfiguration`, which names the
/// operating system refusing the call and nothing else.
const LIMITS_SIZE: u32 = size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;

/// The width above is the whole structure, not a truncation of it.
const _: () = assert!(LIMITS_SIZE as usize == size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>());

/// Configure the created job to end its members when its last handle closes.
///
/// The limit is what ends a tree whose owner died without running any Rust at
/// all. It is not what `Drop` relies on, for the reason `Drop` records.
fn configured_job(job: HANDLE) -> Result<HANDLE, ContainmentError> {
    // SAFETY: zeroed is the documented starting state for this information
    // class, and the one field the call reads is written below.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: job is live, limits is fully initialized for the requested
    // information class, and LIMITS_SIZE is that class's own proved width.
    let configured = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&limits).cast(),
            LIMITS_SIZE,
        )
    };
    match configured {
        0 => {
            let source = std::io::Error::last_os_error();
            Err(closing(job, ContainmentError::JobConfiguration { source }))
        }
        _ => Ok(job),
    }
}

/// Assign the named child to the job that owns its tree from here on.
fn assigned_job(job: HANDLE, child: ChildContainment) -> Result<HANDLE, ContainmentError> {
    // SAFETY: both handles are live. Assignment either succeeds or leaves the
    // job to `closing`, which releases it before the refusal travels.
    let assigned = unsafe { AssignProcessToJobObject(job, child.handle.cast()) };
    match assigned {
        0 => {
            let source = std::io::Error::last_os_error();
            Err(closing(job, ContainmentError::JobAssignment { source }))
        }
        _ => Ok(job),
    }
}

/// Resume the primary thread only after assignment made containment atomic.
fn resumed_job(job: HANDLE, process: u32) -> Result<HANDLE, ContainmentError> {
    match resume_primary_thread(process) {
        Ok(()) => Ok(job),
        Err(refusal) => Err(closing(job, refusal)),
    }
}

/// Find and resume the one thread a newly created suspended process owns.
fn resume_primary_thread(process: u32) -> Result<(), ContainmentError> {
    // SAFETY: the call returns a new snapshot handle and reads no caller memory.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(ContainmentError::ThreadEnumeration {
            source: std::io::Error::last_os_error(),
        });
    }
    let thread = primary_thread(snapshot, process);
    // SAFETY: snapshot is the handle opened above and is closed exactly once,
    // after enumeration no longer reads it.
    unsafe { CloseHandle(snapshot) };
    let thread = thread?;
    // SAFETY: the id came from the live system snapshot. The returned handle
    // is checked before use and owned by `thread_handle`.
    let thread_handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread) };
    if thread_handle.is_null() {
        return Err(ContainmentError::ThreadOpen {
            thread,
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: the handle grants THREAD_SUSPEND_RESUME and remains live across
    // the call. `u32::MAX` is the documented failure result.
    let resumed = unsafe { ResumeThread(thread_handle) };
    // SAFETY: thread_handle is the handle opened above and is closed exactly
    // once, after the resume call no longer reads it.
    unsafe { CloseHandle(thread_handle) };
    match resumed {
        1 => Ok(()),
        u32::MAX => Err(ContainmentError::ThreadResume {
            thread,
            source: std::io::Error::last_os_error(),
        }),
        count => Err(ContainmentError::UnexpectedThreadSuspendCount { thread, count }),
    }
}

/// The first thread the system snapshot reports for `process`.
fn primary_thread(snapshot: HANDLE, process: u32) -> Result<u32, ContainmentError> {
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    // SAFETY: snapshot is live and entry is initialized to the structure size
    // the API requires before it writes the remaining fields.
    unsafe { SetLastError(0) };
    let first = unsafe { Thread32First(snapshot, &raw mut entry) };
    if first == 0 {
        return Err(enumeration_end(process));
    }
    loop {
        if entry.th32OwnerProcessID == process {
            return Ok(entry.th32ThreadID);
        }
        // SAFETY: the same live snapshot and initialized entry are reused for
        // the next record. A zero result means the enumeration is exhausted.
        unsafe { SetLastError(0) };
        let next = unsafe { Thread32Next(snapshot, &raw mut entry) };
        if next == 0 {
            return Err(enumeration_end(process));
        }
    }
}

/// Classify the end of a ToolHelp thread enumeration.
fn enumeration_end(process: u32) -> ContainmentError {
    let source = std::io::Error::last_os_error();
    match os_error_is(&source, ERROR_NO_MORE_FILES) {
        true => ContainmentError::MissingPrimaryThread { pid: process },
        false => ContainmentError::ThreadEnumeration { source },
    }
}

/// Release a job handle no tree ended up owning, and report why.
///
/// Every adoption step after creation is handed a live job and every one of
/// them can refuse, so the release is stated once here rather than hand-written
/// beside each refusal. A step added later releases the handle whether or not
/// its author remembered the rule.
///
/// The refusal arrives already built: `CloseHandle` writes the last-error
/// slate, so a refusal reading it after this ran would name this release rather
/// than the failure that ordered it.
fn closing(job: HANDLE, refusal: ContainmentError) -> ContainmentError {
    // SAFETY: job is the live handle the caller was given, closed exactly once
    // — the caller returns this refusal rather than using the handle again.
    unsafe { CloseHandle(job) };
    refusal
}

/// What this host contains a lent child by.
pub(super) fn naming(child: &Child) -> ChildContainment {
    use std::os::windows::io::AsRawHandle;

    // SAFETY: the handle is the one std opened for the live child this borrow
    // names, with full access, and `Child` keeps it open until it is reaped —
    // which this borrow prevents for as long as the name is used.
    unsafe { ChildContainment::from_raw_handle(child.as_raw_handle()) }
}

/// Whether a process is still present.
///
/// Only "no such process" reports the process as gone. Other refusals leave the
/// conservative answer as present.
pub fn process_is_running(pid: u32) -> bool {
    const STILL_ACTIVE: u32 = 259;

    // SAFETY: the last-error slate is cleared first so what is read back belongs
    // to this call, and the returned handle is checked before any use.
    let handle = unsafe {
        SetLastError(0);
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    };
    let refusal = std::io::Error::last_os_error();
    if handle.is_null() {
        // A pid naming no live process is the one refusal that means gone.
        return !os_error_is(&refusal, ERROR_INVALID_PARAMETER);
    }
    let mut status = 0_u32;
    // SAFETY: handle is the live handle opened above, and status is initialized
    // storage of exactly the width the call writes.
    let read = unsafe { GetExitCodeProcess(handle, &raw mut status) };
    // SAFETY: handle is the handle opened above, closed exactly once.
    unsafe { CloseHandle(handle) };
    match read {
        // An exit code that went unread says nothing about whether it exists.
        0 => true,
        _ => status == STILL_ACTIVE,
    }
}

/// The process id a Windows child handle names.
fn process_id(child: ChildContainment) -> Result<u32, ContainmentError> {
    // SAFETY: the handle belongs to the child this caller named, and the call
    // reads it without writing memory.
    match unsafe { GetProcessId(child.handle.cast()) } {
        0 => Err(ContainmentError::UnnamedChild {
            source: std::io::Error::last_os_error(),
        }),
        pid => Ok(pid),
    }
}

/// Whether an OS refusal is the Win32 error named.
pub(super) fn os_error_is(refusal: &std::io::Error, code: WIN32_ERROR) -> bool {
    refusal
        .raw_os_error()
        .and_then(|raw| u32::try_from(raw).ok())
        .is_some_and(|raw| raw == code)
}
