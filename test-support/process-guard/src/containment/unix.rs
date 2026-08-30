//! Containment on a host whose process tree is a process group.
//!
//! A Unix tree needs no naming beyond the number it already has: the group id
//! a configured child leads *is* that child's process id, so a caller holding
//! only the root pid can still ask the kernel what the group holds.

use std::process::{Child, Command};

use super::error::ContainmentError;

/// Configure a command so its future child can become a contained tree root.
pub fn configure_child(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

/// What this host names a spawned child by, for the purpose of containing it.
///
/// A `std::process::Child` carries every spelling at once, so a caller holding
/// one never has to choose. A caller whose runtime owns its own child type
/// holds them one at a time, and adoption is stated over the name rather than
/// over one library's child so both kinds of caller reach the same owner.
///
/// An opaque struct rather than the process id itself, because the same name on
/// Windows is a raw handle: a public alias for one would make every adoption a
/// safe function that dereferences a pointer nothing checked. Each host states
/// its own constructor, and each states there what makes a name valid.
#[derive(Clone, Copy, Debug)]
pub struct ChildContainment {
    pid: u32,
}

impl ChildContainment {
    /// Name a child by its process id.
    ///
    /// Safe on this host: a process id is a number the kernel validates on use,
    /// so a wrong one names an absent group rather than reading freed memory.
    pub fn from_pid(pid: u32) -> Self {
        Self { pid }
    }
}

/// The operating-system object that owns one child process tree.
pub struct ContainedProcessTree {
    root_pid: u32,
    group_id: i32,
}

impl ContainedProcessTree {
    /// Adopt a child configured by configure_child, named by its process id.
    ///
    /// Nothing is cleaned up here: a caller that named a child rather than
    /// lending one is the only owner in a position to end it.
    /// [`super::adopt_child`] is the same adoption for a caller that lends the
    /// child it owns, and it cleans up whatever this refuses.
    pub fn adopting(child: ChildContainment) -> Result<Self, ContainmentError> {
        let group_id =
            i32::try_from(child.pid).map_err(|source| ContainmentError::InvalidProcessGroupId {
                pid: child.pid,
                source,
            })?;
        leading_its_own_group(child.pid, group_id)?;
        Ok(Self {
            root_pid: child.pid,
            group_id,
        })
    }

    /// The process id this tree is named by.
    ///
    /// Published because each consumer's wrapper reports it: the containment is
    /// what named the tree, so a wrapper that also recorded the pid held a
    /// second record of one identity with nothing keeping the two in step.
    pub fn root(&self) -> u32 {
        self.root_pid
    }

    /// Whether any member of this process group is still present.
    pub(super) fn is_running(&self) -> bool {
        group_is_running(self.group_id)
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

/// End the tree for an owner nobody terminated by hand.
///
/// Nothing on this host ends a process group when the last reference to it goes
/// away — the Windows kill-on-close limit has no Unix counterpart — so without
/// this a panic or an early return between adoption and an explicit kill leaves
/// every descendant running. `terminate` reports a group already gone as
/// success, so this repeats an explicit call harmlessly.
///
/// It does not replace the explicit calls. A consumer draining the tree's pipes
/// has to kill before it joins those drains, and a field dropped after its
/// owner's `Drop` body runs is too late for that ordering.
impl Drop for ContainedProcessTree {
    fn drop(&mut self) {
        std::mem::drop(self.terminate());
    }
}

/// Prove the adopted child leads the process group this tree is named by.
///
/// Without this, adoption on this host asserts nothing at all: the rest of it
/// is a widening conversion no live process id can fail, so a child spawned
/// from a command nobody handed to [`configure_child`] would adopt cleanly and
/// stay in its parent's group. Every later question would then be asked about
/// the parent's group — `killpg` on it refuses with `ESRCH`, which `terminate`
/// reports as success and the group query reports as gone, so a leaked tree
/// reads green in every claim built on it. The Windows host refuses an
/// assignment it could not make; this is that same refusal.
///
/// The group a leader leads is its own process id, so leadership is the single
/// question that proves both that the command was configured and that the
/// number this tree is named by names this tree.
///
/// Asked once rather than waited on. `process_group` is applied in the child,
/// between the fork and the exec, and every spawn this crate's callers make goes
/// through `posix_spawn`, which does not hand the parent back until the child
/// has execed. A caller that reached std's fork fallback instead — by attaching
/// a pre-exec closure, a uid, or a chroot — would be racing its own child for
/// this answer, and a refusal it can read beats a claim nothing checked.
fn leading_its_own_group(pid: u32, group_id: i32) -> Result<(), ContainmentError> {
    // SAFETY: getpgid reads a process id and writes no memory. A pid naming no
    // process, or one this caller may not ask about, returns -1 rather than
    // reading anything.
    let group = unsafe { libc::getpgid(group_id) };
    match group {
        actual if actual == group_id => Ok(()),
        actual if actual >= 0 => Err(ContainmentError::UnledProcessGroup { pid, group: actual }),
        _ => inspect_group_after_leader_exit(pid, group_id, std::io::Error::last_os_error()),
    }
}

/// Distinguish an exited leader from an unread process-group question.
fn inspect_group_after_leader_exit(
    pid: u32,
    group_id: i32,
    source: std::io::Error,
) -> Result<(), ContainmentError> {
    match source.raw_os_error() {
        Some(libc::ESRCH) => inspect_surviving_group(pid, group_id),
        _ => Err(ContainmentError::ProcessGroupInspection { pid, source }),
    }
}

/// Accept a surviving configured group or the empty group left after a clean exit.
fn inspect_surviving_group(pid: u32, group_id: i32) -> Result<(), ContainmentError> {
    // SAFETY: signal zero checks group existence and permission without
    // delivering a signal or writing memory.
    let status = unsafe { libc::killpg(group_id, 0) };
    let source = std::io::Error::last_os_error();
    match (status, source.raw_os_error()) {
        (0, _) | (-1, Some(libc::ESRCH)) | (-1, Some(libc::EPERM)) => Ok(()),
        _ => Err(ContainmentError::ProcessGroupInspection { pid, source }),
    }
}

/// What this host contains a lent child by.
pub(super) fn naming(child: &Child) -> ChildContainment {
    ChildContainment::from_pid(child.id())
}

/// Whether a process is still present.
///
/// A process id too wide for this host to name reads as present. That is the
/// direction the `containment` module states for every unread liveness
/// question: absence is the one answer that lets a caller stop waiting and call
/// a tree clean, so a question that went unread must never give it. The Windows
/// host takes the same verdict for every refusal it cannot read as "no such
/// process".
pub fn process_is_running(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return true;
    };
    // SAFETY: signal zero checks existence and permission without delivering a
    // signal or writing memory.
    let status = unsafe { libc::kill(pid, 0) };
    status == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Whether any member of a process group is still present.
fn group_is_running(group_id: i32) -> bool {
    // SAFETY: signal zero checks group existence and permission without
    // delivering a signal or writing memory.
    let status = unsafe { libc::killpg(group_id, 0) };
    status == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}
