//! Which processes a Windows Job Object still holds.
//!
//! The member list is what makes the tree question answerable on this host. A
//! job keeps a terminated process in that list until every reference to the
//! process is released, and the reaped root is exactly such a process, so the
//! list alone would report the root as its own survivor. Each listed member is
//! therefore asked whether it is running.

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    JOBOBJECT_BASIC_PROCESS_ID_LIST, JobObjectBasicProcessIdList, QueryInformationJobObject,
};

use super::windows::{os_error_is, process_is_running};

/// How many members one query makes room for before it asks for more.
///
/// A tree this guard contains holds a root and whatever that root started,
/// which is a handful. The room is far above that, so growing is the exception
/// rather than the ordinary read.
const MEMBER_QUERY: usize = 64;

/// How many times a truncated member query grows before it stops growing.
const MEMBER_QUERY_ROUNDS: u32 = 4;

/// How many machine words the declared list holds ahead of its member array.
///
/// The *offset* of that array, not the size of the struct declaring it. The
/// struct declares the array's first element inline, so its size is one word
/// larger than the header on both layouts this crate builds for: x86 offsets
/// the array at 8 with a struct size of 12, x64 at 8 with a size of 16. A
/// size-derived count is one word too many on both, so every read would start
/// past the first member id and end one word beyond the last one written.
const HEADER_WORDS: usize =
    std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList) / size_of::<usize>();

/// Whether any process a job still lists is running.
pub(super) fn job_holds_a_live_member(job: HANDLE) -> bool {
    let mut room = MEMBER_QUERY;
    for _ in 0..MEMBER_QUERY_ROUNDS {
        match job_members(job, room) {
            Members::Whole(ids) => return ids.into_iter().any(process_is_running),
            // Grow to what the job reported, and never below a doubling, so a
            // truncation that reported no count still ends this loop.
            Members::Truncated(assigned) => room = assigned.max(room.saturating_mul(2)),
            // A query that did not answer says nothing about what the job
            // holds. Reporting it empty would be reporting a leak as a clean
            // exit.
            Members::Unknown => return true,
        }
    }
    // A job still too large to enumerate after four growths holds more
    // processes than any tree this guard contains. Reporting it empty would be
    // reporting a leak as a clean exit.
    true
}

/// What one member query read, and whether it read all of it.
enum Members {
    /// Every member the job holds, which may be none.
    Whole(Box<[u32]>),
    /// The buffer was too small; the job reports holding this many.
    Truncated(usize),
    /// The query did not answer, so what the job holds went unread.
    Unknown,
}

/// What a job's member list holds, as one query reads it.
///
/// A query that does not answer reads as `Unknown` rather than as an empty
/// list, because an unread list is not an empty one — the two answers carry
/// opposite verdicts on a leak.
fn job_members(job: HANDLE, room: usize) -> Members {
    queried_members(job, room).unwrap_or(Members::Unknown)
}

/// Read a job's member process ids into room for `room` of them.
///
/// The buffer is allocated as machine words rather than as bytes because the
/// list Windows writes into it is word-aligned; a `Vec<u8>` carries no such
/// guarantee, and reading the counts out of one would be an unaligned read.
///
/// `None` reports a length or a slice this read depends on that did not fit,
/// which leaves the member list as unread as a refusal does.
fn queried_members(job: HANDLE, room: usize) -> Option<Members> {
    let words = HEADER_WORDS.checked_add(room)?;
    let mut buffer = vec![0_usize; words];
    let length = u32::try_from(words.checked_mul(size_of::<usize>())?).ok()?;
    // SAFETY: the buffer is word-aligned, holds `length` initialized bytes, and
    // is the only storage the requested information class writes into.
    let read = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicProcessIdList,
            buffer.as_mut_ptr().cast(),
            length,
            std::ptr::null_mut(),
        )
    };
    let refusal = std::io::Error::last_os_error();
    // SAFETY: the buffer is word-aligned and at least one list long, and the
    // query writes its two counts before anything else — including when it
    // refuses for want of room.
    let list = unsafe { &*buffer.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
    let assigned = usize::try_from(list.NumberOfAssignedProcesses).ok()?;
    let listed = usize::try_from(list.NumberOfProcessIdsInList).ok()?;
    match (read == 0, os_error_is(&refusal, ERROR_MORE_DATA)) {
        (true, true) => Some(Members::Truncated(assigned)),
        (true, false) => Some(Members::Unknown),
        (false, _) => Some(read_members(buffer.get(HEADER_WORDS..)?, listed)),
    }
}

/// Every member id the read list names, or `Unknown` when one went unnamed.
///
/// A member id wider than the process-id type is a process this read cannot
/// name, and so is a member the list counts but the buffer does not hold. A
/// member it cannot name is unread rather than absent, and taking the ids it
/// did get would report a live process as gone — the one verdict every other
/// unread path in this module refuses to give.
fn read_members(words: &[usize], listed: usize) -> Members {
    match listed_ids(words, listed) {
        Some(ids) => Members::Whole(ids),
        None => Members::Unknown,
    }
}

/// Every id the list counts, or nothing when the read cannot name them all.
///
/// The count is the job's claim about what it wrote, not the buffer's own
/// length, so a count reaching past what this read allocated is refused rather
/// than quietly shortened to fit. A shortened list reported as whole is a live
/// member reported gone.
fn listed_ids(words: &[usize], listed: usize) -> Option<Box<[u32]>> {
    words
        .get(..listed)?
        .iter()
        .map(|id| u32::try_from(*id).ok())
        .collect()
}
