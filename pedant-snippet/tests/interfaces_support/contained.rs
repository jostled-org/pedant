//! Spawning and reaping every child this root owns, contained.
//!
//! Both transport journeys claim the server leaves no descendant behind, and
//! that claim is only worth making if something looks. A reaped direct child
//! proves nothing about a grandchild: the process this harness waited for is
//! gone either way, and a leaked descendant goes on holding the inherited pipes
//! and the temporary repository after the case that spawned it returned.
//!
//! So every child is spawned as the root of a contained tree — a process group
//! on Unix, a kill-on-close Job Object on Windows — through the same
//! `pedant-process-guard` owner `pedant` and `pedant-mcp` reach for the same
//! claim. The tree is *read* after the root is reaped and *ended* immediately
//! afterwards, in that order: what the process left behind is the claim, and
//! what this harness then did about it is the cleanup.
//!
//! The primitives every child shares live here too — the pipe pair, the reap,
//! the kill, the error exit, and the lossy decode. They used to sit in
//! [`crate::child`], which is the module named for the long-lived session, so
//! that module imported the spawn and this one imported the reap: a cycle
//! between two files that own different things. Spawning and reaping are one
//! job, so one module owns them, and the split above it is the shape a caller
//! reads — [`crate::child`] owns the session a journey talks to, and
//! [`crate::command`] owns the one run that is asked nothing.

use std::process::{Command as HostCommand, Stdio};
use std::time::Duration;

use pedant_process_guard::{
    ChildContainment, ContainedProcessTree, configure_child, tree_is_live, wait_until_released,
};
use tokio::process::{Child, ChildStderr, ChildStdout, Command};

use crate::failure::{Failure, bounded, io};

/// How long the harness waits for a tree it killed to be gone.
///
/// Short, because the kill has already been delivered: this bounds the
/// operating system's reporting of it, not any work the tree is doing.
const TEARDOWN: Duration = Duration::from_secs(5);

/// What one contained tree held once the process rooting it had exited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Descendants {
    /// Nothing of the tree was left.
    None,
    /// Some member of the tree outlived the process that rooted it.
    Survived,
}

/// One spawned child and the operating-system object owning its whole tree.
pub struct Spawned {
    /// The child this harness talks to.
    pub child: Child,
    /// The tree it roots, which is what containment owns.
    tree: ContainedProcessTree,
    /// The process id the tree was rooted at, kept because a reaped child no
    /// longer states one and the leak is reported after the reap.
    ///
    /// Names the tree in a failure message and nothing else. Both liveness
    /// questions are asked through `tree` instead: on a host whose tree is a
    /// named kernel object, a pid-keyed question asked once the last handle has
    /// closed reads a destroyed job as an empty tree — a leak reported as a
    /// clean exit. Borrowing the tree is the proof a handle is still open.
    root: u32,
}

impl Spawned {
    /// End this tree, whatever it still holds.
    ///
    /// Idempotent and infallible-by-design for a caller that already reported a
    /// failure: an empty group and an empty job both terminate successfully.
    pub fn terminate(&self) {
        drop(self.tree.terminate());
    }

    /// Close stdin, reap this child, end its tree, and say why it all happened.
    ///
    /// The one error exit from a spawned tree. Both spawn paths used to write
    /// the reap and the kill out themselves, which let either one lose the
    /// [`abort`] and leak a live child, or lose the [`Spawned::terminate`] and
    /// leak everything that child had started, without the other noticing.
    pub async fn abort(&mut self, failure: Failure) -> Failure {
        let aborted = abort(&mut self.child, failure).await;
        self.terminate();
        aborted
    }
}

/// Take both output pipes, naming `subject` when one is missing.
///
/// `subject` arrives spelled as the whole noun phrase — "the server", "the run",
/// "the fixture parent" — because the caller that drains a child names it once
/// and hands the same words to [`crate::failure::bounded`], which takes a
/// `&'static str` it cannot compose.
pub fn pipes(child: &mut Child, subject: &str) -> Result<(ChildStdout, ChildStderr), Failure> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Failure::Protocol(format!("{subject} has no stdout").into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Failure::Protocol(format!("{subject} has no stderr").into()))?;
    Ok((stdout, stderr))
}

/// Reap a child, killing it first when it is still live.
///
/// A child already waited for is already reaped, and signalling it again reports
/// an exited process — an error about the reap that would bury the failure which
/// called for it.
async fn reap(child: &mut Child) -> Result<(), Failure> {
    match child.try_wait().map_err(io("the reap"))? {
        Some(_) => Ok(()),
        None => kill(child).await,
    }
}

/// Signal a live child and wait for the corpse inside the budget.
async fn kill(child: &mut Child) -> Result<(), Failure> {
    child.start_kill().map_err(io("the kill"))?;
    bounded("the kill", child.wait()).await.map(drop)
}

/// Close stdin, reap the child, and say why the operation failed.
///
/// Every error exit from a live child routes through here. A clean reap reports
/// the original failure. A reap that fails reports both, so neither diagnostic
/// is lost.
///
/// The direct child and nothing else. A caller holding a [`Spawned`] owes the
/// tree as well and reaches [`Spawned::abort`], which is the one error exit that
/// states both halves.
async fn abort(child: &mut Child, failure: Failure) -> Failure {
    drop(child.stdin.take());
    match reap(child).await {
        Ok(()) => failure,
        Err(reaping) => {
            Failure::Protocol(format!("{failure} and the kill failed: {reaping}").into())
        }
    }
}

/// Decode what a child wrote, for a report or for a finished run.
///
/// Lossy, because a child killed mid-write can be cut mid-codepoint. A strict
/// decode would fail there and replace the diagnostic the reader needs with a
/// different one.
pub fn text(bytes: &[u8]) -> Box<str> {
    String::from_utf8_lossy(bytes).into()
}

/// Spawn the binary under test contained, piped, and killable on drop.
///
/// Every child runs under `LC_ALL=C`. No case here reads a locale-dependent
/// string: every refusal it asserts on is a typed code or a clap token. So the
/// pin buys a stable child environment rather than an assertion — it keeps a
/// host locale out of the `strerror_r` text a failing run prints, which is text
/// a reader has to interpret.
pub async fn spawn(arguments: &[&str]) -> Result<Spawned, Failure> {
    let mut command = HostCommand::new(env!("CARGO_BIN_EXE_pedant-snippet"));
    command.args(arguments).env("LC_ALL", "C");
    contained(command).await
}

/// Spawn any command as the root of a contained tree.
///
/// The command arrives built because two callers build different ones: every
/// journey runs the binary under test, and one control row runs this test
/// executable as the shared process fixture. What they share is the
/// containment, so `configure_child` is applied here — no caller can spawn an
/// uncontained child by forgetting it.
///
/// The command is the host's own `Command` because that is what
/// `configure_child` configures: one owner decides what "contained" means for
/// this repository, and a second spelling here would be a second answer.
pub async fn contained(mut command: HostCommand) -> Result<Spawned, Failure> {
    configure_child(&mut command);
    let child = Command::from(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(io("the spawn"))?;
    adopted(child).await
}

/// Adopt a live child into a contained tree, killing it if adoption refuses.
///
/// Called on a child that has started nothing, and only there. Every refusal
/// below reaps the direct child. On Unix the configured process group already
/// exists. On Windows the child remains suspended until adoption assigns its
/// Job Object, so it cannot start a descendant before containment succeeds.
///
/// The one caller is [`contained`], which spawns the command on the statement
/// above and hands the child straight over, so nothing has written to its stdin
/// and nothing has waited for it to speak. That is the invariant, and it is
/// stated rather than left implied: this module's claim is that no caller can
/// spawn an uncontained child by forgetting the containment, and a refusal path
/// that quietly relied on the child being idle would be the exception.
async fn adopted(mut child: Child) -> Result<Spawned, Failure> {
    let Some(root) = child.id() else {
        return Err(abort(
            &mut child,
            Failure::Protocol("the spawned child states no process id".into()),
        )
        .await);
    };
    let Some(name) = containment(&child) else {
        return Err(abort(
            &mut child,
            Failure::Protocol("the spawned child states no containment name".into()),
        )
        .await);
    };
    match ContainedProcessTree::adopting(name) {
        Ok(tree) => Ok(Spawned { child, tree, root }),
        Err(refusal) => Err(abort(&mut child, Failure::Containment(refusal)).await),
    }
}

/// What this host contains a live child by.
///
/// Absent once the child is reaped, on both hosts: the runtime drops the name
/// with the process, and adoption happens before anything waits.
#[cfg(unix)]
fn containment(child: &Child) -> Option<ChildContainment> {
    child.id().map(ChildContainment::from_pid)
}

/// What this host contains a live child by.
#[cfg(windows)]
fn containment(child: &Child) -> Option<ChildContainment> {
    // SAFETY: the handle is the one the runtime opened for this live child,
    // with full access, and it stays open until the child is reaped — which
    // this borrow prevents for as long as the name is used.
    child
        .raw_handle()
        .map(|handle| unsafe { ChildContainment::from_raw_handle(handle) })
}

/// Read what a reaped child's tree still held, then end the tree.
///
/// The reading comes first because "leaves no descendant" is a claim about the
/// process, not about the kill that follows it. The kill comes unconditionally,
/// and a tree that survives it is a harness failure rather than a case result:
/// the next case would inherit both the leak and the pipes it holds.
pub fn released(spawned: &Spawned) -> Result<Descendants, Failure> {
    let held = match tree_is_live(&spawned.tree) {
        true => Descendants::Survived,
        false => Descendants::None,
    };
    spawned.tree.terminate().map_err(Failure::Containment)?;
    match wait_until_released(&spawned.tree, TEARDOWN) {
        true => Ok(held),
        false => Err(Failure::Protocol(
            format!(
                "the process tree rooted at {} outlived the kill that ended it",
                spawned.root
            )
            .into(),
        )),
    }
}
