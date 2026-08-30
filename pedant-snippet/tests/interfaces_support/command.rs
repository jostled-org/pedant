//! One finished run of the binary under test.
//!
//! The other shape a child takes. A [`crate::child::Server`] is asked questions
//! for as long as a journey has them; a run here is handed a command line, given
//! no input at all, and drained until it exits on its own. Both are reaped
//! inside the same budget, through the same [`crate::contained`] helpers, and
//! both report what their contained process tree still held afterwards.

use std::process::ExitStatus;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, ChildStdout};

use crate::contained::{Descendants, Spawned, pipes, released, spawn, text};
use crate::failure::{Failure, bounded};

/// One finished CLI run.
pub struct Output {
    /// The exit status the process reported.
    pub status: ExitStatus,
    /// Everything the process wrote to stdout.
    pub stdout: Box<str>,
    /// Everything the process wrote to stderr.
    pub stderr: Box<str>,
    /// What the run's process tree still held once the run itself had exited.
    pub descendants: Descendants,
    /// How long the run took, measured from the spawn to the reap.
    ///
    /// A [`crate::child::Server`] measures from the client's EOF, because a
    /// session ends when the client says so. A run here is never asked
    /// anything, so what bounds it is its whole life — and a run bounded only
    /// by the harness's own thirty-second ceiling is a run no case measured.
    pub elapsed: Duration,
}

/// Run the binary to completion, bounded, and reap its whole tree.
pub async fn run(arguments: &[&str]) -> Result<Output, Failure> {
    let started = Instant::now();
    let mut spawned = spawn(arguments).await?;
    // Every command but `mcp` reads no input, so closing stdin proves it and
    // leaves no way for a run to block waiting on one.
    drop(spawned.child.stdin.take());
    match completed(&mut spawned, started).await {
        Ok(output) => Ok(output),
        Err(failure) => Err(spawned.abort(failure).await),
    }
}

/// Drain one run, then read what its process tree left behind.
///
/// The clock stops at the reap rather than after the reading: what follows is
/// this harness's own kill and its bounded wait, which is cleanup rather than
/// anything the run spent.
async fn completed(spawned: &mut Spawned, started: Instant) -> Result<Output, Failure> {
    let (status, stdout, stderr) = bounded_run(&mut spawned.child, "the run").await?;
    let elapsed = started.elapsed();
    Ok(Output {
        status,
        stdout,
        stderr,
        descendants: released(spawned)?,
        elapsed,
    })
}

/// Take both pipes, drain them inside the budget, and reap the child.
///
/// A failed run reports what the child wrote before it failed, the way
/// [`crate::child::Server::shutdown`] reports the log it drained.
///
/// Published because a second caller spawns a child of a different shape and
/// owes the same three things. `pedant-process-guard`'s fixture parent is piped
/// on all three handles and says why it failed on stderr, so a journey that only
/// waited for it would hold an exit status and discard the sentence explaining
/// it — and would break the pipe-drain invariant [`crate::child`] states for
/// every child this root spawns. `subject` names the child in both the missing
/// pipe and the budget failures, so one word covers the whole drain.
pub async fn bounded_run(
    child: &mut Child,
    subject: &'static str,
) -> Result<(ExitStatus, Box<str>, Box<str>), Failure> {
    let (stdout, stderr) = pipes(child, subject)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let finished = bounded(subject, collect(child, stdout, stderr, &mut out, &mut err)).await;
    match finished {
        Ok(status) => Ok((status, text(&out), text(&err))),
        Err(failure) => Err(with_output(failure, &out, &err)),
    }
}

/// Drain both pipes into the caller's buffers and reap the process.
///
/// The buffers belong to the caller so a run that overruns the budget keeps
/// whatever the child managed to say. Owning them here would drop them with the
/// abandoned future, leaving the one failure whose diagnostics matter most with
/// no stdout, no stderr, and no status.
///
/// They are `Vec<u8>` because only `read_to_end` honours that. `read_to_string`
/// takes the caller's `String` by `mem::take`, accumulates into a buffer the
/// future owns, and writes the caller's back only after EOF — so a cancelled
/// read leaves the caller holding an empty string. `read_to_end` borrows the
/// caller's vector for the whole read, so every byte already read survives the
/// drop.
async fn collect(
    child: &mut Child,
    mut stdout: ChildStdout,
    mut stderr: ChildStderr,
    out: &mut Vec<u8>,
    err: &mut Vec<u8>,
) -> std::io::Result<ExitStatus> {
    let (read_out, read_err, waited) = tokio::join!(
        stdout.read_to_end(out),
        stderr.read_to_end(err),
        child.wait(),
    );
    read_out?;
    read_err?;
    waited
}

/// Fold whatever the child managed to write into a failed run.
fn with_output(failure: Failure, stdout: &[u8], stderr: &[u8]) -> Failure {
    Failure::Protocol(
        format!(
            "{failure} (child stdout: {:?}, child stderr: {:?})",
            text(stdout),
            text(stderr)
        )
        .into(),
    )
}
