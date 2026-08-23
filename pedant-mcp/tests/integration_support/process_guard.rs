//! Bounded ownership of every child this MCP integration root spawns.
//!
//! The server talks newline-delimited JSON-RPC over stdio, so a test has to
//! hold the child open while it reads. That is exactly the shape that leaks:
//! an unread pipe blocks the writer, an unbounded read parks the test forever,
//! and a killed child that is never reaped leaves a zombie behind. One guard
//! owns all of it. The child starts in its own process group on Unix and in
//! its own Job Object on Windows, both pipes are drained for the tree's whole
//! life, every read and wait is bounded, and teardown closes stdin, kills the
//! group, reaps the child, and joins both drains before a caller may assert.
//!
//! Draining and reading are the same act here. The stdout drain hands each
//! line to a channel as it arrives, so the protocol can consume responses while
//! the pipe never fills. The guard keeps every line it hands out and collects
//! whatever is left at teardown, so the transcript is complete whether or not
//! the protocol read a given line.
//!
//! The shared `pedant-process-guard` dependency is the single authority for
//! operating-system containment. This module retains the MCP-specific line
//! channel, transcript, and protocol failure behavior.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pedant_process_guard::{ContainedProcessTree, ContainmentError, configure_child};

/// Budget for a run that is expected to finish on its own.
pub(crate) const BUDGET: Duration = Duration::from_secs(120);

/// Poll interval for every bounded wait.
pub(crate) const POLL: Duration = Duration::from_millis(25);

/// The server under test, which every stdio journey names.
pub(crate) const PEDANT_MCP: &str = env!("CARGO_BIN_EXE_pedant-mcp");

/// Why a guarded run could not produce a result.
///
/// A timeout of the child itself is not here: a run that overran its budget is
/// an [`Outcome`], so a test can require one without treating it as harness
/// breakage. A response that never arrived is different — the protocol asked a
/// question the server never answered — and that is a [`Failure::Protocol`].
#[derive(Debug)]
pub(crate) enum Failure {
    /// The operating system refused the named operation.
    Io {
        /// The operation the harness was performing.
        operation: &'static str,
        /// What the operating system reported.
        error: std::io::Error,
    },
    /// The operating system refused to create or control the process tree.
    Containment(ContainmentError),
    /// The harness could not proceed for a reason the system did not report.
    Protocol(Box<str>),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { operation, error } => write!(formatter, "{operation} failed: {error}"),
            Self::Containment(error) => std::fmt::Display::fmt(error, formatter),
            Self::Protocol(detail) => write!(formatter, "{detail}"),
        }
    }
}

impl From<ContainmentError> for Failure {
    fn from(error: ContainmentError) -> Self {
        Self::Containment(error)
    }
}

/// A harness failure that names its own cause.
pub(crate) fn protocol(detail: String) -> Failure {
    Failure::Protocol(detail.into_boxed_str())
}

fn io(operation: &'static str) -> impl Fn(std::io::Error) -> Failure {
    move |error| Failure::Io { operation, error }
}

/// One guarded child invocation.
pub(crate) struct Run<'a> {
    /// The binary to run. The stdio journeys name the server; the lifecycle
    /// rows name a shell script, so the guard's ownership is proved against a
    /// child that deliberately leaves a descendant behind.
    pub(crate) program: &'a str,
    /// Working directory the child starts in.
    pub(crate) cwd: &'a Path,
    /// Arguments after the binary name.
    pub(crate) args: &'a [&'a str],
    /// Extra environment the child receives.
    pub(crate) env: &'a [(&'a str, &'a str)],
    /// Ceiling on how long the child may run before it is killed.
    pub(crate) budget: Duration,
}

impl<'a> Run<'a> {
    /// A server run with the ordinary budget and no extra environment.
    pub(crate) fn server(cwd: &'a Path) -> Self {
        Self::program(PEDANT_MCP, cwd, &[])
    }

    /// The same ordinary run of any binary.
    pub(crate) fn program(program: &'a str, cwd: &'a Path, args: &'a [&'a str]) -> Self {
        Self {
            program,
            cwd,
            args,
            env: &[],
            budget: BUDGET,
        }
    }
}

/// How a guarded run ended.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// The child exited on its own with this status.
    Exited(ExitStatus),
    /// The child was still running when its budget expired.
    TimedOut,
}

/// One finished run, reported only after its whole tree is gone.
pub(crate) struct Completed {
    /// The process the guard contained, which names the whole tree.
    ///
    /// Teardown has already killed that tree and reaped its root, so a caller
    /// holds this to state the claim rather than to act on it: a row asks
    /// whether anything the server started outlived the guard, and a failure
    /// message says which tree it was asking about.
    pub(crate) tree_root: u32,
    /// How the child ended.
    pub(crate) outcome: Outcome,
    /// Every line the tree wrote to stdout, read or unread.
    pub(crate) stdout: Box<[Box<str>]>,
    /// Everything the tree wrote to stderr.
    pub(crate) stderr: Box<str>,
}

impl Completed {
    /// Whether the child exited successfully.
    pub(crate) fn success(&self) -> bool {
        matches!(&self.outcome, Outcome::Exited(status) if status.success())
    }

    /// The exit code, when the child exited with one.
    pub(crate) fn code(&self) -> Option<i32> {
        match &self.outcome {
            Outcome::Exited(status) => status.code(),
            Outcome::TimedOut => None,
        }
    }

    /// Whether the budget expired before the child exited.
    pub(crate) fn timed_out(&self) -> bool {
        matches!(self.outcome, Outcome::TimedOut)
    }

    /// Both streams, for a failure message that must say what the child said.
    pub(crate) fn transcript(&self) -> String {
        format!("stdout={:?} stderr={}", self.stdout, self.stderr)
    }
}

/// Both drained streams, as teardown collected them.
///
/// Named rather than returned as a pair: the two halves are the same shape
/// once erased, and a caller that swapped them would still compile.
struct Transcripts {
    /// Every line the tree wrote to stdout, read or unread.
    stdout: Box<[Box<str>]>,
    /// Everything the tree wrote to stderr.
    stderr: Box<str>,
}

/// Owns one child, its process tree, its stdin, and the threads draining it.
pub(crate) struct Guard {
    child: Child,
    group: ContainedProcessTree,
    stdin: Option<ChildStdin>,
    lines: Receiver<Box<str>>,
    /// Every line already handed to a caller, in arrival order.
    transcript: Vec<Box<str>>,
    stdout: Option<JoinHandle<std::io::Result<()>>>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl Guard {
    /// Start the child contained, piped, and already being drained.
    pub(crate) fn spawn(run: &Run<'_>) -> Result<Self, Failure> {
        let mut command = Command::new(run.program);
        command
            .current_dir(run.cwd)
            .args(run.args)
            // Keep the child off the CI runner's real GITHUB_OUTPUT file:
            // parallel subprocesses interleave those writes.
            .env_remove("GITHUB_OUTPUT")
            .env_remove("RUST_LOG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in run.env {
            command.env(key, value);
        }
        configure_child(&mut command);
        let mut child = command.spawn().map_err(io("the spawn"))?;
        let group = ContainedProcessTree::adopt(&mut child)?;
        let (sender, lines) = mpsc::channel();
        let mut guard = Self {
            child,
            group,
            stdin: None,
            lines,
            transcript: Vec::new(),
            stdout: None,
            stderr: None,
        };
        let stdout = take_pipe(guard.child.stdout.take(), "stdout")?;
        let stderr = take_pipe(guard.child.stderr.take(), "stderr")?;
        guard.stdin = Some(take_pipe(guard.child.stdin.take(), "stdin")?);
        guard.stdout = Some(thread::spawn(move || drain_lines(stdout, &sender)));
        guard.stderr = Some(thread::spawn(move || drain(stderr)));
        Ok(guard)
    }

    /// Write one newline-terminated message to the child.
    pub(crate) fn send_line(&mut self, text: &str) -> Result<(), Failure> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| protocol(String::from("the child's stdin is already closed")))?;
        stdin
            .write_all(format!("{text}\n").as_bytes())
            .map_err(io("the write"))?;
        stdin.flush().map_err(io("the flush"))
    }

    /// Take the next line the child wrote, or report that none arrived in time.
    ///
    /// The line is kept before it is returned, so the transcript records what a
    /// caller consumed as well as what it ignored.
    pub(crate) fn read_line(&mut self, budget: Duration) -> Result<&str, Failure> {
        match self.lines.recv_timeout(budget) {
            Ok(line) => {
                self.transcript.push(line);
                Ok(self.transcript.last().map_or("", |line| &**line))
            }
            Err(RecvTimeoutError::Timeout) => Err(protocol(format!(
                "the server wrote no line within {budget:?}"
            ))),
            Err(RecvTimeoutError::Disconnected) => {
                Err(protocol(String::from("the server closed stdout")))
            }
        }
    }

    /// Close stdin, which is how the server is asked to shut down normally.
    pub(crate) fn close_stdin(&mut self) {
        std::mem::drop(self.stdin.take());
    }

    /// Shut the child down and return only after its whole tree is reaped.
    pub(crate) fn finish(mut self, budget: Duration) -> Result<Completed, Failure> {
        self.close_stdin();
        let tree_root = self.child.id();
        let waited = self.wait(budget);
        let transcripts = self.teardown()?;
        Ok(Completed {
            tree_root,
            outcome: waited?,
            stdout: transcripts.stdout,
            stderr: transcripts.stderr,
        })
    }

    /// Wait for the child's own exit, or report that the budget expired.
    fn wait(&mut self, budget: Duration) -> Result<Outcome, Failure> {
        let deadline = Instant::now() + budget;
        loop {
            match self.child.try_wait().map_err(io("the wait"))? {
                Some(status) => return Ok(Outcome::Exited(status)),
                None if Instant::now() >= deadline => return Ok(Outcome::TimedOut),
                None => thread::sleep(POLL),
            }
        }
    }

    /// Kill the whole tree, reap the child, and collect both transcripts.
    ///
    /// The tree is killed even after a clean exit: a descendant the child left
    /// behind still holds the inherited pipes, so joining a drain before the
    /// kill would block on a process nobody is waiting for.
    fn teardown(&mut self) -> Result<Transcripts, Failure> {
        std::mem::drop(self.stdin.take());
        self.group.terminate()?;
        self.child.wait().map_err(io("the reap"))?;
        joined(self.stdout.take(), "stdout")?;
        let stderr = joined(self.stderr.take(), "stderr")?;
        self.transcript.extend(self.lines.try_iter());
        Ok(Transcripts {
            stdout: std::mem::take(&mut self.transcript).into(),
            stderr: decode(&stderr),
        })
    }
}

/// Release the tree for a guard nobody tore down.
///
/// `finish` is the only path that reports a result; a panic before it would
/// otherwise leave a killed child unreaped and two drain threads parked on
/// pipes that never close.
impl Drop for Guard {
    fn drop(&mut self) {
        std::mem::drop(self.stdin.take());
        std::mem::drop(self.group.terminate());
        std::mem::drop(self.child.kill());
        std::mem::drop(self.child.wait());
        std::mem::drop(self.stdout.take().map(JoinHandle::join));
        std::mem::drop(self.stderr.take().map(JoinHandle::join));
    }
}

/// Run one child to completion under a guard, with nothing to say to it.
pub(crate) fn execute(run: &Run<'_>) -> Result<Completed, Failure> {
    Guard::spawn(run)?.finish(run.budget)
}

fn take_pipe<R>(pipe: Option<R>, name: &str) -> Result<R, Failure> {
    pipe.ok_or_else(|| protocol(format!("the child has no {name}")))
}

/// Read stdout line by line and publish each line as it arrives.
///
/// A send failure means the guard is gone and nobody is reading any more; the
/// drain keeps going regardless, because stopping would block the writer.
fn drain_lines<R: Read>(reader: R, sender: &Sender<Box<str>>) -> std::io::Result<()> {
    for line in BufReader::new(reader).lines() {
        std::mem::drop(sender.send(line?.into_boxed_str()));
    }
    Ok(())
}

fn drain<R: Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut collected = Vec::new();
    reader.read_to_end(&mut collected)?;
    Ok(collected)
}

/// Lossy, because a tree killed mid-write can be cut mid-codepoint; a strict
/// decode would replace the diagnostic a reader needs with a different one.
fn decode(bytes: &[u8]) -> Box<str> {
    String::from_utf8_lossy(bytes).into()
}

fn joined<T>(
    handle: Option<JoinHandle<std::io::Result<T>>>,
    name: &'static str,
) -> Result<T, Failure> {
    let handle = take_pipe(handle, name)?;
    match handle.join() {
        Ok(Ok(collected)) => Ok(collected),
        Ok(Err(error)) => Err(Failure::Io {
            operation: name,
            error,
        }),
        Err(_) => Err(protocol(format!("the {name} drain panicked"))),
    }
}
