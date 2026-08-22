//! Bounded ownership of every child a `pedant` test root spawns.
//!
//! Both child-spawning roots consume this exact wrapper: `pedant supply-chain`
//! runs Cargo and Cargo runs whatever else it likes, and `pedant gate
//! --project` reads a repository someone else wrote. A child here is therefore
//! a process tree rather than a process. One guard owns that tree: the child
//! starts in its own process group on Unix and in its own Job Object on
//! Windows, both output pipes are drained for the tree's whole life, every wait
//! is bounded, and teardown closes stdin, kills the group, reaps the child, and
//! joins both drains before a caller may assert anything.
//!
//! Draining matters twice over. A pipe nobody reads fills and blocks its
//! writer, and a descendant inherits the same pipes — so the drains cannot
//! finish until the last member of the tree is gone, which is exactly the
//! property teardown must prove.
//!
//! One row deliberately closes the parent's stdout reader before the child
//! writes, which is the only way to observe how the binary reports a failed
//! write. That row still drains stderr, still bounds its wait, and still kills,
//! reaps, and joins before it asserts.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pedant_process_guard::{ContainedProcessTree, ContainmentError, configure_child};

/// Budget for a run that is expected to finish on its own.
pub(crate) const BUDGET: Duration = Duration::from_secs(120);

/// Poll interval for every bounded wait.
pub(crate) const POLL: Duration = Duration::from_millis(25);

/// Largest stdin fixture a row may state.
///
/// The fixture is written before the wait begins, so a child that never reads
/// it can only block the harness once the write exceeds the pipe buffer. One
/// page is below the smallest buffer either platform provides, which keeps the
/// module's "every wait is bounded" contract true rather than merely untested.
const STDIN_CEILING: usize = 4096;

/// Why a guarded run could not produce a result.
///
/// A timeout is not here: a run that overran its budget is an [`Outcome`], so a
/// test can require one without treating it as harness breakage.
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

fn io(operation: &'static str) -> impl Fn(std::io::Error) -> Failure {
    move |error| Failure::Io { operation, error }
}

/// One guarded child invocation.
pub(crate) struct Run<'a> {
    /// The binary to run. Fixture setup runs Cargo through the same guard the
    /// journeys use, so no child of this root is unbounded or unreaped.
    pub(crate) program: &'a str,
    /// Working directory the child starts in.
    pub(crate) cwd: &'a Path,
    /// Arguments after the binary name.
    pub(crate) args: &'a [&'a str],
    /// Directory prepended to `PATH`, which is how a fake Cargo is installed.
    pub(crate) path_prefix: Option<&'a Path>,
    /// Extra environment the child receives.
    pub(crate) env: &'a [(&'a str, &'a str)],
    /// Ceiling on how long the child may run before it is killed.
    pub(crate) budget: Duration,
    /// Bytes written to the child's stdin, which is closed straight after.
    pub(crate) stdin: Option<&'a [u8]>,
    /// Whether the parent keeps the child's stdout reader.
    ///
    /// A row that must observe a failed write sets this false, so the reader is
    /// dropped before the child writes. Every other row drains stdout for the
    /// tree's whole life.
    pub(crate) capture_stdout: bool,
}

/// The binary under test, which most runs here name.
pub(crate) const PEDANT: &str = env!("CARGO_BIN_EXE_pedant");

impl<'a> Run<'a> {
    /// A `pedant` run with the ordinary budget, no fake Cargo, and no extra
    /// environment.
    pub(crate) fn new(cwd: &'a Path, args: &'a [&'a str]) -> Self {
        Self::program(PEDANT, cwd, args)
    }

    /// The same ordinary run of any binary, which is how fixture setup runs
    /// Cargo without leaving the guard.
    pub(crate) fn program(program: &'a str, cwd: &'a Path, args: &'a [&'a str]) -> Self {
        Self {
            program,
            cwd,
            args,
            path_prefix: None,
            env: &[],
            budget: BUDGET,
            stdin: None,
            capture_stdout: true,
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
    /// whether anything the child started outlived the guard, and a failure
    /// message says which tree it was asking about.
    pub(crate) tree_root: u32,
    /// How the child ended.
    pub(crate) outcome: Outcome,
    /// Everything the tree wrote to stdout, empty when nothing drained it.
    ///
    /// A row that closes the reader before the child writes reads empty here
    /// whatever the child produced, so an assertion over this field states
    /// nothing for that row. `captured_stdout` tells the two apart.
    pub(crate) stdout: Box<str>,
    /// Everything the tree wrote to stderr.
    pub(crate) stderr: Box<str>,
    /// Whether a drain ran for stdout at all.
    pub(crate) captured_stdout: bool,
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
    ///
    /// An uncaptured stream says so, rather than reading as an empty one.
    pub(crate) fn transcript(&self) -> String {
        match self.captured_stdout {
            true => format!("stdout={} stderr={}", self.stdout, self.stderr),
            false => format!("stdout=<not captured> stderr={}", self.stderr),
        }
    }
}

/// Run one child under a guard and return only after its tree is reaped.
pub(crate) fn execute(run: &Run<'_>) -> Result<Completed, Failure> {
    Guard::spawn(run)?.finish(run.budget)
}

/// Owns one child, its process tree, and the threads draining its pipes.
///
/// Exposed so a root that must act between adoption and the wait — releasing a
/// fixture that blocks on proof of adoption — can do so without a second
/// lifecycle owner.
pub(crate) struct Guard {
    child: Child,
    group: ContainedProcessTree,
    stdout: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl Guard {
    /// Start one contained child and its drains, before any wait begins.
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
        if let Some(prefix) = run.path_prefix {
            command.env("PATH", prepended_path(prefix));
        }
        for (key, value) in run.env {
            command.env(key, value);
        }
        configure_child(&mut command);
        // The guard is built from the child before anything else can fail. A
        // pipe taken first would return through `?` with the child owned by
        // nobody, and `Child::drop` neither kills nor reaps: the tree would run
        // on under a `PATH` this fixture wrote.
        let mut child = command.spawn().map_err(io("the spawn"))?;
        let group = ContainedProcessTree::adopt(&mut child)?;
        let mut guard = Self {
            child,
            group,
            stdout: None,
            stderr: None,
        };
        let stdout = take_pipe(guard.child.stdout.take(), "stdout")?;
        let stderr = take_pipe(guard.child.stderr.take(), "stderr")?;
        guard.stdout = start_stdout(stdout, run.capture_stdout);
        // stderr is drained unconditionally: a row that closes stdout still has
        // to report what the child said about the failed write.
        guard.stderr = Some(thread::spawn(move || drain(stderr)));
        write_stdin(&mut guard.child, run.stdin)?;
        Ok(guard)
    }

    /// Wait out the budget, tear the tree down, and report what it wrote.
    pub(crate) fn finish(mut self, budget: Duration) -> Result<Completed, Failure> {
        let tree_root = self.child.id();
        let waited = self.wait(budget);
        let captured_stdout = self.stdout.is_some();
        let (stdout, stderr) = self.teardown()?;
        Ok(Completed {
            tree_root,
            outcome: waited?,
            stdout,
            stderr,
            captured_stdout,
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

    /// Close stdin, kill the whole tree, reap the child, and collect both logs.
    ///
    /// The tree is killed even after a clean exit: a descendant the child left
    /// behind still holds the inherited pipes, so joining a drain before the
    /// kill would block on a process nobody is waiting for.
    fn teardown(&mut self) -> Result<(Box<str>, Box<str>), Failure> {
        std::mem::drop(self.child.stdin.take());
        self.group.terminate()?;
        self.child.wait().map_err(io("the reap"))?;
        let stdout = match self.stdout.take() {
            Some(handle) => joined(handle, "stdout")?,
            None => Box::default(),
        };
        let stderr = joined(take_pipe(self.stderr.take(), "stderr")?, "stderr")?;
        Ok((stdout, stderr))
    }
}

/// Release the tree for a guard nobody tore down.
///
/// `teardown` is the only path that reports a result; a panic before it, or a
/// spawn that could not hand over its pipes, would otherwise leave a killed
/// child unreaped and any drain thread parked on a pipe that never closes.
impl Drop for Guard {
    fn drop(&mut self) {
        std::mem::drop(self.group.terminate());
        std::mem::drop(self.child.kill());
        std::mem::drop(self.child.wait());
        for handle in [self.stdout.take(), self.stderr.take()]
            .into_iter()
            .flatten()
        {
            std::mem::drop(handle.join());
        }
    }
}

fn take_pipe<R>(pipe: Option<R>, name: &str) -> Result<R, Failure> {
    pipe.ok_or_else(|| Failure::Protocol(format!("the child has no {name}").into()))
}

/// Start the ordinary stdout drain, or close the reader before the child
/// writes so the binary observes a broken pipe.
fn start_stdout<R: Read + Send + 'static>(
    pipe: R,
    capture: bool,
) -> Option<JoinHandle<std::io::Result<Vec<u8>>>> {
    match capture {
        true => Some(thread::spawn(move || drain(pipe))),
        false => {
            std::mem::drop(pipe);
            None
        }
    }
}

/// Write the whole stdin fixture, then close the pipe before the wait begins.
///
/// A run that states no fixture keeps the pipe until teardown, exactly as
/// every existing supply-chain row does. A fixture over [`STDIN_CEILING`]
/// refuses here rather than blocking the harness on a child that never reads.
fn write_stdin(child: &mut Child, fixture: Option<&[u8]>) -> Result<(), Failure> {
    let Some(bytes) = fixture else {
        return Ok(());
    };
    if bytes.len() > STDIN_CEILING {
        return Err(Failure::Protocol(
            format!(
                "the stdin fixture is {} bytes, over the {STDIN_CEILING}-byte ceiling this \
                 harness writes before its wait begins",
                bytes.len()
            )
            .into(),
        ));
    }
    let mut pipe = take_pipe(child.stdin.take(), "stdin")?;
    pipe.write_all(bytes).map_err(io("the stdin write"))
}

fn drain<R: Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut collected = Vec::new();
    reader.read_to_end(&mut collected)?;
    Ok(collected)
}

/// Join one drain thread and decode what it read.
///
/// Lossy, because a tree killed mid-write can be cut mid-codepoint; a strict
/// decode would replace the diagnostic a reader needs with a different one.
fn joined(
    handle: JoinHandle<std::io::Result<Vec<u8>>>,
    name: &'static str,
) -> Result<Box<str>, Failure> {
    match handle.join() {
        Ok(Ok(bytes)) => Ok(String::from_utf8_lossy(&bytes).into()),
        Ok(Err(error)) => Err(Failure::Io {
            operation: name,
            error,
        }),
        Err(_) => Err(Failure::Protocol(
            format!("the {name} drain panicked").into(),
        )),
    }
}

fn prepended_path(prefix: &Path) -> String {
    format!(
        "{}:{}",
        prefix.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}
