//! Bounded ownership of every `pedant-snippet` child this root spawns.
//!
//! Both transport journeys run the real binary, so no helper here asserts while
//! a child is live: each returns a [`Failure`] and the caller collects the
//! journey, tears the child down, and only then panics. Every child is spawned
//! with `kill_on_drop`, every pipe is drained for as long as the child lives —
//! an unread pipe fills and blocks its writer — every wait is bounded, and every
//! error exit closes stdin, kills, and reaps before returning. `kill_on_drop`
//! only signals: it hands the corpse to the runtime, which a test runtime
//! dropping straight after may never reap. [`Server`] therefore carries a
//! destructor as well, so a panic that skips its shutdown still releases the
//! task draining the child's stderr.

use std::future::Future;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdout, Command};
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// Every read, write, and wait in this harness is bounded by this budget.
const BUDGET: Duration = Duration::from_secs(30);

/// Why a live-child operation could not produce its result.
///
/// Both failure modes name the operation they belong to. A message that said
/// only "child I/O failed: No such file or directory" would leave a reader
/// unable to tell a spawn that never found the binary from a read that lost its
/// pipe.
#[derive(Debug)]
pub enum Failure {
    /// The operating system refused the named spawn, read, write, or wait.
    Io {
        /// The operation the harness was performing.
        operation: &'static str,
        /// What the operating system reported.
        error: std::io::Error,
    },
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
            Self::Timeout(operation) => {
                write!(formatter, "{operation} exceeded {}s", BUDGET.as_secs())
            }
            Self::Protocol(detail) => write!(formatter, "protocol failure: {detail}"),
        }
    }
}

/// One I/O failure, named by the operation that produced it.
fn io(operation: &'static str) -> impl Fn(std::io::Error) -> Failure {
    move |error| Failure::Io { operation, error }
}

/// One finished CLI run.
pub struct Output {
    /// The exit status the process reported.
    pub status: ExitStatus,
    /// Everything the process wrote to stdout.
    pub stdout: Box<str>,
    /// Everything the process wrote to stderr.
    pub stderr: Box<str>,
}

/// One finished server: how it exited and everything it logged.
pub struct Termination {
    /// The exit status the process reported.
    pub status: ExitStatus,
    /// Everything the process wrote to stderr over its whole life.
    pub stderr: Box<str>,
    /// Everything the server sent unsolicited: the stdout left after the last
    /// read, drained while the process exited.
    pub trailing: Box<str>,
}

/// Spawn the binary under test with piped stdio and kill-on-drop.
///
/// Every child runs under `LC_ALL=C`. `std::io::Error`'s `Display` is
/// `strerror_r` on unix, so the reason text a read failure reports is whatever
/// `LC_MESSAGES` selects; pinning the locale makes both transport journeys read
/// the English text [`crate::cases::MISSING_REASON`] states.
fn spawn(arguments: &[&str]) -> Result<Child, Failure> {
    Command::new(env!("CARGO_BIN_EXE_pedant-snippet"))
        .args(arguments)
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(io("the spawn"))
}

/// Await `work` inside [`BUDGET`], naming `operation` in either failure.
async fn bounded<T>(
    operation: &'static str,
    work: impl Future<Output = std::io::Result<T>>,
) -> Result<T, Failure> {
    timeout(BUDGET, work)
        .await
        .map_err(|_| Failure::Timeout(operation))?
        .map_err(io(operation))
}

/// Take both output pipes, naming `subject` when one is missing.
fn pipes(child: &mut Child, subject: &str) -> Result<(ChildStdout, ChildStderr), Failure> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Failure::Protocol(format!("the {subject} has no stdout").into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Failure::Protocol(format!("the {subject} has no stderr").into()))?;
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
async fn abort(child: &mut Child, failure: Failure) -> Failure {
    drop(child.stdin.take());
    match reap(child).await {
        Ok(()) => failure,
        Err(reaping) => {
            Failure::Protocol(format!("{failure} and the kill failed: {reaping}").into())
        }
    }
}

/// Drain both pipes into the caller's buffers and reap the process.
///
/// The buffers belong to the caller so a run that overruns [`BUDGET`] keeps
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

/// Decode what a child wrote, for a report or for an [`Output`].
///
/// Lossy, because a child killed mid-write can be cut mid-codepoint. A strict
/// decode would fail there and replace the diagnostic the reader needs with a
/// different one.
fn text(bytes: &[u8]) -> Box<str> {
    String::from_utf8_lossy(bytes).into()
}

/// Run the binary to completion, bounded, and reap it before returning.
pub async fn run(arguments: &[&str]) -> Result<Output, Failure> {
    let mut child = spawn(arguments)?;
    // The `extract` subcommand reads no input, so closing stdin proves it and
    // leaves no way for a run to block waiting on one.
    drop(child.stdin.take());
    match bounded_run(&mut child).await {
        Ok(output) => Ok(output),
        Err(failure) => Err(abort(&mut child, failure).await),
    }
}

/// Take both pipes and drain them inside the budget.
///
/// A failed run reports what the child wrote before it failed, the way
/// [`Server::shutdown`] reports the log it drained.
async fn bounded_run(child: &mut Child) -> Result<Output, Failure> {
    let (stdout, stderr) = pipes(child, "run")?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let finished = bounded(
        "the run",
        collect(child, stdout, stderr, &mut out, &mut err),
    )
    .await;
    match finished {
        Ok(status) => Ok(Output {
            status,
            stdout: text(&out),
            stderr: text(&err),
        }),
        Err(failure) => Err(with_output(failure, &out, &err)),
    }
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

/// Read everything a child writes to one pipe, until it closes.
async fn drain(mut stderr: ChildStderr) -> std::io::Result<String> {
    let mut logged = String::new();
    stderr.read_to_string(&mut logged).await?;
    Ok(logged)
}

/// A live stdio MCP server owned by one test.
pub struct Server {
    child: Child,
    stdout: BufReader<ChildStdout>,
    /// Drains stderr for the child's whole life. A pipe nobody reads fills and
    /// blocks the writer, so an unread stderr would hang the server mid-journey;
    /// draining it also keeps its diagnostics for a failure message.
    ///
    /// Held in an `Option` because [`Server::shutdown`] takes the handle to
    /// await it, and a type with a destructor cannot be moved out of.
    stderr: Option<JoinHandle<std::io::Result<String>>>,
}

/// Release the drain task for a server nobody shut down.
///
/// [`Server::shutdown`] is the only path that reaps the child and awaits its
/// log; a panic anywhere between [`Server::start`] and that call skips it.
/// `kill_on_drop` signals the child, and this releases the task that would
/// otherwise outlive the runtime holding the child's stderr pipe.
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(drain) = self.stderr.take() {
            drain.abort();
        }
    }
}

impl Server {
    /// Spawn `pedant-snippet mcp` with piped stdio and a live stderr drain.
    pub async fn start() -> Result<Self, Failure> {
        let mut child = spawn(&["mcp"])?;
        match pipes(&mut child, "server") {
            Ok((stdout, stderr)) => Ok(Self {
                child,
                stdout: BufReader::new(stdout),
                stderr: Some(tokio::spawn(drain(stderr))),
            }),
            Err(failure) => Err(abort(&mut child, failure).await),
        }
    }

    /// Write one newline-delimited JSON-RPC message.
    pub async fn send(&mut self, message: &Value) -> Result<(), Failure> {
        let mut line = serde_json::to_string(message)
            .map_err(|error| Failure::Protocol(error.to_string().into()))?;
        line.push('\n');
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| Failure::Protocol("the server stdin is closed".into()))?;
        bounded("the send", stdin.write_all(line.as_bytes())).await?;
        bounded("the flush", stdin.flush()).await
    }

    /// Read one newline-delimited JSON-RPC message.
    pub async fn recv(&mut self) -> Result<Value, Failure> {
        let mut line = String::new();
        let read = bounded("the recv", self.stdout.read_line(&mut line)).await?;
        match read {
            0 => Err(Failure::Protocol("the server closed stdout".into())),
            _ => serde_json::from_str(line.trim()).map_err(|error| {
                Failure::Protocol(format!("invalid JSON {line:?}: {error}").into())
            }),
        }
    }

    /// Send one request and read the response that answers it.
    ///
    /// A reply carrying another id or another protocol version is a protocol
    /// failure, so no assertion can compare an answer to the wrong question.
    pub async fn request(&mut self, message: &Value) -> Result<Value, Failure> {
        self.send(message).await?;
        let response = self.recv().await?;
        match (
            response["jsonrpc"] == message["jsonrpc"],
            response["id"] == message["id"],
        ) {
            (true, true) => Ok(response),
            _ => Err(Failure::Protocol(
                format!("{response} does not answer {message}").into(),
            )),
        }
    }

    /// Close stdin, which is how a client asks for shutdown.
    pub fn close_stdin(&mut self) {
        drop(self.child.stdin.take());
    }

    /// Drain stdout into the caller's buffer while the process exits.
    ///
    /// A server that writes after the last `recv` fills its stdout pipe and
    /// blocks there forever, so the wait can never be the only thing in flight.
    ///
    /// The buffer belongs to the caller, and is a `Vec<u8>`, for the reason
    /// [`collect`] records: a shutdown that overruns [`BUDGET`] must still
    /// report what the server said.
    async fn finish(&mut self, trailing: &mut Vec<u8>) -> std::io::Result<ExitStatus> {
        let (read, waited) = tokio::join!(self.stdout.read_to_end(trailing), self.child.wait(),);
        read?;
        waited
    }

    /// Close stdin, wait for exit inside the budget, and reap with the logs.
    ///
    /// The drain is awaited on both paths. A shutdown that overran [`BUDGET`] is
    /// the run whose diagnostics matter most, and dropping the handle there
    /// would detach the task holding the whole run's log. [`abort`] has already
    /// killed the child by then, so the pipe is closed and the drain finishes.
    pub async fn shutdown(mut self) -> Result<Termination, Failure> {
        self.close_stdin();
        let mut trailing = Vec::new();
        let finished = bounded("the shutdown", self.finish(&mut trailing)).await;
        let status = match finished {
            Ok(status) => status,
            Err(failure) => {
                let aborted = abort(&mut self.child, failure).await;
                let logged = drained(self.stderr.take()).await;
                return Err(with_logs(aborted, &trailing, logged));
            }
        };
        match drained(self.stderr.take()).await {
            Ok(logged) => Ok(Termination {
                status,
                stderr: logged.into(),
                trailing: text(&trailing),
            }),
            Err(reason) => Err(undrained(status, &trailing, reason)),
        }
    }
}

/// Await the stderr drain inside [`BUDGET`], naming why there is no log.
///
/// The handle arrives owned, taken from the [`Server`] whose destructor would
/// otherwise abort it. It is `Some` on every path [`Server::shutdown`] takes.
async fn drained(reader: Option<JoinHandle<std::io::Result<String>>>) -> Result<String, Failure> {
    let Some(reader) = reader else {
        return Err(Failure::Protocol(
            "the stderr drain was already taken".into(),
        ));
    };
    match timeout(BUDGET, reader).await {
        Ok(Ok(Ok(logged))) => Ok(logged),
        Ok(Ok(Err(error))) => Err(Failure::Io {
            operation: "the stderr drain",
            error,
        }),
        Ok(Err(error)) => Err(Failure::Protocol(
            format!("the stderr reader failed: {error}").into(),
        )),
        Err(_) => Err(Failure::Timeout("the stderr drain")),
    }
}

/// Fold the server's trailing stdout and its log into a teardown failure.
///
/// The log is the reason the failure is readable at all, so it travels with it
/// — and when the drain itself failed, that says why the log is missing rather
/// than leaving the failure looking undiagnosed. The stdout drained before the
/// failure travels beside it, because a server that answered wrongly and then
/// hung says so in the bytes it managed to write.
fn with_logs(failure: Failure, trailing: &[u8], drain: Result<String, Failure>) -> Failure {
    let logged = match drain {
        Ok(logged) => format!("server stderr: {logged}"),
        Err(reason) => format!("the server stderr is lost: {reason}"),
    };
    Failure::Protocol(
        format!(
            "{failure} (server trailing stdout: {:?}, {logged})",
            text(trailing)
        )
        .into(),
    )
}

/// Report a lost stderr drain without discarding a termination already in hand.
///
/// The child exited and its stdout was drained, so the exit status and the
/// unsolicited output are facts this run established. Returning the drain's I/O
/// error alone would turn a pipe blip into a teardown of unknown outcome.
fn undrained(status: ExitStatus, trailing: &[u8], reason: Failure) -> Failure {
    Failure::Protocol(
        format!(
            "the server exited {status:?} leaving {:?}, \
             but its stderr drain failed: {reason}",
            text(trailing)
        )
        .into(),
    )
}
