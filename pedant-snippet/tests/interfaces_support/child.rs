//! The live stdio server one test owns, and the child plumbing it shares.
//!
//! Both transport journeys run the real binary, so no helper here asserts while
//! a child is live: each returns a [`Failure`] and the caller collects the
//! journey, tears the child down, and only then panics. Every child roots a
//! contained process tree ([`crate::contained`]), every pipe is drained for as
//! long as the child lives — an unread pipe fills and blocks its writer — every
//! wait is bounded, and every error exit closes stdin, kills, and reaps before
//! returning. `kill_on_drop` only signals: it hands the corpse to the runtime,
//! which a test runtime dropping straight after may never reap. [`Server`]
//! therefore carries a destructor as well, so a panic that skips its shutdown
//! still ends the tree and releases the task draining the child's stderr.
//!
//! The reap, the pipe pair, and the lossy decode belong to
//! [`crate::contained`], which spawns every child this root owns. This module
//! owns one shape a child can take — the session a journey talks to — and
//! [`crate::command`] owns the other: one run that is asked nothing and finishes
//! on its own.

use std::process::ExitStatus;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStderr, ChildStdout};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::contained::{Descendants, Spawned, pipes, released, spawn, text};
use crate::failure::{BUDGET, Failure, bounded};

/// One finished server: how it exited and everything it logged.
pub struct Termination {
    /// The exit status the process reported.
    pub status: ExitStatus,
    /// Everything the process wrote to stderr over its whole life.
    pub stderr: Box<str>,
    /// Everything the server sent unsolicited: the stdout left after the last
    /// read, drained while the process exited.
    pub trailing: Box<str>,
    /// What the server's process tree still held once the server had exited.
    pub descendants: Descendants,
    /// How long the exit took, measured from the client's EOF to the reap.
    ///
    /// The shutdown this binary contracts is bounded, and a bound nobody
    /// measures is a bound only the harness's own thirty-second ceiling
    /// enforces — which is not the claim any caller makes.
    pub elapsed: Duration,
}

/// Read everything a child writes to one pipe, until it closes.
///
/// Into a `Vec<u8>` and through [`text`], for the reason that decode is lossy:
/// this drain is running when the child is killed, and a server cut mid-write
/// can be cut mid-codepoint. A strict `read_to_string` refuses there and
/// discards the whole run's log as an I/O failure — on exactly the path
/// [`Server::shutdown`] calls the one whose diagnostics matter most.
async fn drain(mut stderr: ChildStderr) -> std::io::Result<Box<str>> {
    let mut logged = Vec::new();
    stderr.read_to_end(&mut logged).await?;
    Ok(text(&logged))
}

/// A live stdio MCP server owned by one test.
pub struct Server {
    spawned: Spawned,
    /// The next request id nobody on this connection has used.
    ///
    /// Allocated rather than written down wherever a journey asks a question
    /// per poll: a reply is matched to its request by id, and a bounded poll
    /// issues as many questions as the host makes it. It opens at two because
    /// the handshake owns one, and the cases that write their own ids down —
    /// the registry and parity claims, where the id is part of what is being
    /// proved — never allocate from here.
    next_id: i64,
    stdout: BufReader<ChildStdout>,
    /// Drains stderr for the child's whole life. A pipe nobody reads fills and
    /// blocks the writer, so an unread stderr would hang the server mid-journey;
    /// draining it also keeps its diagnostics for a failure message.
    ///
    /// Held in an `Option` because [`Server::shutdown`] takes the handle to
    /// await it, and a type with a destructor cannot be moved out of.
    stderr: Option<JoinHandle<std::io::Result<Box<str>>>>,
}

/// Release the tree and the drain task for a server nobody shut down.
///
/// [`Server::shutdown`] is the only path that reaps the child and awaits its
/// log; a panic anywhere between [`Server::start`] and that call skips it.
/// `kill_on_drop` signals the direct child alone, so the tree is ended here
/// too, and the drain task that would otherwise outlive the runtime holding the
/// child's stderr pipe is released with it.
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(drain) = self.stderr.take() {
            drain.abort();
        }
        self.spawned.terminate();
    }
}

impl Server {
    /// Spawn the server contained, with piped stdio and a live stderr drain.
    ///
    /// The arguments are the caller's because the server indexes one repository
    /// and every journey owns its own: a start that spelled the root itself
    /// would serve whatever tree the test runner happened to stand in.
    pub async fn start(arguments: &[&str]) -> Result<Self, Failure> {
        let mut spawned = spawn(arguments).await?;
        match pipes(&mut spawned.child, "the server") {
            Ok((stdout, stderr)) => Ok(Self {
                spawned,
                next_id: 2,
                stdout: BufReader::new(stdout),
                stderr: Some(tokio::spawn(drain(stderr))),
            }),
            Err(failure) => Err(spawned.abort(failure).await),
        }
    }

    /// Take one request id, leaving the next for whoever asks after this.
    pub fn next_id(&mut self) -> i64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    /// Write one newline-delimited JSON-RPC message.
    pub async fn send(&mut self, message: &Value) -> Result<(), Failure> {
        let mut line = serde_json::to_string(message)
            .map_err(|error| Failure::Protocol(error.to_string().into()))?;
        line.push('\n');
        let stdin = self
            .spawned
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
        drop(self.spawned.child.stdin.take());
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
        let (read, waited) =
            tokio::join!(self.stdout.read_to_end(trailing), self.spawned.child.wait(),);
        read?;
        waited
    }

    /// Close stdin, wait for exit inside the budget, and reap with the logs.
    ///
    /// The order is fixed: the process is reaped, its tree is then read and
    /// ended, and only then is the stderr drain awaited. A descendant holding
    /// the inherited stderr pipe keeps that drain from ever finishing, so a
    /// shutdown that joined it first would hang on exactly the leak the
    /// [`Termination`] is meant to report.
    ///
    /// The drain is awaited on every path. A shutdown that overran [`BUDGET`] is
    /// the run whose diagnostics matter most, and dropping the handle there
    /// would detach the task holding the whole run's log.
    /// [`Spawned::abort`] has already killed the child by then, so the pipe is
    /// closed and the drain finishes.
    ///
    /// Both error exits end the tree, and neither spells the ending out here.
    /// The overrun routes through [`Spawned::abort`], which is the one error exit
    /// from a spawned tree — it reaps the child *and* terminates the tree, so a
    /// caller cannot keep one and lose the other. The reading path routes through
    /// [`released`], which terminates before it answers at all. A `terminate`
    /// written beside them would be a third statement of the same cleanup, in the
    /// one place both had already made it.
    pub async fn shutdown(mut self) -> Result<Termination, Failure> {
        self.close_stdin();
        let asked = Instant::now();
        let mut trailing = Vec::new();
        let finished = bounded("the shutdown", self.finish(&mut trailing)).await;
        let elapsed = asked.elapsed();
        let ended = match finished {
            Ok(status) => released(&self.spawned).map(|descendants| (status, descendants)),
            Err(failure) => Err(self.spawned.abort(failure).await),
        };
        let (status, descendants) = match ended {
            Ok(ended) => ended,
            Err(failure) => {
                let logged = drained(self.stderr.take()).await;
                return Err(with_logs(failure, &trailing, logged));
            }
        };
        match drained(self.stderr.take()).await {
            Ok(logged) => Ok(Termination {
                status,
                stderr: logged,
                trailing: text(&trailing),
                descendants,
                elapsed,
            }),
            Err(reason) => Err(undrained(status, &trailing, reason)),
        }
    }
}

/// Await the stderr drain inside [`BUDGET`], naming why there is no log.
///
/// The handle arrives owned, taken from the [`Server`] whose destructor would
/// otherwise abort it. It is `Some` on every path [`Server::shutdown`] takes.
///
/// The wait borrows the handle and the overrun aborts it, because dropping a
/// tokio `JoinHandle` detaches its task rather than ending it. This is the one
/// timeout in the module with nothing behind it to reap: [`Server::shutdown`]
/// has already taken the handle out of the [`Server`], so the destructor cannot
/// reach it, and a detached drain would hold the child's `ChildStderr` for the
/// rest of the runtime's life. `JoinHandle` is `Unpin`, so `&mut` is a future
/// [`timeout`] accepts and the handle survives the elapsed arm to be aborted.
async fn drained(
    reader: Option<JoinHandle<std::io::Result<Box<str>>>>,
) -> Result<Box<str>, Failure> {
    let Some(mut reader) = reader else {
        return Err(Failure::Protocol(
            "the stderr drain was already taken".into(),
        ));
    };
    match timeout(BUDGET, &mut reader).await {
        Ok(Ok(Ok(logged))) => Ok(logged),
        Ok(Ok(Err(error))) => Err(Failure::Io {
            operation: "the stderr drain",
            error,
        }),
        Ok(Err(error)) => Err(Failure::Protocol(
            format!("the stderr reader failed: {error}").into(),
        )),
        Err(_) => {
            reader.abort();
            Err(Failure::Timeout("the stderr drain"))
        }
    }
}

/// Fold the server's trailing stdout and its log into a teardown failure.
///
/// The log is the reason the failure is readable at all, so it travels with it
/// — and when the drain itself failed, that says why the log is missing rather
/// than leaving the failure looking undiagnosed. The stdout drained before the
/// failure travels beside it, because a server that answered wrongly and then
/// hung says so in the bytes it managed to write.
fn with_logs(failure: Failure, trailing: &[u8], drain: Result<Box<str>, Failure>) -> Failure {
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
