use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use thiserror::Error;

use crate::poll::until_answered;

/// Environment variable selecting the fixture process role.
pub const FIXTURE_ROLE_ENV: &str = "PEDANT_PROCESS_FIXTURE_ROLE";
/// Environment variable naming the test function used as the fixture process.
pub const FIXTURE_TEST_ENV: &str = "PEDANT_PROCESS_FIXTURE_TEST";
/// Environment variable holding the descendant pid file.
pub const FIXTURE_PID_FILE_ENV: &str = "PEDANT_PROCESS_FIXTURE_PID_FILE";
/// Environment variable holding the post-adoption release file.
pub const FIXTURE_RELEASE_FILE_ENV: &str = "PEDANT_PROCESS_FIXTURE_RELEASE_FILE";
/// Environment variable selecting success, timeout, or failure.
pub const FIXTURE_OUTCOME_ENV: &str = "PEDANT_PROCESS_FIXTURE_OUTCOME";
/// Environment variable selecting whether the descendant inherits stdio.
pub const FIXTURE_STDIO_ENV: &str = "PEDANT_PROCESS_FIXTURE_STDIO";

const FIXTURE_WAIT: Duration = Duration::from_secs(10);
const FIXTURE_SLEEP: Duration = Duration::from_secs(300);

/// A failure inside the reusable Rust process-tree fixture.
#[derive(Debug, Error)]
pub enum FixtureError {
    /// A required environment variable was absent.
    #[error("{0} is not set")]
    MissingEnvironment(&'static str),
    /// A fixture role or outcome was unknown.
    #[error("{name} has unsupported value {value}")]
    InvalidValue {
        /// Which environment variable held the value.
        name: &'static str,
        /// The unsupported value.
        value: Box<str>,
    },
    /// A bounded fixture wait expired.
    #[error("timed out waiting for {0}")]
    TimedOut(&'static str),
    /// An operating-system fixture operation failed.
    #[error("{operation} failed: {source}")]
    Io {
        /// The operation being performed.
        operation: &'static str,
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// The fixture was asked to end with an early failure.
    #[error("the fixture requested an early failure")]
    RequestedFailure,
}

/// Run the fixture role selected by FIXTURE_ROLE_ENV.
///
/// With no role this is a no-op, allowing the fixture test to remain harmless
/// during an ordinary test-suite run.
pub fn run_fixture() -> Result<(), FixtureError> {
    match std::env::var(FIXTURE_ROLE_ENV) {
        Err(std::env::VarError::NotPresent) => Ok(()),
        Err(std::env::VarError::NotUnicode(_)) => Err(not_unicode(FIXTURE_ROLE_ENV)),
        Ok(role) if role == "parent" => run_parent(),
        Ok(role) if role == "descendant" => {
            std::thread::sleep(FIXTURE_SLEEP);
            Ok(())
        }
        Ok(value) => Err(FixtureError::InvalidValue {
            name: FIXTURE_ROLE_ENV,
            value: value.into_boxed_str(),
        }),
    }
}

fn run_parent() -> Result<(), FixtureError> {
    let release_file = environment_path(FIXTURE_RELEASE_FILE_ENV)?;
    wait_for_file(&release_file, "fixture release")?;
    let pid_file = environment_path(FIXTURE_PID_FILE_ENV)?;
    let test_name = environment(FIXTURE_TEST_ENV)?;
    let executable = std::env::current_exe().map_err(io("fixture executable discovery"))?;
    let mut command = Command::new(executable);
    command
        .args(["--exact", &test_name, "--nocapture"])
        .env(FIXTURE_ROLE_ENV, "descendant")
        .stdin(Stdio::null());
    configure_descendant_stdio(&mut command)?;
    let child = command.spawn().map_err(io("fixture descendant spawn"))?;
    std::fs::write(pid_file, child.id().to_string()).map_err(io("fixture descendant pid write"))?;

    match environment(FIXTURE_OUTCOME_ENV)?.as_str() {
        "success" => Ok(()),
        "timeout" => {
            std::thread::sleep(FIXTURE_SLEEP);
            Ok(())
        }
        "failure" => Err(FixtureError::RequestedFailure),
        value => Err(FixtureError::InvalidValue {
            name: FIXTURE_OUTCOME_ENV,
            value: value.into(),
        }),
    }
}

fn configure_descendant_stdio(command: &mut Command) -> Result<(), FixtureError> {
    match std::env::var(FIXTURE_STDIO_ENV) {
        Err(std::env::VarError::NotPresent) => {
            command.stdout(Stdio::null()).stderr(Stdio::null());
            Ok(())
        }
        Err(std::env::VarError::NotUnicode(_)) => Err(not_unicode(FIXTURE_STDIO_ENV)),
        Ok(value) if value == "inherit" => {
            command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
            Ok(())
        }
        Ok(value) => Err(FixtureError::InvalidValue {
            name: FIXTURE_STDIO_ENV,
            value: value.into_boxed_str(),
        }),
    }
}

fn environment(name: &'static str) -> Result<String, FixtureError> {
    std::env::var(name).map_err(|error| match error {
        std::env::VarError::NotPresent => FixtureError::MissingEnvironment(name),
        std::env::VarError::NotUnicode(_) => not_unicode(name),
    })
}

/// The refusal both environment readers state for a value that is not Unicode.
///
/// The two readers disagree about what an *absent* variable means — one is the
/// fixture's harmless no-op role, the other a missing requirement — and agree
/// about nothing else. A value the platform will not spell as Unicode is that
/// one thing, so the sentinel standing in for it, and the variant carrying it,
/// are written here rather than at each reader.
fn not_unicode(name: &'static str) -> FixtureError {
    FixtureError::InvalidValue {
        name,
        value: "<non-Unicode>".into(),
    }
}

fn environment_path(name: &'static str) -> Result<PathBuf, FixtureError> {
    environment(name).map(PathBuf::from)
}

/// The pid the fixture descendant recorded, once its file holds one.
///
/// The file is the one the parent fixture writes under [`FIXTURE_PID_FILE_ENV`],
/// and its contents are a decimal pid with no framing of any kind. Reading that
/// back is this crate's half of its own contract, not either consuming root's
/// protocol: a root spelling the poll itself would be parsing a format it does
/// not own, and every such root would own a separate chance to parse it wrongly.
///
/// `None` reports a budget that expired with the file still holding no pid.
/// The wait is bounded on the same schedule every other wait in this crate
/// runs on, and a budget no clock can name is an unbounded wait rather than a
/// panic.
pub fn descendant_pid(path: &Path, budget: Duration) -> Option<u32> {
    until_answered(|| recorded_pid(path), budget)
}

/// The pid the descendant file holds, or nothing while it holds none yet.
///
/// A file that is absent, unreadable, empty, or mid-write answers the same way:
/// not yet. The parent writes the pid in one call, so a read that does not
/// parse is a read taken before that call rather than a torn one.
fn recorded_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
}

/// Poll for a file until it appears or the fixture budget expires.
fn wait_for_file(path: &Path, subject: &'static str) -> Result<(), FixtureError> {
    match until_answered(|| path.is_file().then_some(()), FIXTURE_WAIT) {
        Some(()) => Ok(()),
        None => Err(FixtureError::TimedOut(subject)),
    }
}

fn io(operation: &'static str) -> impl Fn(std::io::Error) -> FixtureError {
    move |source| FixtureError::Io { operation, source }
}
