use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

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

const FIXTURE_WAIT: Duration = Duration::from_secs(10);
const FIXTURE_SLEEP: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_millis(25);

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
        Err(std::env::VarError::NotUnicode(_)) => Err(FixtureError::InvalidValue {
            name: FIXTURE_ROLE_ENV,
            value: "<non-Unicode>".into(),
        }),
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
    let child = Command::new(executable)
        .args(["--exact", &test_name, "--nocapture"])
        .env(FIXTURE_ROLE_ENV, "descendant")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(io("fixture descendant spawn"))?;
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

fn environment(name: &'static str) -> Result<String, FixtureError> {
    std::env::var(name).map_err(|error| match error {
        std::env::VarError::NotPresent => FixtureError::MissingEnvironment(name),
        std::env::VarError::NotUnicode(_) => FixtureError::InvalidValue {
            name,
            value: "<non-Unicode>".into(),
        },
    })
}

fn environment_path(name: &'static str) -> Result<PathBuf, FixtureError> {
    environment(name).map(PathBuf::from)
}

fn wait_for_file(path: &Path, subject: &'static str) -> Result<(), FixtureError> {
    let deadline = Instant::now() + FIXTURE_WAIT;
    loop {
        match (path.is_file(), Instant::now() >= deadline) {
            (true, _) => return Ok(()),
            (false, true) => return Err(FixtureError::TimedOut(subject)),
            (false, false) => std::thread::sleep(POLL),
        }
    }
}

fn io(operation: &'static str) -> impl Fn(std::io::Error) -> FixtureError {
    move |source| FixtureError::Io { operation, source }
}
