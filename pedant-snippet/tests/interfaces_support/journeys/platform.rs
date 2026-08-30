//! 9.T9: the process contract every host is held to, plus each host's own.
//!
//! Four rows are portable and hold everywhere: a spawned command answers over
//! real pipes, every path it prints is normalized with `/` however the host
//! spells one, the stdio server exits inside a measured bound on EOF, and the
//! process tree that server rooted holds nothing once it has gone.
//!
//! The host-specific rows sit beside them rather than in a second predicate,
//! because they are the same journey asked of a different kernel. Two of them
//! are the containment row read on different hosts: on Windows a contained tree
//! is a kill-on-close Job Object, on Unix it is a process group, and one
//! `pedant-process-guard` owner decides which — so the row states one claim and
//! the host decides what enforces it. Windows also normalizes a backslash
//! spelling, macOS replaces a recursive watcher and joins it, and Linux runs the
//! portable rows alone.
//!
//! This is the only predicate the Windows job runs, so the containment and the
//! bound are asserted here rather than left to a sibling that never executes on
//! that host.

use std::process::Command as HostCommand;
use std::time::{Duration, Instant};

use pedant_process_guard::{
    FIXTURE_OUTCOME_ENV, FIXTURE_PID_FILE_ENV, FIXTURE_RELEASE_FILE_ENV, FIXTURE_ROLE_ENV,
    FIXTURE_STDIO_ENV, FIXTURE_TEST_ENV, wait_until_gone,
};
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::process::{ChildStderr, ChildStdout};
use tokio::time::sleep;

use crate::child::Server;
use crate::contained::{Descendants, Spawned, contained, pipes, released, text};
use crate::failure::{Failure, bounded, io};
use crate::journeys::client;
use crate::journeys::fixture::{Fixture, root_arguments};
use crate::journeys::outcome::{assert_bounded, refusal, run, value};

/// The separator every printed path uses, on every host.
const SEPARATOR: char = '/';

/// The separator no printed path uses, on any host.
const FOREIGN_SEPARATOR: char = '\\';

/// The one source the normalization row asks about, spelled as this index
/// normalizes it.
///
/// Written down rather than read back off a run. The expectation used to be the
/// spawned CLI's own answer to the same question, and a `serde_json::Value`
/// index yields `Null` for a field that is not there — so a build that stopped
/// stating `result.path` at all compared `Null` against `Null` and reported
/// success on the one row that exists to prove normalization.
const NORMALIZED_PATH: &str = "crate-a/src/lib.rs";

/// How long the control row waits for a fixture file, or for a killed
/// descendant to be gone.
const FIXTURE_BOUND: Duration = Duration::from_secs(10);

/// How often the control row rereads a file the fixture parent is writing.
const FIXTURE_POLL: Duration = Duration::from_millis(25);

/// The predicate in this root the process fixture re-executes.
const FIXTURE_TEST: &str = "process_tree_fixture";

#[tokio::test]
async fn code_intelligence_platform_process_contract_is_exact() {
    let fixture = Fixture::new();

    assert_paths_are_normalized_however_the_host_spells_one(&fixture).await;
    assert_a_host_spelled_path_reaches_the_same_answer(&fixture).await;
    assert_the_tree_observation_can_see_a_survivor().await;
    assert_stdio_framing_and_bounded_exit(&fixture).await;
    assert_the_watcher_replacement_publishes(&fixture).await;
}

/// Every path the binary prints uses `/`, on every host.
async fn assert_paths_are_normalized_however_the_host_spells_one(fixture: &Fixture) {
    let listed = run(
        fixture.root(),
        &["search", "e", "--mode", "contains"],
        "a search over the mixed repository",
    )
    .await
    .unwrap_or_else(|failure| panic!("the search runs: {failure}"));
    let answered = value(&listed, "a search over the mixed repository");
    let matched = answered["result"]
        .as_array()
        .unwrap_or_else(|| panic!("a search result is an array: {answered}"));
    assert!(
        !matched.is_empty(),
        "the fixture states matches to normalize: {answered}"
    );
    for structure in matched {
        let path = structure["path"]
            .as_str()
            .unwrap_or_else(|| panic!("a structure states its path: {structure}"));
        assert!(
            !path.contains(FOREIGN_SEPARATOR),
            "a printed path is normalized with {SEPARATOR}: {path}"
        );
        assert!(
            !path.starts_with(SEPARATOR),
            "and is repository-relative: {path}"
        );
    }
}

/// A path a caller spells the host's way reaches the same normalized answer.
///
/// On Windows a caller types `crate-a\src\lib.rs`; on every other host that
/// spelling is not a path at all. Both are refused or answered by the index's
/// own normalizer rather than by the transport, which is the claim: one
/// vocabulary, whatever the shell handed over.
async fn assert_a_host_spelled_path_reaches_the_same_answer(fixture: &Fixture) {
    let normalized = run(
        fixture.root(),
        &["outline", NORMALIZED_PATH],
        "the normalized outline",
    )
    .await
    .unwrap_or_else(|failure| panic!("the normalized outline runs: {failure}"));
    assert_eq!(
        value(&normalized, "the normalized outline")["result"]["path"],
        json!(NORMALIZED_PATH),
        "the normalized spelling answers the file it names"
    );

    // Both spellings below are [`NORMALIZED_PATH`] as one host writes it. Left
    // as literals rather than derived from it, because the point of the row is
    // that a caller types what the shell hands over.
    let spelled = match cfg!(windows) {
        true => "crate-a\\src\\lib.rs",
        false => "./crate-a/src/lib.rs",
    };
    let host = run(
        fixture.root(),
        &["outline", spelled],
        "the host-spelled outline",
    )
    .await
    .unwrap_or_else(|failure| panic!("the host-spelled outline runs: {failure}"));
    match host.status.success() {
        // A host that admits the spelling must answer the same file, named by
        // the constant both runs are held to rather than by the other run.
        true => assert_eq!(
            value(&host, "the host-spelled outline")["result"]["path"],
            json!(NORMALIZED_PATH),
            "a host spelling reaches the same normalized path"
        ),
        // A host that does not must refuse it as a path, never as a file it
        // failed to find under an unnormalized name. Read as a typed envelope
        // rather than as text on stderr: the exit code and the empty stdout are
        // what make it a refusal at all, and a crash that happened to mention
        // the path would satisfy a substring search over free diagnostics.
        false => {
            let refused = refusal(&host, "a host-spelled path");
            assert!(
                matches!(
                    refused["error"]["code"].as_str(),
                    Some("path_escape" | "unknown_file")
                ),
                "and a spelling this index does not normalize is refused as a path: {refused}"
            );
        }
    }
}

/// The observation the containment rows rest on can report the other answer.
///
/// Every other row here requires `Descendants::None`, and that requirement says
/// nothing unless the observation behind it is able to say `Survived`. The
/// binary under test holds no process capability at all, so no journey in this
/// root can ever produce a survivor — which leaves `None` as the only value
/// those rows have ever seen, on any host.
///
/// So this row builds one on purpose, out of the same `pedant-process-guard`
/// owner the journeys contain their children with. It runs this test executable
/// as the guard's fixture parent; the parent starts a lingering descendant and
/// exits. The root is reaped first, exactly as every journey reaps its server,
/// and only then is the tree asked — which is the moment a root-only question
/// stops being able to answer. Windows is the host this matters most for: its
/// CI job runs this predicate and nothing else, and a job object asked about
/// its reaped root reports every tree empty.
///
/// The tree is ended before anything is asserted, on every path. This is the
/// row that exists to catch a leaked descendant, so a failure inside it must
/// not leave one: the sleeping fixture descendant would outlive the whole
/// suite. `released` performs the kill this row's own claim depends on, the
/// `terminate` after it covers the reading path, and the error path routes
/// through `Spawned::abort` — which reaps the root as well as ending the tree,
/// because a `terminate` alone leaves the corpse this harness spawned.
async fn assert_the_tree_observation_can_see_a_survivor() {
    let temporary = tempfile::tempdir().expect("the control row has a directory");
    let pid_file = temporary.path().join("descendant.pid");
    let release_file = temporary.path().join("release");
    let mut spawned = contained(fixture_parent(&pid_file, &release_file))
        .await
        .unwrap_or_else(|failure| panic!("the fixture parent starts contained: {failure}"));

    let (descendant, held) = match survivor(&mut spawned, &pid_file, &release_file).await {
        Ok(read) => {
            spawned.terminate();
            read
        }
        // The one error exit from a spawned tree. A bare `terminate` here
        // signals the tree and never reaps the direct child, and `Spawned`
        // carries no destructor of its own — so the row written to catch a
        // leaked descendant would leave a corpse behind whenever it failed.
        Err(failure) => panic!(
            "the control row reads its own tree: {}",
            spawned.abort(failure).await
        ),
    };
    assert_eq!(
        held,
        Descendants::Survived,
        "the tree observation reports descendant {descendant}, which outlived the reaped root \
         this host contains it with"
    );
    assert!(
        wait_until_gone(descendant, FIXTURE_BOUND),
        "and the kill that follows the reading ends descendant {descendant}"
    );
}

/// Release and reap the fixture parent, read and end its tree, then drain it.
///
/// The release file is written only once adoption is complete: the parent
/// blocks on it, so the descendant it starts is born inside the contained tree
/// rather than beside it.
///
/// The descendant inherits the parent's output handles on purpose. Windows can
/// do that even when the child requests null standard streams, and a drain
/// waiting for EOF would then wait for the descendant this row exists to
/// observe. The direct child writes only the bounded libtest report, so it is
/// reaped first; the tree is observed and ended next; only then can both pipes
/// be drained to EOF without hiding the parent's diagnostics.
async fn survivor(
    spawned: &mut Spawned,
    pid_file: &std::path::Path,
    release_file: &std::path::Path,
) -> Result<(u32, Descendants), Failure> {
    std::fs::write(release_file, b"adopted").map_err(io("the fixture release"))?;
    let (stdout, stderr) = pipes(&mut spawned.child, "the fixture parent")?;
    let status = bounded("the fixture parent", spawned.child.wait()).await?;
    let descendant = recorded_pid(pid_file).await.ok_or_else(|| {
        Failure::Protocol("the fixture parent records the descendant it started".into())
    })?;
    let held = released(spawned)?;
    let (out, err) = fixture_output(stdout, stderr).await?;
    if !status.success() {
        return Err(Failure::Protocol(
            format!(
                "the fixture parent exits cleanly: {status:?} \
                 (fixture stdout: {out:?}, fixture stderr: {err:?})"
            )
            .into(),
        ));
    }
    Ok((descendant, held))
}

/// Drain the fixture pipes after its whole tree has released their write ends.
async fn fixture_output(
    mut stdout: ChildStdout,
    mut stderr: ChildStderr,
) -> Result<(Box<str>, Box<str>), Failure> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    bounded("the fixture output", async {
        let (read_out, read_err) =
            tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err),);
        read_out?;
        read_err?;
        Ok(())
    })
    .await?;
    Ok((text(&out), text(&err)))
}

/// The command that runs this test executable as the guard's fixture parent.
fn fixture_parent(pid_file: &std::path::Path, release_file: &std::path::Path) -> HostCommand {
    let executable = std::env::current_exe().expect("this test executable is nameable");
    let mut command = HostCommand::new(executable);
    command
        .args(["--exact", FIXTURE_TEST, "--nocapture"])
        .env(FIXTURE_ROLE_ENV, "parent")
        .env(FIXTURE_TEST_ENV, FIXTURE_TEST)
        .env(FIXTURE_PID_FILE_ENV, pid_file)
        .env(FIXTURE_RELEASE_FILE_ENV, release_file)
        .env(FIXTURE_STDIO_ENV, "inherit")
        .env(FIXTURE_OUTCOME_ENV, "success");
    command
}

/// The pid the fixture parent wrote down, waited for inside the bound.
///
/// The wait is the runtime's, not the thread's. This runs on the worker driving
/// a `#[tokio::test]`, and a blocking sleep there parks the whole runtime — for
/// up to [`FIXTURE_BOUND`] — including the drain of the fixture parent's own
/// pipes. Every other wait in this harness is a bounded await, and so is this.
async fn recorded_pid(path: &std::path::Path) -> Option<u32> {
    let deadline = Instant::now() + FIXTURE_BOUND;
    loop {
        let recorded = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse().ok());
        match (recorded, Instant::now() >= deadline) {
            (Some(pid), _) => return Some(pid),
            (None, true) => return None,
            (None, false) => sleep(FIXTURE_POLL).await,
        }
    }
}

/// The stdio server frames real messages and exits contained and inside its
/// bound.
async fn assert_stdio_framing_and_bounded_exit(fixture: &Fixture) {
    let ((), termination) = client::session(
        &root_arguments(fixture),
        "the framing journey",
        async |server| framing(server).await,
    )
    .await;
    assert!(
        termination.status.success(),
        "and it exits cleanly: {:?}: {}",
        termination.status,
        termination.stderr
    );
    // The containment and the bound are asserted from this predicate rather than
    // left to 9.T6, because this is the one predicate the Windows and macOS jobs
    // run: a claim proved only on Linux says nothing about the hosts this row
    // exists for. What each kernel enforces differs — a kill-on-close Job Object
    // or a process group — and the claim is the same either way.
    assert_bounded(&termination, "the framed session");
}

/// One handshake and one answer, over real newline-delimited framing.
async fn framing(server: &mut Server) -> Result<(), Failure> {
    client::initialized(server).await?;
    let answered = client::envelope(server, "list_projects", &json!({}), "a framed call").await?;
    client::claimed(answered["index_revision"].is_string(), || {
        format!("a framed answer carries its index revision: {answered}")
    })
}

/// The host's recursive watcher publishes a change made while the server runs.
///
/// macOS replaces notify's FSEvents backend with kqueue for this repository's
/// temporary roots, and Windows and Linux keep their own; the claim below is the
/// one all three owe, which is that a source written after the handshake reaches
/// the next answer.
async fn assert_the_watcher_replacement_publishes(fixture: &Fixture) {
    let ((), termination) = client::session(
        &root_arguments(fixture),
        "the watcher journey",
        async |server| watch(server, fixture).await,
    )
    .await;
    assert_bounded(&termination, "the watching session");
}

/// Write one source and wait, bounded, for the index revision to move.
///
/// The wait is the claim. [`client::published`] returns only on a revision that
/// left the one the session opened on, and fails on the budget otherwise — so a
/// host whose watcher never reported the write fails here, and one that reported
/// it passes with nothing further to ask.
async fn watch(server: &mut Server, fixture: &Fixture) -> Result<(), Failure> {
    client::initialized(server).await?;
    let (_, held) = client::opened(server, "the opening state").await?;
    fixture.write(
        "web/platform.ts",
        "export function platform(): number {\n  return 1;\n}\n",
    );
    client::published(server, "index_revision", &held, "the host's own watcher")
        .await
        .map(drop)
}
