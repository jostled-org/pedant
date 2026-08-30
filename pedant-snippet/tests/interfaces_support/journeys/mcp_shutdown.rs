//! 9.T6: the server exits inside its budget and leaves no descendant.
//!
//! Eight ways a run can end, and one claim about all of them: the watcher stops
//! before the process does, the process exits inside a measured bound, and no
//! part of it outlives the exit. A server that returned from its transport
//! without joining the applying thread would still satisfy an exit-status check
//! and could land a transaction after the client believed it was done.
//!
//! The process tree is what proves the second half. `kill_on_drop` only signals,
//! so every case here reaps its own child, reads the status rather than trusting
//! the runtime to, and asks the operating system whether the tree that child
//! rooted still holds anything — before this harness kills it. A row that only
//! reaped the direct child would pass unchanged against a server that leaked a
//! descendant, because nothing would have looked.
//!
//! The bound is measured rather than assumed. 8.T5 states that timeout and EOF
//! handoff are conditions of the process hosting a watcher rather than of the
//! in-process owner, and names this predicate as where they are proved: the
//! loaded row hands the watcher a repository to rebuild and then stops talking,
//! and the refusing row leaves the watcher's last transaction a refusal. Both
//! must still exit inside [`crate::journeys::outcome::EXIT_BOUND`].
//!
//! Every row is measured, and the two shapes measure from different marks. A
//! session ends when its client closes stdin, so the six rows that reach a
//! transport are timed from that EOF to the reap. The two rows that refuse
//! before any transport exists have no EOF to time from, so they are timed
//! across their whole life, from the spawn to the reap. Neither shape is left
//! to the harness's thirty-second ceiling, which no case here claims.

use serde_json::json;

use crate::child::Server;
use crate::failure::Failure;
use crate::journeys::client;
use crate::journeys::fixture::{
    Fixture, broken_authority_goes_stale, named_project_arguments, root_arguments,
};
use crate::journeys::outcome::{
    REFUSED, assert_bounded, assert_clean, assert_contained, assert_run_is_bounded,
    assert_usage_error,
};

/// How many sources one burst writes.
///
/// Enough that the settle window collects them into one batch and the
/// transaction that follows rebuilds a repository rather than a file.
const BURST: u32 = 24;

/// One burst source, which every burst writes the same bytes of.
const BURST_SOURCE: &str = "export function burst(): number {\n  return 1;\n}\n";

#[tokio::test]
async fn code_intelligence_mcp_shutdown_reaps_descendants_on_success_timeout_and_error() {
    let fixture = Fixture::new();

    assert_eof_before_any_call(&fixture).await;
    assert_eof_before_the_handshake_still_stops(&fixture).await;
    assert_eof_after_a_clean_call(&fixture).await;
    assert_a_protocol_failure_still_exits(&fixture).await;
    assert_a_root_that_cannot_be_indexed_never_serves(&fixture).await;
    assert_a_malformed_host_option_never_indexes().await;
    assert_a_loaded_watcher_still_exits_inside_the_bound().await;
    assert_a_watcher_whose_rebuild_refused_still_exits().await;
}

/// EOF after the handshake and before any call still exits cleanly.
async fn assert_eof_before_any_call(fixture: &Fixture) {
    let (_, termination) =
        client::session(&root_arguments(fixture), "the handshake", async |server| {
            client::initialized(server).await
        })
        .await;
    assert_clean(&termination, "EOF before any call");
}

/// EOF before the handshake ends the run without leaving a watcher behind.
///
/// Not a clean shutdown: a client that opened a pipe and closed it never
/// finished connecting, so the server says so rather than exiting zero on a
/// session that never began. What it owes either way is the same — stop
/// observing, join the applying thread, and exit inside the bounded wait.
async fn assert_eof_before_the_handshake_still_stops(fixture: &Fixture) {
    // Its own spawn rather than a `client::session`: the session helper drives a
    // journey and this row is the case where a client never opens one, so there
    // is nothing for it to drive.
    let server = Server::start(&root_arguments(fixture))
        .await
        .unwrap_or_else(|failure| panic!("the stdio server starts: {failure}"));
    let termination = server
        .shutdown()
        .await
        .unwrap_or_else(|failure| panic!("an unfinished session exits: {failure}"));
    assert_bounded(&termination, "an unfinished session");
    assert_eq!(
        termination.status.code(),
        Some(REFUSED),
        "an unfinished session refuses: {:?}: {}",
        termination.status,
        termination.stderr
    );
    assert!(
        termination.trailing.is_empty(),
        "and sends nothing: {}",
        termination.trailing
    );
    assert!(
        termination.stderr.contains("MCP server failed to start"),
        "and says why: {}",
        termination.stderr
    );
}

/// EOF after a served call exits cleanly, with nothing left in flight.
async fn assert_eof_after_a_clean_call(fixture: &Fixture) {
    let ((), termination) = client::session(
        &root_arguments(fixture),
        "the served call",
        async |server| clean_call(server).await,
    )
    .await;
    assert_clean(&termination, "EOF after a served call");
}

/// One handshake and one answered call.
async fn clean_call(server: &mut Server) -> Result<(), Failure> {
    client::initialized(server).await?;
    let response = client::asked(server, "list_projects", &json!({})).await?;
    client::claimed_answer(&response, "a served call").map(drop)
}

/// A call the server refuses as a protocol error leaves it able to exit.
///
/// The refusal is the point: a server that unwound its transport on a bad
/// request would exit here without joining its watcher, and the bounded
/// teardown below is what would catch it.
async fn assert_a_protocol_failure_still_exits(fixture: &Fixture) {
    let ((), termination) = client::session(
        &root_arguments(fixture),
        "the refused call",
        async |server| protocol_failure(server).await,
    )
    .await;
    assert_clean(&termination, "EOF after a protocol failure");
}

/// One handshake and one call the server never runs.
async fn protocol_failure(server: &mut Server) -> Result<(), Failure> {
    client::initialized(server).await?;
    let response = client::asked(server, "no_such_tool", &json!({})).await?;
    client::claimed_protocol_error(
        &response,
        client::INVALID_PARAMS,
        &["unknown tool: no_such_tool"],
        "a tool this server does not serve",
    )
}

/// A root that cannot be indexed refuses before the transport ever starts.
///
/// The server builds its index first on purpose: a transport that accepted a
/// handshake and then refused every call would look alive to a client that has
/// no way to ask why.
async fn assert_a_root_that_cannot_be_indexed_never_serves(fixture: &Fixture) {
    let missing = format!("{}/nowhere", fixture.root());
    let output = crate::command::run(&["mcp", "--root", &missing])
        .await
        .unwrap_or_else(|failure| panic!("the refused server exits: {failure}"));
    assert_contained(&output, "a root that cannot be indexed");
    assert_run_is_bounded(&output, "a root that cannot be indexed");
    assert_eq!(
        output.status.code(),
        Some(REFUSED),
        "a root that cannot be indexed refuses: {:?}: {}",
        output.status,
        output.stderr
    );
    assert_eq!(
        &*output.stdout, "",
        "and it speaks no protocol at all: {}",
        output.stdout
    );
    assert!(
        output.stderr.contains("invalid_root"),
        "and says which classification refused: {}",
        output.stderr
    );
}

/// A malformed host option never reaches an index at all.
async fn assert_a_malformed_host_option_never_indexes() {
    let refused = crate::command::run(&["mcp", "--project", "cobol:Build.toml"])
        .await
        .unwrap_or_else(|failure| panic!("the refused run completes: {failure}"));
    assert_usage_error(
        &refused,
        "a project authority in a language this design has no loader for",
        "cobol:Build.toml",
    );
    assert_run_is_bounded(&refused, "a malformed host option");
}

/// EOF arriving while the watcher still has a repository to rebuild.
///
/// This is the timeout row 8.T5 delegated here. The teardown joins the thread
/// it stopped feeding, so a client that stops talking mid-rebuild is the one
/// condition under which that join has real work to wait for — and the claim is
/// that it still finishes inside [`crate::journeys::outcome::EXIT_BOUND`] rather than inside whatever the
/// host feels like taking.
async fn assert_a_loaded_watcher_still_exits_inside_the_bound() {
    let fixture = Fixture::new();
    let ((), termination) = client::session(
        &root_arguments(&fixture),
        "the loaded journey",
        async |server| loaded(server, &fixture).await,
    )
    .await;
    assert_clean(&termination, "EOF with the watcher still applying");
}

/// Prove the watcher is live, then hand it a second batch and stop asking.
///
/// The first burst is waited for, so the case knows this host reports changes
/// at all and is not merely quiet. The second is not waited for: EOF follows it
/// immediately, which is the condition the claim is about.
async fn loaded(server: &mut Server, fixture: &Fixture) -> Result<(), Failure> {
    client::initialized(server).await?;
    let (_, held) = client::opened(server, "the opening state").await?;
    burst(fixture, "first");
    client::published(server, "index_revision", &held, "the first burst").await?;
    burst(fixture, "second");
    Ok(())
}

/// Write one burst of admitted sources into the watched tree.
fn burst(fixture: &Fixture, label: &str) {
    for index in 0..BURST {
        fixture.write(&format!("web/{label}{index}.ts"), BURST_SOURCE);
    }
}

/// A watcher whose last transaction refused still stops before the process does.
///
/// The named authority is what makes the refusal fatal: the caller asked for
/// that project, so the rebuild keeps the last good index and publishes a
/// stalled state rather than quietly dropping it. This case waits until that
/// state has reached the transport — which is the watcher having failed, from
/// the only place a client can see it — and then closes stdin.
async fn assert_a_watcher_whose_rebuild_refused_still_exits() {
    let fixture = Fixture::new();
    let ((), termination) = client::session(
        &named_project_arguments(&fixture),
        "the refusing journey",
        async |server| refusing_watcher(server, &fixture).await,
    )
    .await;
    assert_clean(&termination, "EOF after the watcher's rebuild refused");
}

/// Break the named authority and wait for the refusal to reach a tool answer.
///
/// The whole body is the shared setup, because this row's claim is what happens
/// *after* it: the session is torn down from here and the termination above is
/// what states the exit. 9.T5 drives the same refusal to read the staleness
/// back, and one sequence means neither journey can start breaking a different
/// file or waiting on a different health.
async fn refusing_watcher(server: &mut Server, fixture: &Fixture) -> Result<(), Failure> {
    broken_authority_goes_stale(server, fixture).await.map(drop)
}
