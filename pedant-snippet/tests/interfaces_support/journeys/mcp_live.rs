//! 9.T5: the real stdio server publishes live states through its tools.
//!
//! The server is not a stateless reader of the tree it was pointed at. It builds
//! one index, watches the root, and republishes on every settled batch — so a
//! source written after the handshake changes the revision the next answer
//! carries, an authority written after it changes the project list too, and an
//! ignore file written after either changes which sources the index will answer
//! about at all.
//!
//! The fourth change is the one a client has to be told about rather than
//! shown: a rebuild that refuses keeps the last good index and publishes a state
//! that says so. That claim is 8.T3's in process; here it is the transport's —
//! the stale health has to reach a caller through a tool response and clear
//! through one when the repository is fixed.
//!
//! Every wait is a bounded poll for the answer to change, never a sleep for a
//! duration somebody guessed. A host that publishes sooner finishes sooner, and
//! a host that never publishes fails on the budget rather than on a race.

use serde_json::{Value, json};

use crate::child::Server;
use crate::failure::Failure;
use crate::journeys::client;
use crate::journeys::fixture::{
    Fixture, NAMED_AUTHORITY, STALE, Stale, broken_authority_goes_stale, named_project_arguments,
    root_arguments,
};
use crate::journeys::outcome::assert_clean;

/// A new source, admitted only if the watcher rediscovered the corpus.
const ADDED_SOURCE: &str = "web/added.ts";

/// A new Go module, which is a project authority and selects a new slice.
///
/// Written into a directory the fixture already holds. A host whose recursive
/// watch is emulated registers each directory as it sees it, so a tree created
/// whole can raise no event for anything inside it — and this row is about
/// authority precedence, not about how a kernel discovers a new subtree.
const ADDED_AUTHORITY: &str = "web/go.mod";

/// The ignore file the fixture already holds, so the watcher has held it since
/// the handshake and a change to it is an edit rather than a discovery.
const IGNORE_FILE: &str = ".gitignore";

/// What that file states when the fixture is built.
const IGNORED_ORIGINALLY: &str = "excluded/\n";

/// What it states once this journey excludes a directory the index admitted.
const IGNORED_WIDENED: &str = "excluded/\nscripts/\n";

/// One admitted source inside the directory the widened ignore file excludes.
const EXCLUDED_SOURCE: &str = "scripts/tool.py";

/// The manifest's own bytes, restored to prove the staleness clears.
const MANIFEST: &str = "[package]\nname = \"crate-a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";

#[tokio::test]
async fn code_intelligence_mcp_watcher_publishes_live_states() {
    assert_source_authority_and_ignore_changes_publish().await;
    assert_a_refused_rebuild_reports_stale_health_until_recovery().await;
}

/// A source, an authority, and an ignore file, each observed through the tools.
async fn assert_source_authority_and_ignore_changes_publish() {
    let fixture = Fixture::new();
    let ((), termination) = client::session(
        &root_arguments(&fixture),
        "the live journey",
        async |server| journey(server, &fixture).await,
    )
    .await;
    assert_clean(&termination, "the live session");
}

/// Observe one source change, one authority change, and one ignore change.
async fn journey(server: &mut Server, fixture: &Fixture) -> Result<(), Failure> {
    client::initialized(server).await?;

    let (_, opening) = client::opened(server, "the state the server opened with").await?;
    let held = fixture.revision_text();
    client::claimed(opening == held, || {
        format!(
            "the server opened on the same index this fixture was built from: \
             it reports {opening} and the fixture holds {held}"
        )
    })?;

    let after_source = a_new_source_is_published(server, fixture, &opening).await?;
    let after_authority = a_new_authority_is_published(server, fixture, &after_source).await?;
    an_ignore_change_narrows_and_widens_the_corpus(server, fixture, &after_authority).await
}

/// A new admitted source moves the index and is outlined from its own bytes.
///
/// The batch names one path and the transaction rebuilds the whole repository,
/// so the index identity moves.
async fn a_new_source_is_published(
    server: &mut Server,
    fixture: &Fixture,
    held: &str,
) -> Result<Box<str>, Failure> {
    fixture.write(
        ADDED_SOURCE,
        "export function added(): number {\n  return 1;\n}\n",
    );
    // The poll is the claim: it returns only on a revision that left `held`, and
    // times out on a host that never publishes one.
    let (_, after) =
        client::published(server, "index_revision", held, "an admitted source appears").await?;

    let answered = client::envelope(
        server,
        "outline_file",
        &json!({ "path": ADDED_SOURCE }),
        ADDED_SOURCE,
    )
    .await?;
    client::claimed(answered["result"]["path"] == json!(ADDED_SOURCE), || {
        format!("and the new source is outlined from its own bytes: {answered}")
    })?;
    client::claimed(answered["index_revision"] == json!(after), || {
        format!("under the revision the tools now report: {answered}")
    })?;
    Ok(after)
}

/// A new project authority rediscovers the corpus and grows the project list.
///
/// It is not merely another source: it selects a slice the previous index did
/// not have.
async fn a_new_authority_is_published(
    server: &mut Server,
    fixture: &Fixture,
    held: &str,
) -> Result<Box<str>, Failure> {
    let before = projects(server).await?;
    fixture.write(ADDED_AUTHORITY, "module example.com/web\n\ngo 1.22\n");
    fixture.write("web/serve.go", "package web\n\nfunc Serve() {}\n");
    let (_, after) =
        client::published(server, "index_revision", held, "an authority appears").await?;
    let grown = projects(server).await?;
    client::claimed(grown > before, || {
        format!("and the project list grows from {before}, where it now states {grown}")
    })?;
    Ok(after)
}

/// An ignore change takes a source out of the corpus, and puts it back.
///
/// Both halves are the claim. Excluding a directory the index had admitted
/// proves the ignore file rediscovers the corpus rather than the one file it
/// names; restoring it proves the exclusion was the ignore file's doing and not
/// a source the index lost track of.
async fn an_ignore_change_narrows_and_widens_the_corpus(
    server: &mut Server,
    fixture: &Fixture,
    held: &str,
) -> Result<(), Failure> {
    let outlined = client::envelope(
        server,
        "outline_file",
        &json!({ "path": EXCLUDED_SOURCE }),
        "the source before it is ignored",
    )
    .await?;
    client::claimed(outlined["result"]["path"] == json!(EXCLUDED_SOURCE), || {
        format!("the index admits the source this journey is about to exclude: {outlined}")
    })?;

    fixture.write(IGNORE_FILE, IGNORED_WIDENED);
    let (_, excluded) =
        client::published(server, "index_revision", held, "an ignore file widens").await?;
    let reported = client::refusal(
        server,
        "outline_file",
        &json!({ "path": EXCLUDED_SOURCE }),
        "an excluded source",
    )
    .await?;
    client::claimed(reported["error"]["code"] == json!("unknown_file"), || {
        format!("an excluded source is no longer one the index answers for: {reported}")
    })?;

    fixture.write(IGNORE_FILE, IGNORED_ORIGINALLY);
    client::published(
        server,
        "index_revision",
        &excluded,
        "an ignore file narrows",
    )
    .await?;
    let readmitted = client::envelope(
        server,
        "outline_file",
        &json!({ "path": EXCLUDED_SOURCE }),
        "the readmitted source",
    )
    .await?;
    client::claimed(
        readmitted["result"]["path"] == json!(EXCLUDED_SOURCE),
        || format!("and restoring the ignore file readmits it: {readmitted}"),
    )
}

/// A refused rebuild reports stale health through the tools until it recovers.
///
/// The authority is named on the command line, which is what makes its refusal
/// fatal rather than one degraded scope: the caller asked for that project by
/// name, so an index that quietly dropped it would answer a different question
/// than the one it was started for.
async fn assert_a_refused_rebuild_reports_stale_health_until_recovery() {
    let fixture = Fixture::new();
    let ((), termination) = client::session(
        &named_project_arguments(&fixture),
        "the stale journey",
        async |server| stale_journey(server, &fixture).await,
    )
    .await;
    assert_clean(&termination, "the stale session");
}

/// Break the named authority, read the staleness back, then fix it.
///
/// The break and the wait are [`broken_authority_goes_stale`], because the
/// shutdown journey forces the same refusal the same way. What is this
/// journey's own is everything after: which index the refusal kept, which state
/// identity moved, that every tool repeats it, and that restoring the bytes
/// clears it.
async fn stale_journey(server: &mut Server, fixture: &Fixture) -> Result<(), Failure> {
    let Stale { opened, stale } = broken_authority_goes_stale(server, fixture).await?;
    client::claimed(opened["health"]["stale_scopes"] == json!(0), || {
        format!(
            "nothing was answering from before the change when the session opened: {}",
            opened["health"]
        )
    })?;
    let good = client::stated(&opened, "index_revision", "the opening state")?;
    // The health this repository recovers to is the health it opened with,
    // read rather than written down: a case that named a status would be
    // asserting what the fixture happens to hold, and a fixture that grew one
    // degraded source would make the recovery row wait for a state that never
    // arrives.
    let sound = client::stated(&opened["health"], "status", "the opening state")?;
    // Read from the subject, so what makes the recovery wait a claim is stated
    // here rather than inferred. A fixture that opened stale would have the
    // recovery poll return on the state it was already in, and every row after
    // it would pass against an index that never recovered at all.
    client::claimed(&*sound != STALE, || {
        format!("the session opened on a sound repository, not a {STALE} one: {opened}")
    })?;

    client::claimed(
        client::stated(&stale, "index_revision", "the stale state")? == good,
        || format!("a refused rebuild keeps the last good index {good}: {stale}"),
    )?;
    client::claimed(
        client::stated(&stale, "state_revision", "the stale state")?
            != client::stated(&opened, "state_revision", "the opening state")?,
        || format!("under a state revision that says something changed: {stale}"),
    )?;
    every_answer_repeats_it(server, &stale).await?;

    fixture.write(NAMED_AUTHORITY, MANIFEST);
    let recovered = client::healthy(server, &sound, "the restored authority").await?;
    client::claimed(recovered["health"]["stale_scopes"] == json!(0), || {
        format!("the restored manifest rebuilds and nothing is stale again: {recovered}")
    })?;
    client::claimed(
        client::stated(&recovered, "index_revision", "the recovered state")? == good,
        || {
            format!(
                "and the restored bytes are the original bytes, so the index is still {good}: \
                 {recovered}"
            )
        },
    )
}

/// The stale health reaches every tool, not only the one that first saw it.
///
/// A client decides whether to trust an answer from the answer it holds, so an
/// index that reported staleness on one route and not another would be telling
/// two different clients two different things about one repository.
async fn every_answer_repeats_it(server: &mut Server, stale: &Value) -> Result<(), Failure> {
    let good = client::stated(stale, "index_revision", "the stale probe")?;
    for (name, arguments) in [
        ("search_symbols", json!({ "text": "make", "mode": "exact" })),
        ("outline_file", json!({ "path": "crate-a/src/lib.rs" })),
    ] {
        let answered = client::envelope(server, name, &arguments, name).await?;
        client::claimed(answered["health"]["status"] == json!(STALE), || {
            format!("{name} reports stale health: {answered}")
        })?;
        let scopes = answered["health"]["stale_scopes"].as_u64().unwrap_or(0);
        client::claimed(scopes > 0, || {
            format!("{name} reports every stale scope rather than a sound answer: {answered}")
        })?;
        client::claimed(
            client::stated(&answered, "index_revision", name)? == good,
            || format!("and answers from the last good index {good}: {answered}"),
        )?;
        client::stated(&answered, "state_revision", name)?;
    }
    Ok(())
}

/// How many projects the next probe answer states.
///
/// A refusal rather than a zero when the answer states no array. A count that
/// defaulted would let a reading that never parsed stand in for an empty list,
/// and the growth claim above compares two of these readings.
async fn projects(server: &mut Server) -> Result<usize, Failure> {
    let answered =
        client::envelope(server, "list_projects", &json!({}), "the project list").await?;
    answered["result"].as_array().map(Vec::len).ok_or_else(|| {
        Failure::Protocol(
            format!("the project list: the answer states its result array: {answered}").into(),
        )
    })
}
