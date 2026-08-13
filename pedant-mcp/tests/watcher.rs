//! What a live watcher does to the shared index it was started on.
//!
//! Every case here owns its watcher through [`WatcherGuard`], which drops the
//! event source, proves no watcher thread still holds the index, and only then
//! releases the temporary workspace. A case that kept the watcher in a plain
//! binding would let the notify callback wake on a directory the test had
//! already deleted, because dropping the watcher does not join its thread.
//! Observations therefore return `Result` and are asserted after teardown.

use std::fs;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use pedant_mcp::index::WorkspaceIndex;
use pedant_mcp::watcher::start_watcher;
use pedant_types::Capability;

/// Watcher lifecycle owner. The `#[path]` is required: cargo links one test
/// executable per `tests/*.rs`, so the support tree must stay a sibling
/// directory rather than become a root of its own.
#[path = "watcher_support/guard.rs"]
mod guard;

/// The same repository fixture `index.rs` uses, declared rather than copied so
/// both roots watch one shared Cargo project shape.
#[path = "index_support/project_fixture.rs"]
mod project_fixture;

/// Where the committed fixture workspaces live, shared with every other root
/// that reads one. Same `#[path]` reason as [`guard`].
#[path = "fixture_support/committed_fixture.rs"]
mod committed_fixture;

/// A writable copy of one of those, shared with `index.rs`. Same `#[path]`
/// reason as [`guard`].
#[path = "fixture_support/writable_fixture.rs"]
mod writable_fixture;

use guard::WatcherGuard;
use writable_fixture::copy_fixture_to_temp;

/// How long the notification backend gets to establish its watch before a case
/// changes the tree. An event raised before the watch exists is never delivered,
/// so a case that edited immediately would wait out its budget on a change the
/// watcher never saw.
const WATCH_ESTABLISH: Duration = Duration::from_millis(200);

/// Drive one create-then-remove cycle inside the root package while the
/// watcher is live. Every step returns `Result` so teardown runs before the
/// caller asserts.
fn observe_reindex_and_removal<W>(guard: &WatcherGuard<W>) -> Result<(), Box<str>> {
    guard.wait_for("the root package is indexed", |index| {
        index.crate_profile("root-app").is_some()
    })?;

    let extra = guard.root().join("src/extra.rs");
    let key = extra.to_string_lossy().into_owned();
    fs::write(&extra, "")
        .map_err(|source| Box::<str>::from(format!("failed to create {key}: {source}")))?;

    guard.wait_for("the empty root-package source is indexed", |index| {
        index.file_result(&key).is_some()
    })?;

    fs::write(
        &extra,
        "use std::net::TcpStream;\npub fn dial() -> std::io::Result<TcpStream> { TcpStream::connect(\"127.0.0.1:0\") }\n",
    )
    .map_err(|source| Box::<str>::from(format!("failed to fill {key}: {source}")))?;
    guard.wait_for("the added source reaches the crate profile", |index| {
        index
            .crate_profile("root-app")
            .is_some_and(|profile| profile.capabilities().contains(&Capability::Network))
    })?;

    fs::remove_file(&extra)
        .map_err(|source| Box::<str>::from(format!("failed to remove {key}: {source}")))?;
    guard.wait_for("the removed source is dropped from the index", |index| {
        index.file_result(&key).is_none()
    })
}

/// Break one source and watch the index mark it degraded while keeping what the
/// last good analysis of the crate reported.
fn observe_degraded_file<W>(guard: &WatcherGuard<W>) -> Result<(), Box<str>> {
    thread::sleep(WATCH_ESTABLISH);

    let other_rs = guard.root().join("lib-a/src/other.rs");
    fs::write(&other_rs, "pub fn broken( {\n").map_err(|source| {
        Box::<str>::from(format!("failed to break {}: {source}", other_rs.display()))
    })?;

    guard.wait_for("the unparsable file is reported degraded", |index| {
        index
            .crate_degraded_files("lib-a")
            .is_some_and(|mut files| files.any(|(path, _)| path.ends_with("other.rs")))
    })?;

    // Read once rather than waited for: the retained result is what the index
    // held before the file broke, so a single wrong answer is the defect.
    let retained = guard.read(|index| {
        index
            .crate_profile("lib-a")
            .is_some_and(|profile| profile.capabilities().contains(&Capability::FileRead))
    })?;
    match retained {
        true => Ok(()),
        false => Err(Box::<str>::from(
            "lib-a lost FileRead, so the last good analysis result was discarded",
        )),
    }
}

/// Rename one indexed source and watch the index drop the path that is gone.
fn observe_rename_reindex<W>(guard: &WatcherGuard<W>) -> Result<(), Box<str>> {
    thread::sleep(WATCH_ESTABLISH);

    let old_path = guard.root().join("lib-a/src/other.rs");
    let new_path = guard.root().join("lib-a/src/renamed.rs");
    let old_key = old_path.to_string_lossy().into_owned();
    let new_key = new_path.to_string_lossy().into_owned();

    fs::rename(&old_path, &new_path)
        .map_err(|source| Box::<str>::from(format!("failed to rename {old_key}: {source}")))?;

    guard.wait_for("the renamed source replaces the path it left", |index| {
        index.file_result(&old_key).is_none() && index.file_result(&new_key).is_some()
    })
}

#[test]
fn mcp_watcher_cutover_preserves_incremental_reindex_and_removal() {
    let workspace = project_fixture::build_project_workspace();
    let root = workspace.path().canonicalize().unwrap();
    let index = Arc::new(RwLock::new(WorkspaceIndex::build(&root, None).unwrap()));
    let watcher = start_watcher(&index).unwrap();
    let guard = WatcherGuard::adopt(workspace, root, index, watcher);

    let outcome = observe_reindex_and_removal(&guard);
    let teardown = guard.shut_down();

    outcome.expect("watcher must reindex and remove root-package sources");
    teardown.expect("the watcher must release the index before the workspace drops");
}

#[test]
fn test_watcher_keeps_last_good_result_and_marks_file_degraded() {
    let workspace = copy_fixture_to_temp("multi_crate");
    let root = workspace.path().canonicalize().unwrap();
    let index = Arc::new(RwLock::new(WorkspaceIndex::build(&root, None).unwrap()));
    assert!(
        index
            .read()
            .unwrap()
            .crate_profile("lib-a")
            .is_some_and(|profile| profile.capabilities().contains(&Capability::FileRead)),
        "expected FileRead before introducing invalid Rust"
    );

    let watcher = start_watcher(&index).unwrap();
    let guard = WatcherGuard::adopt(workspace, root, index, watcher);

    let outcome = observe_degraded_file(&guard);
    let teardown = guard.shut_down();

    outcome.expect("the watcher must mark the file degraded and keep the last good result");
    teardown.expect("the watcher must release the index before the workspace drops");
}

#[test]
fn test_watcher_removes_stale_entry_after_rename() {
    let workspace = copy_fixture_to_temp("multi_crate");
    let root = workspace.path().canonicalize().unwrap();
    let index = Arc::new(RwLock::new(WorkspaceIndex::build(&root, None).unwrap()));
    let old_key = root
        .join("lib-a/src/other.rs")
        .to_string_lossy()
        .into_owned();
    assert!(
        index.read().unwrap().file_result(&old_key).is_some(),
        "expected old file path to be indexed before rename"
    );

    let watcher = start_watcher(&index).unwrap();
    let guard = WatcherGuard::adopt(workspace, root, index, watcher);

    let outcome = observe_rename_reindex(&guard);
    let teardown = guard.shut_down();

    outcome.expect("the watcher must drop the renamed source's old path and index its new one");
    teardown.expect("the watcher must release the index before the workspace drops");
}
