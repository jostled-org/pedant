//! Every way a live case ends releases the watcher, the thread, and the tree.

use std::any::Any;
use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use pedant_snippet::{
    ChangeKind, CodeIntelligenceLimits, LiveCodeIntelligenceIndex, LiveIndexError,
    ProjectAuthority, TransactionOutcome,
};

use crate::index::root::TempRoot;

use super::harness::{LIVE_REPOSITORY, Live, NAMED, UNPARSABLE, admits};
use super::probe::{PROBE_SOURCE, REPORTING_CADENCE, revision_of};
use super::tree::Tree;

/// The source the two cases that watch a live change place while observing.
///
/// One row rather than a path and a body spelled at each of the three places
/// that name it: a case waits on the path it placed, and a path stated twice is
/// a wait that can be pointed at a file nothing wrote.
const PLACED: (&str, &str) = ("crate-a/src/added.rs", "pub fn added() {}\n");

/// What the abandoned-watcher case places while the watcher is still observing.
const BEFORE_DROP: (&str, &str) = ("crate-a/src/first.rs", "pub fn first() {}\n");

/// And what it places after the drop, which nothing may ever publish.
const AFTER_DROP: (&str, &str) = ("crate-a/src/second.rs", "pub fn second() {}\n");

/// Parsable manifest bytes that are not the ones the index already holds.
///
/// The repair the refusal case applies. Restoring the original bytes would
/// rebuild the original index and republish the identity that was already
/// there, so the case would have nothing it could wait for. A comment no source
/// can see parses, and a selected manifest's exact bytes reach the index
/// identity, so this rebuild is one the case can tell apart from the last good
/// state it retained.
const REPAIRED: &str = "# a comment no source can see\n[package]\nname = \"crate-a\"\n\
                        version = \"0.1.0\"\nedition = \"2021\"\n";

/// What the deliberate panic in the failing case carries.
///
/// One spelling, read by the hook that suppresses it and by the `panic!` that
/// raises it: a hook matching on anything else would silence a real failure or
/// print this one.
const DELIBERATE: &str = "a live case fails here";

/// Success, a refused setup, a refused update, an abandoned watcher, and a
/// failing case each end with nothing still running and nothing still on disk.
///
/// Every condition here is in-process, which is the whole set this owner can
/// produce: a `RootWatcher` has no timeout of its own and no transport to
/// reach an end of. The timeout and EOF-handoff conditions belong to the
/// process that hosts one, and 9.T6 owns them over the real stdio server.
#[test]
fn live_index_watcher_teardown_is_bounded_on_success_failure_and_drop() {
    a_shut_down_watcher_joins_and_leaves_the_index_usable();
    a_shut_down_watcher_leaves_no_transaction_behind();
    a_refused_setup_starts_nothing();
    a_refused_update_leaves_the_thread_running_and_joinable();
    an_abandoned_watcher_observes_nothing();
    a_failing_case_still_releases_its_tree();
}

/// Shutdown joins the applying thread, and the index still answers afterwards.
fn a_shut_down_watcher_joins_and_leaves_the_index_usable() {
    let mut live = Live::watching();
    live.tree().place(PLACED.0, PLACED.1);
    live.wait_for("the change is published", |state| {
        admits(state, PLACED.0).then_some(())
    });

    live.stop().expect("the applying thread ends cleanly");
    live.stop()
        .expect("and stopping an already-stopped watcher is nothing to do");

    let after = live.state();
    assert!(
        !after.index().files().is_empty(),
        "no lock is still held, so the state is still readable"
    );
    let applied = live.apply(&[(PLACED.0, ChangeKind::Modified)]);
    assert_eq!(
        applied.outcome(),
        TransactionOutcome::Published,
        "and a batch stated by hand still rebuilds after the observer is gone"
    );
}

/// Shutdown is a barrier, and the join is what makes it one.
///
/// Dropping the observation stops new reports. It does nothing about the ones
/// already handed over, so a shutdown that dropped the observation and
/// returned would leave a rebuild running behind it, publishing over the state
/// its caller had just read.
///
/// The condition has to be produced rather than waited for: a joined thread
/// and an unjoined idle one are the same thing, and the only difference a
/// caller can reach is work still in flight. So a second thread keeps the host
/// reporting across the shutdown, and the claim is an absence — the ledger and
/// the state a caller reads when shutdown returns are the ones still there a
/// quiet window later.
fn a_shut_down_watcher_leaves_no_transaction_behind() {
    let mut live = Live::watching();
    let running = Arc::new(AtomicBool::new(false));
    let mut writer = Rewriter::reporting(&live, &running);

    live.stop().expect("the applying thread ends cleanly");
    let sealed = live.ledger().applied();
    let published = live.state().revision();

    writer.stop();
    assert!(
        !running.load(Ordering::Relaxed),
        "stopping the writer joined the thread rather than only telling it to stop"
    );

    let quiet = live.quiet();
    assert_eq!(
        live.ledger().applied(),
        sealed,
        "shutdown waited for the thread it stopped feeding, so no transaction followed it"
    );
    assert_eq!(
        quiet.revision(),
        published,
        "and the state it returned over is the last one there will be"
    );
}

/// One thread rewriting one already-admitted source, owned by the case that
/// started it.
///
/// The command flag and the handle travel together because a case that held
/// them apart would clear the flag on its success path alone: a panic, a failed
/// assertion, or a wait that ran out of its bound would return without ever
/// reaching the two statements, leaving a thread writing into a tree the unwind
/// is about to remove. That is a directory `remove_dir_all` can find repopulated
/// between its scan and its `rmdir`, and a writer still running through every
/// row after it. Dropping this stops the thread and joins it, and because every
/// case here declares its owner after the [`Live`] it writes into, the drop runs
/// before the tree does.
struct Rewriter {
    writing: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Rewriter {
    /// Start rewriting `path`, reporting through `running` until the thread
    /// ends.
    ///
    /// An admitted source rather than a new one, because the host watches what
    /// it was told to watch: a file created after the observation started is
    /// reported through its directory and enters the watch afterwards, which is
    /// a race this case has no reason to run. Every write states different
    /// bytes, so every one of them is a rebuild the index has to publish.
    ///
    /// `running` is raised here rather than inside the thread, so it means
    /// started-and-not-yet-ended from the statement that returns this owner
    /// rather than from whenever the host got round to scheduling it. It is a
    /// report and not a claim: it is stored on the calling thread and cleared
    /// only by the spawned one's clean exit, so it is `true` from here until
    /// something asks the thread to stop, for a thread that was never scheduled
    /// as much as for one that is writing. Its readers are therefore the two
    /// cases that assert it has been *cleared*, each through the handle it
    /// already holds; this owner keeps no copy of its own to be read back from.
    ///
    /// The pause between rewrites is the host's own reporting cadence, and the
    /// bytes are the ones every rewrite in this tree states. Both belong to
    /// [`super::probe`], which owns what this host has to be waited on for: a
    /// thread pausing faster than the backend reports would produce a quiet
    /// watcher rather than a busy one, which is the opposite of the condition
    /// the case that starts it needs.
    ///
    /// A write that refuses is a tree the case has already released, and nothing
    /// here is waiting to be told about it.
    fn over(path: &Path, running: &Arc<AtomicBool>) -> Self {
        let path = path.to_path_buf();
        let writing = Arc::new(AtomicBool::new(true));
        running.store(true, Ordering::Relaxed);
        let commanded = Arc::clone(&writing);
        let reported = Arc::clone(running);
        let handle = thread::spawn(move || {
            let mut ordinal = 0_u32;
            while commanded.load(Ordering::Relaxed) {
                drop(fs::write(&path, revision_of(ordinal)));
                ordinal = ordinal.saturating_add(1);
                thread::sleep(REPORTING_CADENCE);
            }
            reported.store(false, Ordering::Relaxed);
        });
        Self {
            writing,
            handle: Some(handle),
        }
    }

    /// Start rewriting [`PROBE_SOURCE`], and return once the index is
    /// publishing the rewrites.
    ///
    /// The condition every case that starts one needs is a host still
    /// reporting, and a thread that has been spawned is not yet that. Waiting
    /// here rather than in each case leaves one place where "the writer is
    /// going" is decided.
    fn reporting(live: &Live, running: &Arc<AtomicBool>) -> Self {
        let opening = live.state().index().revision();
        let writer = Self::over(&live.tree().at(PROBE_SOURCE), running);
        live.wait_for("the host is reporting the rewrites", |state| {
            (state.index().revision() != opening).then_some(())
        });
        writer
    }

    /// Whether the writing thread is still going, asked of the thread.
    ///
    /// The handle's own answer rather than the command flag beside it. That flag
    /// is stored on the calling thread and cleared only by a clean exit, so it
    /// reads `true` for a thread that was never scheduled and for one that died
    /// mid-write — a reading that cannot be false wherever a case would want to
    /// make it. A finished handle can: nothing has asked this thread to stop, so
    /// a thread that has ended has ended by panicking.
    fn writing(&self) -> bool {
        self.handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }

    /// Stop the thread and join it, leaving the drop nothing to do.
    fn ended(&mut self) -> thread::Result<()> {
        self.writing.store(false, Ordering::Relaxed);
        match self.handle.take() {
            Some(handle) => handle.join(),
            None => Ok(()),
        }
    }

    /// Stop the thread and require it to have ended cleanly.
    fn stop(&mut self) {
        self.ended().expect("the writing thread ends");
    }
}

impl Drop for Rewriter {
    /// A case that stopped its writer arrives here with nothing left to do.
    /// Every other way a case ends arrives here instead, and how the thread
    /// ended is not a claim an unwind is in any position to make.
    fn drop(&mut self) {
        drop(self.ended());
    }
}

/// A setup that refuses hands back the refusal and holds nothing.
fn a_refused_setup_starts_nothing() {
    let root = TempRoot::new();
    let missing = root.canonical().join("not-a-directory");
    let refused = LiveCodeIntelligenceIndex::open(&missing, &[], CodeIntelligenceLimits::default())
        .err()
        .expect("a root that is not a directory opens nothing");
    assert!(
        matches!(refused, LiveIndexError::Build(_)),
        "and says so as a build refusal: {refused}"
    );

    let tree = Tree::of(LIVE_REPOSITORY);
    let named = LiveCodeIntelligenceIndex::open(
        tree.root(),
        &[ProjectAuthority::RustManifest {
            path: Box::from("absent/Cargo.toml"),
        }],
        CodeIntelligenceLimits::default(),
    )
    .err()
    .expect("an authority the caller named and the tree does not hold opens nothing");
    assert!(
        matches!(named, LiveIndexError::Build(_)),
        "on the same terms: {named}"
    );
}

/// A rebuild that refuses does not end the thread that ran it.
///
/// The join is the weaker half of that claim and cannot carry it alone:
/// `apply_batches` returns on the first apply error, and `shutdown` joins a
/// thread that has already exited exactly as cleanly as one that is still
/// waiting for reports. So the refusal is followed by a repair, and the case
/// requires a further rebuild to be published before it stops — work only a
/// thread that survived the refusal can do.
fn a_refused_update_leaves_the_thread_running_and_joinable() {
    let mut live = Live::over(
        Tree::of(LIVE_REPOSITORY),
        &[ProjectAuthority::RustManifest {
            path: Box::from(NAMED),
        }],
    );
    live.watch();

    live.tree().write(NAMED, UNPARSABLE);
    live.wait_for("the failed rebuild keeps the last good index", |state| {
        (state.health().stale_scopes() > 0).then_some(())
    });

    let retained = live.state().index().revision();
    live.tree().write(NAMED, REPAIRED);
    live.wait_for(
        "the thread that refused applies the repair after it",
        |state| (state.index().revision() != retained).then_some(()),
    );

    live.stop()
        .expect("the applying thread survived the refusal and still joins");
}

/// A watcher that is dropped rather than shut down stops observing.
fn an_abandoned_watcher_observes_nothing() {
    let mut live = Live::watching();
    live.tree().place(BEFORE_DROP.0, BEFORE_DROP.1);
    live.wait_for("the watcher is live", |state| {
        admits(state, BEFORE_DROP.0).then_some(())
    });

    live.abandon();
    let applied = live.ledger().applied();
    live.tree().place(AFTER_DROP.0, AFTER_DROP.1);

    let quiet = live.quiet();
    assert_eq!(
        live.ledger().applied(),
        applied,
        "a dropped watcher applies nothing more"
    );
    assert!(
        !admits(&quiet, AFTER_DROP.0),
        "so the published state is the one the last transaction left"
    );
}

/// A case that fails part-way through still releases everything it owned.
///
/// The failing case owns a thread of its own, and fails while that thread is
/// writing. A resource released on the success path alone is exactly the one an
/// unwind leaves behind, so the row that has to see it is this one: the thread
/// is stopped and joined by an owner rather than by a statement the panic
/// skipped, and only then is the tree removed.
fn a_failing_case_still_releases_its_tree() {
    let seen: Arc<Mutex<PathBuf>> = Arc::new(Mutex::new(PathBuf::new()));
    let recorded = Arc::clone(&seen);
    let running = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&running);

    // The default hook prints the deliberate panic below to stderr, where a
    // reader would take it for a failure of this run rather than the subject of
    // it. The hook a case sets is the whole process's, and `cargo test` runs the
    // other cases of this binary on threads of their own, so a hook that
    // silenced everything would take the message and the location off a real
    // panic raised beside it. This one suppresses the one payload it raises and
    // forwards every other to the hook that was already there.
    let previous: Arc<dyn Fn(&panic::PanicHookInfo<'_>) + Sync + Send> =
        Arc::from(panic::take_hook());
    let forwarding = Arc::clone(&previous);
    panic::set_hook(Box::new(move |info| match deliberate(info) {
        true => (),
        false => (*forwarding)(info),
    }));
    let outcome = panic::catch_unwind(AssertUnwindSafe(move || {
        let live = Live::watching();
        *recorded.lock().unwrap_or_else(|error| error.into_inner()) =
            live.tree().root().to_path_buf();
        // Declared after the tree it writes into, so the unwind releases it
        // first. The other order would remove the directory under the writer.
        let writer = Rewriter::reporting(&live, &observed);
        // Asked of the thread rather than of the flag raised on this one. The
        // flag is `true` from the statement above whatever the thread did with
        // it, so it held for a writer that was never scheduled and for one that
        // died mid-write — which is every state this row exists to rule out.
        assert!(
            writer.writing(),
            "the case is about to fail with a thread of its own still going"
        );
        live.tree().place(PLACED.0, PLACED.1);
        panic!("{DELIBERATE}");
    }));
    panic::set_hook(Box::new(move |info| (*previous)(info)));

    // The payload, not merely the failure. A `Live::watching()` probe that blew
    // its bound, a `Rewriter::reporting` wait that timed out, or any other panic
    // raised before the deliberate one satisfies `is_err` — and every assertion
    // below it still passes, so the panic this row is about would never have to
    // run for the row to report success.
    assert_eq!(
        outcome.err().as_deref().and_then(message),
        Some(DELIBERATE),
        "the case failed where it meant to, which is the case"
    );
    assert!(
        !running.load(Ordering::Relaxed),
        "and the unwind stopped the writing thread rather than leaving it to the process"
    );
    let root = seen
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    assert!(
        !root.as_os_str().is_empty(),
        "and it got far enough to own a tree"
    );
    assert!(
        !root.exists(),
        "which the unwind released, writer first, then watcher, then tree: {}",
        root.display()
    );
}

/// Whether one panic is the one the case above raised on purpose.
fn deliberate(info: &panic::PanicHookInfo<'_>) -> bool {
    message(info.payload()) == Some(DELIBERATE)
}

/// The text one panic payload carries, however it was raised.
///
/// A formatted `panic!` carries a `String` and a literal one carries a
/// `&'static str`, so both are read: a hook that knew only one of them would
/// print the deliberate panic, or silence a real one, the day the message it
/// matches is spelled the other way.
fn message(payload: &(dyn Any + Send)) -> Option<&str> {
    match payload.downcast_ref::<&str>() {
        Some(text) => Some(*text),
        None => payload.downcast_ref::<String>().map(String::as_str),
    }
}
