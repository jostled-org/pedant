//! The root watcher, and the one thread that turns what it reports into
//! transactions.
//!
//! Two owners and one channel. The notification layer calls back on its own
//! thread and does nothing but translate and send, because a rebuild inside a
//! callback would hold the host's event queue for the length of an index. The
//! applying thread receives, settles, and applies.
//!
//! Its first transaction is neither received nor settled. The observation
//! registers after the first index was built, so every change made during that
//! build was reported to nobody and no later report names it; the thread opens
//! by rebuilding once against the tree as it stands, which covers all of them.
//!
//! Settling is what makes a batch a batch. One editor save arrives as several
//! reports and a rename arrives as two, and a rebuild per report would publish
//! revisions of trees that existed for a millisecond. So the thread blocks for
//! the first report and then drains every report that arrives within the settle
//! window, which is a wait for the host to finish rather than a poll. The drain
//! carries its own deadline as well as its gap, because a host that reports
//! something inside every window is a host whose changes would otherwise never
//! be applied at all.
//!
//! A host that drops events says so, and that notice is the one report no batch
//! can carry. It names no path, because what the host is stating is that it no
//! longer knows which paths changed — an inotify queue that overflowed, an
//! FSEvents stream that asked for the subtree to be rescanned. So the drain
//! holding one applies a whole rebuild against the tree as it stands, which
//! covers the dropped changes the way the opening rebuild covers the ones made
//! before the observation existed. Discarding the notice for naming nothing left
//! the index missing every dropped change for good, while every query still
//! answered from it as though it were current.
//!
//! A refusal ends the thread, and it is recorded on the core before the thread
//! returns. Nothing joins this thread until shutdown, which may be hours later
//! or never, so a refusal it kept to itself left every query answering from an
//! index that would never advance again — and left the shutdown that finally
//! joined it reporting a clean stop.
//!
//! Teardown is ordered and total. The notification layer is dropped first,
//! which drops the callback, which drops the sender, which ends the applying
//! thread's receive; the thread is then joined. Every exit runs it: an explicit
//! shutdown, a drop, and a panic between them.

use std::io::Write;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::{JoinHandle, Result as Joined};
use std::time::{Duration, Instant};

use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use super::change::{ChangeKind, HostReport, ObservedChange, ReportedChange};
use super::core::LiveCore;
use super::error::LiveIndexError;

/// How long the applying thread waits for a host to finish reporting.
///
/// Long enough that the several reports one save produces arrive together, and
/// short enough that a caller asking the next question does not wait on it.
const SETTLE: Duration = Duration::from_millis(50);

/// How long one drain may extend before the batch it holds is applied anyway.
///
/// A gap bound alone is not a bound. A root under continuous modification — a
/// checkout, a code generator, an editor saving on a timer — reports something
/// inside every settle window, and each report starts a new one, so the drain
/// never ends and no transaction is ever applied. This is the deadline the
/// whole drain runs under, so a repository that never goes quiet is still
/// rebuilt at a stated cadence.
///
/// Ten settle windows. Long enough that the operations a settle window exists
/// for — a save-all, a rename, a branch switch — still coalesce into one
/// rebuild rather than being cut into several. Short enough that an operator
/// asking a question during a long-running writer reads an index behind by one
/// half-second of edits plus the rebuild those edits cost, rather than by the
/// whole length of the writer.
const MAX_SETTLE: Duration = Duration::from_millis(500);

/// The name the applying thread runs under, so a stack trace names its owner.
const WORKER: &str = "pedant-snippet-live-index";

/// One observed repository root, and the thread applying what it reports.
pub struct RootWatcher {
    watcher: Option<RecommendedWatcher>,
    worker: Option<JoinHandle<()>>,
    core: Arc<LiveCore>,
}

impl RootWatcher {
    /// Start observing `core`'s root.
    ///
    /// The observation is registered before the thread is spawned, so a host
    /// that refuses to watch leaves no thread to stop: the failure this owner
    /// reports is a failure it has nothing to clean up after. It is also what
    /// makes the thread's opening rebuild total — a report raised before the
    /// thread exists queues on the channel, which is unbounded, and a change
    /// the rebuild misses because it landed after the rebuild started is a
    /// change the observation has already accepted.
    pub(super) fn started(core: &Arc<LiveCore>) -> Result<Self, LiveIndexError> {
        let (sender, receiver) = channel::<HostReport>();
        let mut watcher =
            notify::recommended_watcher(reporting(sender)).map_err(|error| refused(&error))?;
        watcher
            .watch(core.root().as_path(), RecursiveMode::Recursive)
            .map_err(|error| refused(&error))?;
        let applying = Arc::clone(core);
        let worker = std::thread::Builder::new()
            .name(String::from(WORKER))
            .spawn(move || apply_batches(&applying, &receiver))
            .map_err(|error| refused(&error))?;
        Ok(Self {
            watcher: Some(watcher),
            worker: Some(worker),
            core: Arc::clone(core),
        })
    }

    /// Stop observing and join the applying thread.
    ///
    /// # Errors
    ///
    /// A thread that ended by panicking, and the refusal a thread that ended by
    /// returning recorded before it did. The second is the one a join cannot
    /// see: a thread that refused a transaction reports it and returns
    /// normally, so a shutdown reading the join alone stated a clean stop for
    /// an index that had stopped advancing hours earlier.
    pub fn shutdown(mut self) -> Result<(), LiveIndexError> {
        self.stop()
    }

    /// Drop the observation, then join what it was feeding.
    ///
    /// Idempotent, because both an explicit shutdown and the drop that follows
    /// it run it. The recorded refusal is read only where a worker was joined,
    /// so the drop after a shutdown restates nothing the shutdown already
    /// stated.
    fn stop(&mut self) -> Result<(), LiveIndexError> {
        drop(self.watcher.take());
        match self.worker.take() {
            Some(worker) => ended(worker.join(), &self.core),
            None => Ok(()),
        }
    }
}

impl Drop for RootWatcher {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            report(&error);
        }
    }
}

/// How the applying thread ended, from how it returned and what it recorded.
///
/// A panic is the join's own answer and nothing else can state it: a thread
/// that unwinds records nothing. Every other refusal the thread reports and
/// records before returning normally, so a join that succeeded is a clean stop
/// only where the core holds no refusal.
fn ended(joined: Joined<()>, core: &LiveCore) -> Result<(), LiveIndexError> {
    match (joined, core.terminal().stated()) {
        (Err(_), _) => Err(LiveIndexError::WorkerPanicked),
        (Ok(()), Some(reason)) => Err(reason),
        (Ok(()), None) => Ok(()),
    }
}

/// The callback the notification layer runs, translating and sending only.
fn reporting(sender: Sender<HostReport>) -> impl Fn(Result<Event, notify::Error>) {
    move |result| send(&sender, translated(result))
}

/// Translate one backend answer into the report the applying thread receives.
fn translated(result: Result<Event, notify::Error>) -> Option<HostReport> {
    match result {
        Ok(event) => asked(event),
        Err(error) => {
            report(&error);
            Some(HostReport::Rescan)
        }
    }
}

/// Whether a typed backend answer requires a whole-tree rescan.
#[cfg(feature = "test-support")]
pub fn requires_rescan(result: Result<Event, notify::Error>) -> bool {
    matches!(translated(result), Some(HostReport::Rescan))
}

/// What one host event asks for, unless it asks for nothing.
///
/// The dropped-event notice is read before the kind and before the paths,
/// because it carries neither. The host sets a flag on an otherwise ordinary
/// event, names no path, and states a kind this index would translate into an
/// empty list — which is the list every discarded event comes to.
fn asked(event: Event) -> Option<HostReport> {
    if event.need_rescan() {
        return Some(HostReport::Rescan);
    }
    let changes = observed(event);
    match changes.is_empty() {
        true => None,
        false => Some(HostReport::Changes(changes)),
    }
}

/// Hand one report to the applying thread, unless the event asked for nothing.
///
/// A send that fails is a thread already stopped, which is what shutdown does
/// on purpose: the reports still in flight when a watcher is dropped have
/// nowhere to go and nothing to do.
fn send(sender: &Sender<HostReport>, asked: Option<HostReport>) {
    match asked {
        None => (),
        Some(reported) => drop(sender.send(reported)),
    }
}

/// Apply until the watcher that feeds this is dropped, and report what stopped
/// it.
///
/// The refusal is reported and recorded in one place, because there is exactly
/// one way this thread stops other than the sender being dropped. Reporting is
/// for the operator watching stderr now; recording is for the query, the ledger
/// read, and the shutdown that come afterwards.
fn apply_batches(core: &Arc<LiveCore>, reports: &Receiver<HostReport>) {
    if let Err(error) = applying(core, reports) {
        report(&error);
        core.terminal().record(error);
    }
}

/// Resynchronize, then receive, settle, and apply.
///
/// Returns when the sender is dropped, or on the first refusal: what a refusal
/// says is that one of the live index's owners is unusable, so every later
/// batch would refuse the same way and each would publish nothing.
fn applying(core: &LiveCore, reports: &Receiver<HostReport>) -> Result<(), LiveIndexError> {
    released_after(core.resynchronized())?;
    while let Ok(first) = reports.recv() {
        let drained = settle(first, reports);
        released_after(applied(core, &drained))?;
    }
    Ok(())
}

/// Apply everything one settled drain asks for, as one transaction.
///
/// A drain holding a dropped-event notice rebuilds against the tree as it
/// stands, which is the same transaction the observation's own registration
/// runs and for the same reason: what it has to reach is changes no report
/// names. The changes drained beside the notice are inside that rebuild
/// already, because it reads every file rather than the ones a batch selects.
fn applied(core: &LiveCore, drained: &HostReport) -> Result<(), LiveIndexError> {
    match drained {
        HostReport::Changes(observed) => core.applied_reports(observed),
        HostReport::Rescan => core.resynchronized(),
    }
}

/// Release the parser cache after one transaction, and hand its result on.
///
/// Taken as an already-evaluated result rather than as a closure, so the
/// release is after the work that parsed however that work turned out: a
/// refusal re-parsed every loose Rust source exactly as a success did.
fn released_after(applied: Result<(), LiveIndexError>) -> Result<(), LiveIndexError> {
    released();
    applied
}

/// Fold every report the host adds while it is still finishing into the first.
///
/// Two bounds rather than one. Each gap is at most [`SETTLE`], so the several
/// reports one save produces stay one batch. The whole drain is at most
/// [`MAX_SETTLE`], so a root that never goes quiet is rebuilt anyway instead of
/// extending the window forever.
fn settle(first: HostReport, reports: &Receiver<HostReport>) -> HostReport {
    let opened = Instant::now();
    let mut drained = first;
    while let Some(window) = remaining(opened) {
        let Ok(settled) = reports.recv_timeout(window) else {
            return drained;
        };
        drained = drained.followed_by(settled);
    }
    drained
}

/// How long a drain opened at `opened` may still wait for one report.
///
/// Absent once the drain has spent its whole deadline, which is what ends it.
/// Measured against the elapsed time rather than a computed instant, so no
/// arithmetic here can overflow and there is no panic path to reason about.
fn remaining(opened: Instant) -> Option<Duration> {
    let left = MAX_SETTLE.saturating_sub(opened.elapsed());
    match left.is_zero() {
        true => None,
        false => Some(SETTLE.min(left)),
    }
}

/// Release the Rust parser's thread-local source map.
///
/// Every rebuild re-parses every loose Rust source on this thread, and
/// `proc-macro2`'s `span-locations` retains the whole text and line table of
/// each parse for the life of the thread — with 32-bit positions that wrap past
/// four gigabytes of cumulative source, after which a lookup answers for the
/// wrong file. Nothing an index retains is a `syn` span: a structure record
/// carries a byte range, a line pair, and an owned name, and the snapshot the
/// graph is built from drops its syntax tree inside the call that parsed it. So
/// the map holds nothing this thread still reads once the rebuild has returned.
///
/// It is released here rather than inside the library's own parse because this
/// is a thread the crate owns end to end. `invalidate_current_thread_spans`
/// invalidates every span live on the calling thread, including one a consumer
/// holds, and no consumer code runs here.
#[cfg(feature = "lang-rust")]
fn released() {
    pedant_syntax::invalidate_parser_cache();
}

/// A build with no Rust backend parses no `syn` and fills no source map.
#[cfg(not(feature = "lang-rust"))]
fn released() {}

/// What one host event says about each path it names.
///
/// The event is taken by value and its path list moved out. A notification
/// layer hands the event over and drops it on the next line, so copying each
/// `PathBuf` out of it allocated one path per report to own bytes nobody else
/// still wanted.
///
/// The kind is read once for the whole event rather than once per path,
/// because it is the event's own field and every path it names shares it.
fn observed(event: Event) -> Vec<ObservedChange> {
    let Some(reported) = reported(event.kind) else {
        return Vec::new();
    };
    event
        .paths
        .into_iter()
        .map(|path| ObservedChange::reported(path, reported))
        .collect()
}

/// What one host event kind says about the paths it names.
///
/// Two of the four answers are unsettled, and deliberately so: telling a rename
/// or a stray modify from a removal means asking whether the path is still
/// there, and that question is owned by [`ReportedChange`] and asked on the
/// applying thread. Asking it here would put one `stat` per reported path on
/// the thread holding the host's event queue, ahead of the string-only
/// exclusion tests that discard most of them.
///
/// Access alone is discarded: reading a file changes no byte of it.
fn reported(kind: EventKind) -> Option<ReportedChange> {
    match kind {
        EventKind::Access(_) => None,
        EventKind::Create(_) => Some(ReportedChange::Stated(ChangeKind::Created)),
        EventKind::Remove(_) => Some(ReportedChange::Stated(ChangeKind::Removed)),
        EventKind::Modify(ModifyKind::Name(_)) => Some(ReportedChange::Renamed),
        _ => Some(ReportedChange::Touched),
    }
}

/// One live-index refusal, from whatever the host said about it.
///
/// Every way starting an observation fails states the same variant — the
/// notification layer refusing to build, refusing to watch the root, and the
/// host refusing to start the applying thread — so all three are built here and
/// the variant has one construction site.
fn refused(error: &impl std::fmt::Display) -> LiveIndexError {
    LiveIndexError::Watch {
        reason: error.to_string().into_boxed_str(),
    }
}

/// Report what no caller is waiting to be told.
///
/// The applying thread and the host callback both run with nobody to return to,
/// and a failure they swallowed would leave a live index quietly serving an
/// index that stopped following its repository.
fn report(reason: &impl std::fmt::Display) {
    drop(writeln!(
        std::io::stderr(),
        "warning: pedant-snippet live index: {reason}"
    ));
}
