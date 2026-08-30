//! What this host's notification backend has to be waited on for.
//!
//! Two owners live here, and both exist because a live claim is made against a
//! filesystem watcher rather than against a function. [`WatchProbe`] writes to
//! the tree in order to learn something about the host — that its watch is
//! registered, and that the reports it made have stopped arriving — rather than
//! to state any case's claim. [`Presence`] is the reading that makes the
//! absence claims falsifiable: how long this run needed to publish a change it
//! did make.
//!
//! Apart from [`harness`](super::harness) because that module owns the index
//! and the tree, and every number below is about the host underneath them. Each
//! constant here is a property of a notification backend, not of this contract.

use std::cell::Cell;
use std::thread;
use std::time::{Duration, Instant};

use pedant_snippet::LiveCodeIntelligenceIndex;

use super::harness::{DEADLINE, assert_whole, counted, published};
use super::tree::Tree;

/// The pace this host reports a rewrite of one file at.
///
/// A property of the notification backend rather than of any case. The one this
/// crate selects on macOS reports a rewrite every fifty milliseconds and
/// delivers nothing at all under a faster one, so anything that hurried would
/// be quieter than the same thing waiting.
///
/// Both readers need exactly that: the probe below waits it out between its
/// rewrites and again for the reports they made to stop arriving, and the
/// teardown case that keeps a writing thread going across a shutdown needs the
/// cadence a busy host actually reports at. Two constants carrying the same
/// number and the same paragraph were two places for a host change to land.
pub(super) const REPORTING_CADENCE: Duration = Duration::from_millis(50);

/// The longest the applying thread may hold reports before it applies them.
///
/// Production's own maximum settle window. A sample taken sooner than this says
/// nothing about whether a transaction is still in flight, because the thread
/// is entitled to be holding one for exactly this long before it starts.
const SETTLING: Duration = Duration::from_millis(500);

/// How many consecutive quiet [`SETTLING`] windows make a count a baseline.
///
/// Two rather than one, because the rebuild that follows a drain re-runs the
/// project loaders: one window can be quiet while the transaction it belongs to
/// is still being built.
const DRAINED: u32 = 2;

/// The admitted source anything that rewrites to raise a report rewrites.
///
/// Already admitted, and in a directory that existed when the index opened: a
/// file created after the observation started is reported through its parent
/// and enters the watch afterwards, which is the race a rewrite is here to
/// close rather than to run.
pub(super) const PROBE_SOURCE: &str = "crate-a/src/lib.rs";

/// The bytes one rewrite of [`PROBE_SOURCE`] states.
///
/// Every ordinal states different bytes, because a revision is a claim over
/// what the corpus holds: a rewrite of the bytes already there rebuilds to the
/// revision already published and looks exactly like a report that never
/// arrived. Written once, because a second copy of this body is a second thing
/// the source it rewrites has to stay in step with.
pub(super) fn revision_of(ordinal: u32) -> String {
    format!("pub fn make() -> u32 {{\n    {ordinal}\n}}\n")
}

/// How long a case waits to establish that nothing happened.
///
/// Only ever used for the absence claims — a dropped watcher observes nothing —
/// where the assertion is that no state arrives rather than that one does.
const QUIET: Duration = Duration::from_secs(1);

/// How far the absence window has to exceed the longest presence this host
/// needed.
///
/// An absence claim is only worth making when a state that was going to arrive
/// would already have arrived. On a host that took the whole window to publish
/// a change it did make, "nothing arrived" is a statement about the window.
const ABSENCE: u32 = 2;

/// The longest any state this case waited for took to arrive, and the absence
/// window measured against it.
///
/// One reading per [`Live`], because every wait it serves is over the same tree
/// on the same host. What the longest one measures is how slow this run is,
/// which is all an absence claim needs to know.
pub(super) struct Presence {
    longest: Cell<Duration>,
}

impl Presence {
    /// A reading that has observed nothing yet.
    pub(super) fn new() -> Self {
        Self {
            longest: Cell::new(Duration::ZERO),
        }
    }

    /// Keep this arrival if it is the slowest one so far.
    pub(super) fn record(&self, started: Instant) {
        self.longest.set(self.longest.get().max(started.elapsed()));
    }

    /// Wait out the quiet window.
    ///
    /// For the absence claims: nothing arriving is the answer, so the wait is
    /// the whole observation rather than a poll toward one. That makes the
    /// window the entire strength of the claim, so it is checked against the
    /// presence this run already measured: a host that needed longer to publish
    /// a change it did make refuses here rather than reporting its own slowness
    /// as an absence.
    ///
    /// A measurement is required before the comparison, because zero passes the
    /// comparison trivially. A [`Live`] that never watched has recorded no
    /// arrival at all, and calling this on one would sleep a second and report
    /// an absence calibrated against nothing.
    pub(super) fn quiet(&self) {
        let longest = self.longest.get();
        assert!(
            !longest.is_zero(),
            "the absence window is calibrated against a presence this run measured, and no \
             wait on this index ever recorded one"
        );
        assert!(
            QUIET >= longest.saturating_mul(ABSENCE),
            "the absence window is shorter than the presence this host needed: {QUIET:?} of \
             quiet against a change that took {longest:?} to arrive"
        );
        thread::sleep(QUIET);
    }
}

/// The probe that turns a registered watch into an observed one.
///
/// Its own type rather than two more methods on [`Live`], because it is the one
/// thing here that writes to the tree in order to learn something about the
/// host rather than to state a case's claim.
pub(super) struct WatchProbe<'live> {
    /// The index whose published state the probe watches for a change.
    pub(super) index: &'live LiveCodeIntelligenceIndex,
    /// The tree it rewrites to raise one.
    pub(super) tree: &'live Tree,
    /// The reading every rewrite's publish latency is kept in.
    pub(super) presence: &'live Presence,
}

impl WatchProbe<'_> {
    /// Establish the watch, and hand back the applied count it settled at.
    pub(super) fn establish(&self) -> u64 {
        self.observed();
        self.drained()
    }

    /// Rewrite an admitted source until the index publishes the change.
    ///
    /// An event raised before the backend registered its watch is never
    /// delivered, so a fixed pause here would be a guess a loaded host can
    /// lose: a case that then made a single change would spend its whole bound
    /// waiting for a report nobody made, and fail. Rewriting until a state
    /// arrives makes the registration something this harness observed.
    ///
    /// Every rewrite states different bytes, which is [`revision_of`]'s whole
    /// reason for taking an ordinal.
    fn observed(&self) {
        let opening = published(self.index).revision();
        let deadline = Instant::now() + DEADLINE;
        let mut probes = 0_u32;
        loop {
            probes = probes.saturating_add(1);
            // Reset here rather than before the loop. What `record` keeps is
            // the presence every absence claim is later measured against, and
            // it has to be one write's publish latency: a reading taken from
            // before the first rewrite accumulates every probe sleep instead,
            // so ten attempts on a loaded host would state half a second of
            // presence and then refuse the one-second quiet window as too
            // short — a false red that grows with the load rather than with
            // anything the index did.
            let started = Instant::now();
            self.tree.write(PROBE_SOURCE, &revision_of(probes));
            thread::sleep(REPORTING_CADENCE);
            let state = published(self.index);
            assert_whole(&state, "the state a watch-establishing probe published");
            if state.revision() != opening {
                self.presence.record(started);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the watch was never established: {probes} rewrites of {PROBE_SOURCE} over \
                 {DEADLINE:?} reached this index as nothing"
            );
        }
    }

    /// The applied count, once it has held still across two whole settle
    /// windows.
    ///
    /// The probe may have rewritten more than once before a state arrived, and
    /// the reports it made after the one it saw are still on their way. A
    /// baseline read while they were in flight would charge them to the case,
    /// which then counts its own changes as one transaction too many.
    ///
    /// The gap is a whole settle window rather than a probe pause, and two of
    /// them are required. The applying thread's own drain may extend to
    /// [`SETTLING`] before it applies anything at all, and the rebuild that
    /// follows re-runs Cargo and Go project loading, so a probe transaction
    /// still in flight is quite capable of leaving the count unmoved across two
    /// samples fifty milliseconds apart. That transaction would then be charged
    /// to the case, and the coalescing row that counts from this baseline would
    /// go red against a host that coalesced exactly as it should.
    fn drained(&self) -> u64 {
        let deadline = Instant::now() + DEADLINE;
        let mut settled = counted(self.index).applied();
        let mut quiet_windows = 0_u32;
        loop {
            thread::sleep(SETTLING);
            let applied = counted(self.index).applied();
            match applied == settled {
                true => quiet_windows = quiet_windows.saturating_add(1),
                false => {
                    settled = applied;
                    quiet_windows = 0;
                }
            }
            if quiet_windows == DRAINED {
                return settled;
            }
            assert!(
                Instant::now() < deadline,
                "the probe that established the watch never stopped being applied: \
                 {settled} transactions and still counting after {DEADLINE:?}"
            );
        }
    }
}
