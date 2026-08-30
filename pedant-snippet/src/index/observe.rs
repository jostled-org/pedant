//! Test-only observation of source work performed by an index revision.

#![cfg(feature = "test-support")]

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Which stage of one revision was running when a unit of source work happened.
///
/// The four stages run in this order, and only the last one runs after the
/// index is sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkPhase {
    /// A project loader was resolving one slice's compilation closure, pulling
    /// the sources that closure reaches through the shared store.
    Resolution,
    /// The loose corpus was being admitted, after every slice had resolved.
    LooseCorpus,
    /// Retained graph nodes were being mapped onto retained declarations.
    PhysicalMapping,
    /// A published query was being answered from retained records.
    Query,
}

impl WorkPhase {
    /// The stable token this stage is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::Resolution => "resolution",
            Self::LooseCorpus => "loose_corpus",
            Self::PhysicalMapping => "physical_mapping",
            Self::Query => "query",
        }
    }
}

/// One unit of source work, as the stage that did it saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceStep {
    /// The shared store opened, read, decoded, and hashed one physical source.
    StoreRead,
    /// One source's text was handed to a language owner to parse.
    ///
    /// Recorded before the hand-off so refusals remain observable. A second
    /// entry for one physical source violates the single-parse contract.
    LanguageParse,
    /// The declaration inventory that owner produced was retained.
    DeclarationInventory,
}

impl SourceStep {
    /// The stable token this unit of work is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::StoreRead => "store_read",
            Self::LanguageParse => "language_parse",
            Self::DeclarationInventory => "declaration_inventory",
        }
    }
}

/// One recorded unit of source work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkEvent {
    phase: WorkPhase,
    step: SourceStep,
    source: Arc<str>,
}

impl WorkEvent {
    /// The stage that was running when this work happened.
    pub fn phase(&self) -> WorkPhase {
        self.phase
    }

    /// What the work was.
    pub fn step(&self) -> SourceStep {
        self.step
    }

    /// The normalized repository path the work was done for.
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// One stage entry, and how much work had already been recorded when it began.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseEntry {
    phase: WorkPhase,
    at: usize,
}

impl PhaseEntry {
    /// The stage that was entered.
    pub fn phase(self) -> WorkPhase {
        self.phase
    }

    /// How many events the trace already held when it was entered.
    ///
    /// The position is what makes "before graph mapping" a checkable claim: an
    /// event recorded after a stage began has an index at or above the position
    /// that stage entered at.
    pub fn at(self) -> usize {
        self.at
    }
}

/// How many times each unit of source work has happened.
///
/// One value rather than three counters, because a reader asks one question:
/// what has this revision spent? Three acquisitions answered it from three
/// moments, so a reader could see a read counted and the parse that followed it
/// not yet recorded — the torn view this module's single lock exists to prevent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceTallies {
    reads: u64,
    parses: u64,
    inventories: u64,
}

impl SourceTallies {
    /// How many times a physical source was read and decoded.
    pub fn reads(self) -> u64 {
        self.reads
    }

    /// How many times a source was handed to a language owner to parse.
    pub fn parses(self) -> u64 {
        self.parses
    }

    /// How many declaration inventories were retained, across every language
    /// owner.
    pub fn inventories(self) -> u64 {
        self.inventories
    }
}

/// Everything recorded in order, behind one lock.
#[derive(Debug, Default)]
struct Recorded {
    events: Vec<WorkEvent>,
    phases: Vec<PhaseEntry>,
    tallies: SourceTallies,
}

impl Recorded {
    /// The tally one unit of work is counted in.
    fn counter(&mut self, step: SourceStep) -> &mut u64 {
        match step {
            SourceStep::StoreRead => &mut self.tallies.reads,
            SourceStep::LanguageParse => &mut self.tallies.parses,
            SourceStep::DeclarationInventory => &mut self.tallies.inventories,
        }
    }
}

/// How much source work one index revision has done, and where.
#[derive(Debug, Default)]
pub struct SourceWork {
    recorded: Mutex<Recorded>,
}

impl SourceWork {
    /// Enter `phase`, if it is not the stage already entered.
    ///
    /// Re-entering the stage already running records nothing, so answering
    /// queries forever leaves one query entry rather than one per call.
    pub(crate) fn entered(&self, phase: WorkPhase) {
        let mut recorded = self.locked();
        if recorded.phases.last().map(|held| held.phase) == Some(phase) {
            return;
        }
        let at = recorded.events.len();
        recorded.phases.push(PhaseEntry { phase, at });
    }

    /// Record one unit of source work against the stage now running.
    ///
    /// Work recorded before any stage was entered is charged to
    /// [`WorkPhase::Resolution`], which is the first stage a build enters: no
    /// route in this crate reaches a source before it, so the fallback names
    /// the stage that would have been running rather than inventing one.
    ///
    /// The path is taken shared rather than borrowed. Every caller already
    /// holds it as the `Arc<str>` the store keys the record by, and three
    /// events per admitted file meant three copies of one path for a trace that
    /// outlives neither.
    pub(crate) fn recorded(&self, step: SourceStep, source: &Arc<str>) {
        let mut recorded = self.locked();
        let phase = recorded
            .phases
            .last()
            .map_or(WorkPhase::Resolution, |held| held.phase);
        let counter = recorded.counter(step);
        *counter = counter.saturating_add(1);
        recorded.events.push(WorkEvent {
            phase,
            step,
            source: Arc::clone(source),
        });
    }

    /// Every tally this revision has recorded, taken together.
    ///
    /// One acquisition, so the three counts are the same moment's reading of one
    /// trace. The accessors below are projections of this value rather than
    /// three acquisitions of their own.
    pub fn tallies(&self) -> SourceTallies {
        self.locked().tallies
    }

    /// How many times a physical source was read and decoded.
    pub fn reads(&self) -> u64 {
        self.tallies().reads()
    }

    /// How many times a source was handed to a language owner to parse.
    pub fn parses(&self) -> u64 {
        self.tallies().parses()
    }

    /// How many declaration inventories were retained, across every language
    /// owner.
    pub fn inventories(&self) -> u64 {
        self.tallies().inventories()
    }

    /// Every unit of source work this revision has done, in order.
    pub fn trace(&self) -> Box<[WorkEvent]> {
        self.locked().events.iter().cloned().collect()
    }

    /// Every stage this revision entered, in order, with the trace position it
    /// began at.
    pub fn phases(&self) -> Box<[PhaseEntry]> {
        self.locked().phases.iter().copied().collect()
    }

    /// The one acquisition of the recorded state.
    ///
    /// A guard poisoned by a panic says nothing about what was recorded — every
    /// write here is one push under the lock — so ownership is recovered and
    /// the record is read as it stands. Observation must not turn a panic
    /// somewhere else into a second panic here.
    fn locked(&self) -> MutexGuard<'_, Recorded> {
        self.recorded.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
