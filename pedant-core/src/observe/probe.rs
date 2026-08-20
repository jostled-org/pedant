//! Proof-only observation of the production loaders and the one-pass extractor.
//!
//! The probe records what the ordinary loaders already do; it never supplies a
//! second implementation. Observation state lives on the installing thread and
//! is released when the last handle drops, so one test cannot read another's
//! counts.

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use super::event::Observation;

/// Everything one installed probe observed.
#[derive(Default)]
struct ProbeState {
    manifest_reads: RefCell<Vec<Box<str>>>,
    source_reads: RefCell<Vec<Box<str>>>,
    parses: RefCell<Vec<Box<str>>>,
    site_visits: RefCell<Vec<Box<str>>>,
    import_walks: RefCell<Vec<Box<str>>>,
    capability_projections: RefCell<Vec<Box<str>>>,
    semantic_file_setups: RefCell<Vec<Box<str>>>,
    semantic_queries: RefCell<Vec<Box<str>>>,
    promotions: RefCell<Vec<Box<str>>>,
    project_loads: Cell<u32>,
    semantic_workspace_loads: Cell<u32>,
    dependency_chain_extensions: Cell<u64>,
    dependency_chain_history_copies: Cell<u64>,
}

thread_local! {
    /// The observation state of the probe installed on this thread, if any.
    /// A weak reference means dropping the last handle releases the state
    /// without a teardown call.
    static INSTALLED: RefCell<Weak<ProbeState>> = const { RefCell::new(Weak::new()) };
}

/// A cloneable handle to this thread's observation state.
#[derive(Clone)]
pub struct ResolutionProbe {
    state: Rc<ProbeState>,
}

impl ResolutionProbe {
    /// Install a probe on the current thread, replacing any earlier one.
    pub fn install() -> Self {
        let state = Rc::new(ProbeState::default());
        set_installed(Rc::downgrade(&state));
        Self { state }
    }

    /// Every build manifest the production loaders read, in order: a
    /// `Cargo.toml` from the Rust loader, a `go.mod` from the Go one.
    pub fn manifest_reads(&self) -> Box<[Box<str>]> {
        snapshot_of(&self.state.manifest_reads)
    }

    /// Every Rust source the production loaders read, in order.
    pub fn source_reads(&self) -> Box<[Box<str>]> {
        snapshot_of(&self.state.source_reads)
    }

    /// Every Rust source production parsed, in order.
    ///
    /// One route reaches `syn`, so a source appears once per parse whichever
    /// caller asked for it — the snapshot reader or the lint pipeline.
    pub fn parses(&self) -> Box<[Box<str>]> {
        snapshot_of(&self.state.parses)
    }

    /// Every source the one-pass site visitor walked, in order.
    pub fn site_visits(&self) -> Box<[Box<str>]> {
        snapshot_of(&self.state.site_visits)
    }

    /// Every `use` item whose tree the extractor walked, in order.
    pub fn import_walks(&self) -> Box<[Box<str>]> {
        snapshot_of(&self.state.import_walks)
    }

    /// Every stored `FileIr` the production detector projected, in order. A
    /// consumer that reparsed instead of reusing the stored IR names its source
    /// in [`Self::parses`] a second time rather than here, because every route
    /// to a fresh `FileIr` parses first and every parse is recorded there.
    pub fn capability_projections(&self) -> Box<[Box<str>]> {
        snapshot_of(&self.state.capability_projections)
    }

    /// How many project indexes the production loader built.
    pub fn project_loads(&self) -> u32 {
        self.state.project_loads.get()
    }

    /// How many dependency-selection edges extended an ancestry chain.
    pub fn dependency_chain_extensions(&self) -> u64 {
        self.state.dependency_chain_extensions.get()
    }

    /// How many existing ancestry entries dependency selection copied while
    /// extending chains.
    pub fn dependency_chain_history_copies(&self) -> u64 {
        self.state.dependency_chain_history_copies.get()
    }

    /// How many rust-analyzer workspaces were loaded.
    pub fn semantic_workspace_loads(&self) -> u32 {
        self.state.semantic_workspace_loads.get()
    }

    /// Every snapshot source the semantic database set up, in order. A source
    /// whose analysis is already cached appears once, not again.
    pub fn semantic_file_setups(&self) -> Box<[Box<str>]> {
        snapshot_of(&self.state.semantic_file_setups)
    }

    /// Every snapshot source queried for its definition targets, in order.
    pub fn semantic_queries(&self) -> Box<[Box<str>]> {
        snapshot_of(&self.state.semantic_queries)
    }

    /// Every source whose reference took its candidates from a semantic edge.
    pub fn promotions(&self) -> Box<[Box<str>]> {
        snapshot_of(&self.state.promotions)
    }
}

fn snapshot_of(entries: &RefCell<Vec<Box<str>>>) -> Box<[Box<str>]> {
    entries.borrow().iter().cloned().collect()
}

/// Point this thread's slot at `state`, while the thread still holds its
/// locals.
///
/// A thread whose locals are already destroyed observes nothing, which is what
/// an uninstalled probe does, so a refused access is a no-op rather than a
/// panic.
fn set_installed(state: Weak<ProbeState>) {
    let replaced = INSTALLED.try_with(|installed| installed.replace(state));
    drop(replaced);
}

/// The observation state installed on this thread, while the thread still
/// holds its locals.
fn installed() -> Option<Rc<ProbeState>> {
    INSTALLED
        .try_with(|installed| installed.borrow().upgrade())
        .ok()
        .flatten()
}

/// Record one production event against the installed probe, if any.
pub(super) fn record(event: &Observation<'_>) {
    installed().iter().for_each(|state| apply(state, event));
}

fn apply(state: &Rc<ProbeState>, event: &Observation<'_>) {
    match event {
        Observation::ProjectLoad => {
            state
                .project_loads
                .set(state.project_loads.get().saturating_add(1));
        }
        #[cfg(feature = "semantic")]
        Observation::SemanticWorkspaceLoad => {
            state
                .semantic_workspace_loads
                .set(state.semantic_workspace_loads.get().saturating_add(1));
        }
        Observation::ManifestRead(path) => push(&state.manifest_reads, path),
        Observation::SourceRead(path) => push(&state.source_reads, path),
        Observation::SourceParse(path) => push(&state.parses, path),
        Observation::SiteVisit(path) => push(&state.site_visits, path),
        Observation::ImportWalk(path) => push(&state.import_walks, path),
        Observation::CapabilityProjection(path) => push(&state.capability_projections, path),
        Observation::DependencyChainExtension {
            history_entries_copied,
        } => record_dependency_chain_extension(state, *history_entries_copied),
        #[cfg(feature = "semantic")]
        Observation::SemanticFileSetup(path) => push(&state.semantic_file_setups, path),
        #[cfg(feature = "semantic")]
        Observation::SemanticQuery(path) => push(&state.semantic_queries, path),
        #[cfg(feature = "semantic")]
        Observation::Promotion(path) => push(&state.promotions, path),
    }
}

fn record_dependency_chain_extension(state: &ProbeState, history_entries_copied: usize) {
    let copied = u64::try_from(history_entries_copied).unwrap_or(u64::MAX);
    state
        .dependency_chain_extensions
        .set(state.dependency_chain_extensions.get().saturating_add(1));
    state.dependency_chain_history_copies.set(
        state
            .dependency_chain_history_copies
            .get()
            .saturating_add(copied),
    );
}

fn push(entries: &RefCell<Vec<Box<str>>>, path: &str) {
    entries.borrow_mut().push(Box::from(path));
}
