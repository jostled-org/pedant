//! The observable production events and the single hook that records them.

/// One observable production event.
///
/// Every path payload is repository-relative and `/`-separated, so an observer
/// compares one path shape no matter which loader recorded the event.
pub(crate) enum Observation<'a> {
    /// A project index was built from a repository root, in any language.
    ProjectLoad,
    /// A build manifest was read — a `Cargo.toml` or a `go.mod`: once per
    /// manifest when the project is indexed, and once more per participating
    /// manifest when a snapshot re-checks the revision it was indexed against.
    ManifestRead(&'a str),
    /// A Rust source was read.
    SourceRead(&'a str),
    /// A Rust source was parsed. One route reaches `syn`, so this counts every
    /// parse whichever caller asked for it.
    SourceParse(&'a str),
    /// A parsed source was walked once for its definition and reference sites.
    SiteVisit(&'a str),
    /// One `use` item's tree was walked once, for both the import sites and the
    /// capability paths projected from them.
    ImportWalk(&'a str),
    /// A stored `FileIr` was projected to a capability profile.
    CapabilityProjection(&'a str),
    /// One dependency-selection edge extended its ancestry, including how many
    /// existing history entries that extension copied.
    #[cfg(feature = "resolution-test-support")]
    DependencyChainExtension { history_entries_copied: usize },
    /// A rust-analyzer workspace was loaded.
    #[cfg(feature = "semantic")]
    SemanticWorkspaceLoad,
    /// A snapshot source was set up in the semantic database for the first
    /// time. A source whose analysis is already cached records nothing.
    #[cfg(feature = "semantic")]
    SemanticFileSetup(&'a str),
    /// A snapshot source was queried for its definition targets.
    #[cfg(feature = "semantic")]
    SemanticQuery(&'a str),
    /// One reference's candidates came from a verified semantic edge.
    #[cfg(feature = "semantic")]
    Promotion(&'a str),
}

/// Hand `event` to the installed probe.
#[cfg(feature = "resolution-test-support")]
pub(crate) fn record(event: Observation<'_>) {
    super::probe::record(&event);
}

/// Discard `event`: an ordinary build installs no observer.
#[cfg(not(feature = "resolution-test-support"))]
pub(crate) fn record(event: Observation<'_>) {
    event.discard();
}

#[cfg(not(feature = "resolution-test-support"))]
impl Observation<'_> {
    /// Consume an event nothing observes.
    ///
    /// The payload is read rather than ignored so an ordinary build carries no
    /// unread field and needs no lint suppression. The result is a length the
    /// caller discards, which the optimizer removes with the call.
    fn discard(self) -> usize {
        match self {
            Self::ProjectLoad => 0,
            #[cfg(feature = "semantic")]
            Self::SemanticWorkspaceLoad => 0,
            #[cfg(feature = "semantic")]
            Self::SemanticFileSetup(path) | Self::SemanticQuery(path) | Self::Promotion(path) => {
                path.len()
            }
            Self::ManifestRead(path)
            | Self::SourceRead(path)
            | Self::SourceParse(path)
            | Self::SiteVisit(path)
            | Self::ImportWalk(path)
            | Self::CapabilityProjection(path) => path.len(),
        }
    }
}
