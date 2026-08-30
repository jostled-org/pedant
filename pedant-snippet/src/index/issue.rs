//! What one index could not do.
//!
//! A degraded index is the ordinary case for a real repository: one unreadable
//! file, one malformed manifest, one project whose graph refused. Every one of
//! those is recorded here rather than dropped, because the alternative — an
//! answer that is quietly missing a file — is indistinguishable from a
//! repository that never had it.
//!
//! Issues sort by scope, stage, then code, so equal repositories state equal
//! issue sequences whatever order the filesystem enumerated them in.
//!
//! The summary every response carries is [`health`](super::health): a count
//! over a selection of these is a different question from what any one of them
//! records, and a different caller's.

use std::sync::Arc;

use serde::{Serialize, Serializer, ser::SerializeMap};

use super::error::{CapacityCollection, CapacityOwner, CodeIntelligenceError};
use super::serialize::serialize_token;

/// Which entity an issue is about.
///
/// The repository is a kind rather than a reserved filename. A refusal that
/// names no path is about the whole tree, and stating it as a file called
/// `<repository>` answered `"file"` to `token()` and handed `name()` a string
/// that is not and never will be a path any request can produce.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueScope {
    /// The whole repository, for a refusal that names no path of its own.
    Repository,
    /// One physical source file, by normalized repository path.
    File {
        /// The normalized repository path.
        path: Arc<str>,
    },
    /// One project, by the normalized path of the authority that selected it.
    Project {
        /// The normalized authority path.
        authority: Arc<str>,
    },
}

impl IssueScope {
    /// The path or authority this scope names, empty for the repository.
    ///
    /// The repository names nothing because there is nothing to name: it is the
    /// root every other scope is spelled relative to, and the root's own
    /// spelling differs on every machine that holds the same tree.
    pub fn name(&self) -> &str {
        match self {
            Self::Repository => "",
            Self::File { path } => path,
            Self::Project { authority } => authority,
        }
    }

    /// The stable token this scope kind is named by.
    pub fn token(&self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::File { .. } => "file",
            Self::Project { .. } => "project",
        }
    }

    /// The scope one refusal names by itself.
    ///
    /// A build knows the path it was admitting when a refusal happened and
    /// names it directly. A live update does not: the rebuild it ran covers the
    /// whole repository, so the only thing that knows which scope failed is the
    /// refusal. Everything that names no path at all — an unusable root, a
    /// repository-wide ceiling, a handle from another revision — is the
    /// repository's own.
    ///
    /// One match over the closed variant set, so a refusal added later fails to
    /// compile here rather than being filed against a scope it is not about.
    pub(crate) fn of(error: &CodeIntelligenceError) -> Self {
        use CodeIntelligenceError as Refusal;

        match error {
            Refusal::Project { authority, .. } | Refusal::Graph { authority, .. } => {
                Self::Project {
                    authority: Arc::from(&**authority),
                }
            }
            Refusal::PathEscape { path }
            | Refusal::SymlinkEscape { path, .. }
            | Refusal::PathEncoding { path }
            | Refusal::SourceEncoding { path, .. }
            | Refusal::UnknownFile { path }
            | Refusal::SourceRead { path, .. }
            | Refusal::Parser { path, .. }
            | Refusal::LanguageUnavailable { path }
            | Refusal::BrokenSpan { path }
            | Refusal::UnknownPoint { path, .. }
            | Refusal::UnenclosedPoint { path, .. } => Self::File {
                path: Arc::from(&**path),
            },
            // An unusable root names the caller's own spelling of it, which is
            // absolute; a ceiling, a stale handle, and every query refusal name
            // no path at all. All of them are about the tree as a whole.
            Refusal::InvalidRoot { .. }
            | Refusal::Capacity { .. }
            | Refusal::StaleRevision
            | Refusal::UnknownStructure
            | Refusal::UnknownProject
            | Refusal::EmptyPage
            | Refusal::CursorDrift
            | Refusal::UnavailableCoverage { .. }
            | Refusal::InvalidQuerySelection { .. } => Self::Repository,
        }
    }
}

/// The kind is written through [`token`](IssueScope::token), for the reason the
/// `serialize_token` macro beside it exists: a derived tag is a second spelling
/// of the three names the accessor already states, and the revision claim hashes
/// the accessor's. A variant renamed with only one of the two updated would send
/// one spelling and hash the other.
///
/// Written out rather than taking that macro, because this vocabulary carries
/// data. The field beside the kind is the variant's own name, not
/// [`name`](IssueScope::name), which answers what the path *is* and not what it
/// is called.
impl Serialize for IssueScope {
    fn serialize<Target: Serializer>(
        &self,
        serializer: Target,
    ) -> Result<Target::Ok, Target::Error> {
        let named = match self {
            Self::Repository => None,
            Self::File { path } => Some(("path", path)),
            Self::Project { authority } => Some(("authority", authority)),
        };
        let mut row = serializer.serialize_map(Some(1 + usize::from(named.is_some())))?;
        row.serialize_entry("kind", self.token())?;
        if let Some((field, value)) = named {
            row.serialize_entry(field, &**value)?;
        }
        row.end()
    }
}

/// Which stage of the build refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueStage {
    /// Root confinement, before anything was opened.
    Confinement,
    /// The corpus walk that discovers candidates.
    Discovery,
    /// Loading one project authority.
    Authority,
    /// Reading or decoding one source.
    Source,
    /// Recognizing one source's structures.
    Inventory,
    /// Taking one project's bounded snapshot.
    Snapshot,
    /// Resolving one project's symbols.
    Resolution,
    /// Building one project's graph.
    Graph,
}

impl IssueStage {
    /// The stable token this stage is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::Confinement => "confinement",
            Self::Discovery => "discovery",
            Self::Authority => "authority",
            Self::Source => "source",
            Self::Inventory => "inventory",
            Self::Snapshot => "snapshot",
            Self::Resolution => "resolution",
            Self::Graph => "graph",
        }
    }

    /// Which stage one refusal happened at.
    ///
    /// One match over the closed variant set, so a refusal added later fails to
    /// compile here rather than reaching the state claim under a stage that
    /// means something else.
    pub(crate) fn of(error: &CodeIntelligenceError) -> Self {
        use CodeIntelligenceError as Refusal;

        match error {
            Refusal::InvalidRoot { .. }
            | Refusal::SymlinkEscape { .. }
            | Refusal::PathEscape { .. }
            | Refusal::PathEncoding { .. } => Self::Confinement,
            Refusal::Parser { .. }
            | Refusal::LanguageUnavailable { .. }
            | Refusal::BrokenSpan { .. } => Self::Inventory,
            Refusal::Project { stage, .. } => *stage,
            Refusal::Graph { .. } => Self::Graph,
            Refusal::Capacity {
                owner: CapacityOwner::Syntax,
                ..
            } => Self::Inventory,
            Refusal::Capacity {
                owner: CapacityOwner::Rust | CapacityOwner::Go,
                ..
            } => Self::Resolution,
            Refusal::Capacity {
                owner: CapacityOwner::GraphBuild | CapacityOwner::GraphAnalysis,
                ..
            } => Self::Graph,
            Refusal::Capacity {
                owner: CapacityOwner::Repository,
                collection,
                ..
            } => Self::of_collection(*collection),
            Refusal::SourceRead { .. } | Refusal::SourceEncoding { .. } => Self::Source,
            // Every refusal a query states, and none a build records. The
            // stage they answer is the one a build would have been in when it
            // read the record the query could not answer from.
            Refusal::UnknownFile { .. }
            | Refusal::UnknownStructure
            | Refusal::UnknownProject
            | Refusal::UnknownPoint { .. }
            | Refusal::UnenclosedPoint { .. }
            | Refusal::StaleRevision
            | Refusal::EmptyPage
            | Refusal::CursorDrift
            | Refusal::UnavailableCoverage { .. }
            | Refusal::InvalidQuerySelection { .. } => Self::Source,
        }
    }

    /// The stage one repository ceiling refused at.
    ///
    /// The repository owns a ceiling in every stage of the build, so its owner
    /// alone does not name one: a graph-node allowance and a directory-entry
    /// allowance are the same owner and opposite stages. The collection is what
    /// separates them, and it is also what keeps one overrun from being filed
    /// under two stages depending on which owner won the clamp.
    fn of_collection(collection: CapacityCollection) -> Self {
        match collection {
            CapacityCollection::DirectoryEntry | CapacityCollection::Authority => Self::Discovery,
            CapacityCollection::File
            | CapacityCollection::FileBytes
            | CapacityCollection::TotalBytes => Self::Source,
            CapacityCollection::Structure | CapacityCollection::SyntaxDepth => Self::Inventory,
            CapacityCollection::Slice => Self::Resolution,
            CapacityCollection::GraphNode
            | CapacityCollection::GraphReference
            | CapacityCollection::GraphEdge => Self::Graph,
            // The repository owns no ceiling on these: each belongs to a
            // language or graph owner, whose own arm above answered before this
            // table was reached. Named rather than left to a catch-all so a
            // collection the repository gains has to be placed here by hand.
            CapacityCollection::Manifest
            | CapacityCollection::Unit
            | CapacityCollection::ModuleDepth
            | CapacityCollection::ModuleInstance
            | CapacityCollection::DependencyDepth
            | CapacityCollection::Fact => Self::Snapshot,
            CapacityCollection::Candidate
            | CapacityCollection::InterfaceComparison
            | CapacityCollection::Definition
            | CapacityCollection::Reference
            | CapacityCollection::ResolutionRecord => Self::Resolution,
            CapacityCollection::PageItem
            | CapacityCollection::TraversalDepth
            | CapacityCollection::BetweennessWork => Self::Graph,
        }
    }
}

serialize_token!(IssueStage);

/// The stable machine-readable reason an issue was recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueCode {
    /// A path resolved outside the canonical root.
    SymlinkEscape,
    /// A path is not the normalized, repository-relative spelling.
    ///
    /// Its own code rather than [`SymlinkEscape`](Self::SymlinkEscape). A
    /// malformed caller path and a path that resolved outside the root are
    /// opposite facts — one never reached the filesystem, the other did — and
    /// an operator told the second about the first goes looking for a link that
    /// is not there.
    PathEscape,
    /// A path beneath the root has no UTF-8 spelling.
    PathEncoding,
    /// A source could not be read.
    SourceUnreadable,
    /// A source's bytes are not valid UTF-8.
    SourceEncoding,
    /// A source states no complete structure inventory.
    InventoryIncomplete,
    /// This build links no owner for the source's language.
    LanguageUnavailable,
    /// A project authority did not load.
    AuthorityUnreadable,
    /// A project's snapshot refused.
    SnapshotRefused,
    /// A project's resolution refused.
    ResolutionRefused,
    /// A project's graph did not build.
    GraphRefused,
    /// A configured ceiling refused before the first excess record.
    CapacityRefused,
}

impl IssueCode {
    /// The stable token this code is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::SymlinkEscape => "symlink_escape",
            Self::PathEscape => "path_escape",
            Self::PathEncoding => "path_encoding",
            Self::SourceUnreadable => "source_unreadable",
            Self::SourceEncoding => "source_encoding",
            Self::InventoryIncomplete => "inventory_incomplete",
            Self::LanguageUnavailable => "language_unavailable",
            Self::AuthorityUnreadable => "authority_unreadable",
            Self::SnapshotRefused => "snapshot_refused",
            Self::ResolutionRefused => "resolution_refused",
            Self::GraphRefused => "graph_refused",
            Self::CapacityRefused => "capacity_refused",
        }
    }

    /// The stable code one refusal is recorded under.
    ///
    /// One match over the closed variant set, so a refusal added later fails to
    /// compile here rather than reaching an operator's filter under a code that
    /// means something else.
    pub(crate) fn of(error: &CodeIntelligenceError) -> Self {
        use CodeIntelligenceError as Refusal;

        match error {
            Refusal::SymlinkEscape { .. } => Self::SymlinkEscape,
            Refusal::PathEscape { .. } => Self::PathEscape,
            Refusal::PathEncoding { .. } => Self::PathEncoding,
            Refusal::SourceEncoding { .. } => Self::SourceEncoding,
            // A broken span is an incomplete inventory found one seam later. It
            // gets no code of its own, because no build produces it and a code
            // an operator can never observe is the defect above, restated.
            Refusal::Parser { .. } | Refusal::BrokenSpan { .. } => Self::InventoryIncomplete,
            Refusal::LanguageUnavailable { .. } => Self::LanguageUnavailable,
            Refusal::Capacity { .. } => Self::CapacityRefused,
            Refusal::Project { stage, .. } => Self::of_stage(*stage),
            Refusal::Graph { .. } => Self::GraphRefused,
            // A root that would not open, a source that would not read, and
            // every query refusal over a record this index does not hold: each
            // is one thing that could not be read, which is what the code says.
            Refusal::InvalidRoot { .. }
            | Refusal::SourceRead { .. }
            | Refusal::UnknownFile { .. }
            | Refusal::UnknownStructure
            | Refusal::UnknownProject
            | Refusal::UnknownPoint { .. }
            | Refusal::UnenclosedPoint { .. }
            | Refusal::StaleRevision
            | Refusal::EmptyPage
            | Refusal::CursorDrift
            | Refusal::UnavailableCoverage { .. }
            | Refusal::InvalidQuerySelection { .. } => Self::SourceUnreadable,
        }
    }

    /// The code one project refusal's own stage is recorded under.
    ///
    /// A stage that names no later phase is recorded against the authority,
    /// which is the one thing every project refusal has in common: it is what
    /// selected the project that then failed.
    ///
    /// Reachable by every slice producer, because this is the whole pairing:
    /// a producer that named a code beside its stage could give one stage two
    /// codes in two files, and a reader has no way to tell which is the claim.
    pub(super) fn of_stage(stage: IssueStage) -> Self {
        match stage {
            IssueStage::Snapshot => Self::SnapshotRefused,
            IssueStage::Resolution => Self::ResolutionRefused,
            IssueStage::Graph => Self::GraphRefused,
            // Every stage that runs before a project has a snapshot, and the
            // two per-source stages a project refusal can also be raised at.
            // Named rather than left to a catch-all, for the reason the three
            // classifiers above name theirs: a stage added later must be placed
            // here by hand rather than filed against the authority by default.
            IssueStage::Confinement
            | IssueStage::Discovery
            | IssueStage::Authority
            | IssueStage::Source
            | IssueStage::Inventory => Self::AuthorityUnreadable,
        }
    }
}

serialize_token!(IssueCode);

/// One thing this index could not do, and whether it is still true.
///
/// The ordering is the claim ordering: scope, then stage, then code. Two
/// repositories that state the same issues state them in the same sequence, so
/// the state revision over them is the same too.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct IndexIssue {
    scope: IssueScope,
    stage: IssueStage,
    code: IssueCode,
    message: Arc<str>,
    stale: bool,
}

impl IndexIssue {
    /// Record one refusal against the scope it happened to.
    ///
    /// `stale` is false here: an initial build records what it found, and only
    /// a live update that kept a previous good answer marks its issue stale.
    pub(crate) fn recorded(
        scope: IssueScope,
        stage: IssueStage,
        code: IssueCode,
        message: Arc<str>,
    ) -> Self {
        Self {
            scope,
            stage,
            code,
            message,
            stale: false,
        }
    }

    /// Record one refusal, classified by the refusal itself.
    ///
    /// The scope stays the caller's: a build knows which path it was admitting,
    /// and that is more exact than what the refusal carries. The stage, the
    /// code, and the message are the refusal's own, so one classification table
    /// answers for every route that records one.
    pub(crate) fn classified(scope: IssueScope, error: &CodeIntelligenceError) -> Self {
        Self::recorded(
            scope,
            IssueStage::of(error),
            IssueCode::of(error),
            Arc::from(error.to_string()),
        )
    }

    /// The same classification, for a live update that kept an older answer.
    pub(crate) fn stalled(error: &CodeIntelligenceError) -> Self {
        Self {
            stale: true,
            ..Self::classified(IssueScope::of(error), error)
        }
    }

    /// This issue, now qualifying an answer older than the tree it describes.
    pub(crate) fn now_stale(&self) -> Self {
        Self {
            stale: true,
            ..self.clone()
        }
    }

    /// Which entity this issue is about.
    pub fn scope(&self) -> &IssueScope {
        &self.scope
    }

    /// Which stage refused.
    pub fn stage(&self) -> IssueStage {
        self.stage
    }

    /// The stable reason code.
    pub fn code(&self) -> IssueCode {
        self.code
    }

    /// The refusal the failing owner stated.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether this scope is still carrying an older good answer.
    pub fn stale(&self) -> bool {
        self.stale
    }
}
