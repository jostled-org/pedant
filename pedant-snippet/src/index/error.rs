//! Why a code-intelligence build or query states no answer.

use std::fmt;

use super::serialize::serialize_token;

/// The named owner a capacity refusal came from.
///
/// Closed, and lower-snake-case on the wire, because a refusal is read by an
/// operator deciding which ceiling to raise: an owner it could not name would
/// leave every ceiling equally suspect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapacityOwner {
    /// The repository-wide ceilings the index itself owns.
    Repository,
    /// The bounded syntax structure inventory.
    Syntax,
    /// The Rust resolution owner.
    Rust,
    /// The Go resolution owner.
    Go,
    /// The graph builder.
    GraphBuild,
    /// The graph analysis view.
    GraphAnalysis,
}

impl CapacityOwner {
    /// The stable token this owner is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::Syntax => "syntax",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::GraphBuild => "graph_build",
            Self::GraphAnalysis => "graph_analysis",
        }
    }
}

serialize_token!(CapacityOwner);

/// Which bounded collection a capacity refusal addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapacityCollection {
    /// Directory entries the corpus walk visited.
    DirectoryEntry,
    /// Project authorities the discovery selected.
    Authority,
    /// Project manifests one language owner admitted.
    Manifest,
    /// Resolution units one language owner retained.
    Unit,
    /// Distinct physical source files.
    File,
    /// Bytes of one source file.
    FileBytes,
    /// Bytes of all retained source text.
    TotalBytes,
    /// Physical logical structures.
    Structure,
    /// Tree levels one structure walk may descend.
    SyntaxDepth,
    /// Rust module levels one source closure may descend.
    ModuleDepth,
    /// Rust module instances one resolution unit may retain.
    ModuleInstance,
    /// Project dependency edges one language owner may descend.
    DependencyDepth,
    /// Go grammar facts one source may retain.
    Fact,
    /// Candidate definitions one reference may retain.
    Candidate,
    /// Concrete-type-to-interface comparisons one resolution may perform.
    InterfaceComparison,
    /// Symbol definitions one resolution report may retain.
    Definition,
    /// Symbol references one resolution report may retain.
    Reference,
    /// Resolution records one report may retain.
    ResolutionRecord,
    /// Resolved project slices.
    Slice,
    /// Graph nodes across every slice.
    GraphNode,
    /// Graph reference records across every slice.
    GraphReference,
    /// Graph edges across every slice.
    GraphEdge,
    /// Items one page may carry.
    PageItem,
    /// Selected steps one traversal may walk.
    TraversalDepth,
    /// Steps betweenness centrality may cost.
    BetweennessWork,
}

impl CapacityCollection {
    /// The stable token this collection is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::DirectoryEntry => "directory_entry",
            Self::Authority => "authority",
            Self::Manifest => "manifest",
            Self::Unit => "unit",
            Self::File => "file",
            Self::FileBytes => "file_bytes",
            Self::TotalBytes => "total_bytes",
            Self::Structure => "structure",
            Self::SyntaxDepth => "syntax_depth",
            Self::ModuleDepth => "module_depth",
            Self::ModuleInstance => "module_instance",
            Self::DependencyDepth => "dependency_depth",
            Self::Fact => "fact",
            Self::Candidate => "candidate",
            Self::InterfaceComparison => "interface_comparison",
            Self::Definition => "definition",
            Self::Reference => "reference",
            Self::ResolutionRecord => "resolution_record",
            Self::Slice => "slice",
            Self::GraphNode => "graph_node",
            Self::GraphReference => "graph_reference",
            Self::GraphEdge => "graph_edge",
            Self::PageItem => "page_item",
            Self::TraversalDepth => "traversal_depth",
            Self::BetweennessWork => "betweenness_work",
        }
    }
}

serialize_token!(CapacityCollection);

/// Which of a project loader's own three source ceilings one repository refusal
/// names.
///
/// A loader's fault vocabulary has a word for these three and for nothing else
/// the repository can refuse, so a structure ceiling or a slice ceiling routed
/// to a source-file count would hand the loader a number it never crossed.
/// Everything else reaches it carrying the refusal's own sentence instead.
///
/// Classified once because both loaders ask the same question of the same
/// collection and only the answer's spelling is theirs. Two copies of the split
/// were two chances for one language to route a ceiling the other did not.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LoaderCeiling {
    /// Distinct physical source files.
    SourceFiles,
    /// Bytes of one source file.
    SourceBytes,
    /// Bytes of all retained source text.
    TotalBytes,
}

#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
impl LoaderCeiling {
    /// The loader ceiling one refused collection names, where it names one.
    ///
    /// Every other collection is named rather than left to a catch-all, for the
    /// reason [`IssueStage::of_collection`](super::issue::IssueStage) names its
    /// own: a collection this crate gains must be placed here by hand. Under a
    /// catch-all, one a loader does have a word for would fall through to the
    /// prose tail and reach that loader as an unreadable file instead of the
    /// ceiling it crossed.
    pub(crate) fn of_collection(collection: CapacityCollection) -> Option<Self> {
        match collection {
            CapacityCollection::File => Some(Self::SourceFiles),
            CapacityCollection::FileBytes => Some(Self::SourceBytes),
            CapacityCollection::TotalBytes => Some(Self::TotalBytes),
            CapacityCollection::DirectoryEntry
            | CapacityCollection::Authority
            | CapacityCollection::Manifest
            | CapacityCollection::Unit
            | CapacityCollection::Structure
            | CapacityCollection::SyntaxDepth
            | CapacityCollection::ModuleDepth
            | CapacityCollection::ModuleInstance
            | CapacityCollection::DependencyDepth
            | CapacityCollection::Fact
            | CapacityCollection::Candidate
            | CapacityCollection::InterfaceComparison
            | CapacityCollection::Definition
            | CapacityCollection::Reference
            | CapacityCollection::ResolutionRecord
            | CapacityCollection::Slice
            | CapacityCollection::GraphNode
            | CapacityCollection::GraphReference
            | CapacityCollection::GraphEdge
            | CapacityCollection::PageItem
            | CapacityCollection::TraversalDepth
            | CapacityCollection::BetweennessWork => None,
        }
    }
}

/// Why one code-intelligence operation states no answer.
///
/// Every variant is a refusal that retains nothing partial. A capacity refusal
/// carries the owner, the collection, what was observed, and the ceiling that
/// refused, so the answer to "which number do I raise" is in the error rather
/// than in a table the reader has to find.
///
/// Cloneable because the shared store retains the refusal one path produced
/// beside the text a successful one produced: every payload here is a
/// `Box<str>` or a `Copy` field, so a retained refusal costs the sentence it
/// already holds rather than a second physical read of the file it names.
#[derive(Clone, Debug, thiserror::Error)]
pub enum CodeIntelligenceError {
    /// The requested root is not a canonical, readable directory.
    #[error("{path} is not a usable repository root: {reason}")]
    InvalidRoot {
        /// The root as the caller spelled it.
        path: Box<str>,
        /// What the filesystem said about it.
        reason: Box<str>,
    },
    /// A path is not the normalized, repository-relative spelling the index
    /// stores.
    #[error("{path} is not a normalized repository-relative path")]
    PathEscape {
        /// The offending path, as the caller spelled it.
        path: Box<str>,
    },
    /// A path resolves outside the canonical root.
    ///
    /// The landing is carried but not displayed. This sentence becomes an
    /// issue message, an issue reaches the state claim, and a location outside
    /// the repository is spelled differently on every machine — so a claim that
    /// named it would give one repository two identities. A language owner
    /// whose own vocabulary names both spellings reads the field instead.
    #[error("{path} resolves outside the repository root")]
    SymlinkEscape {
        /// The offending repository path.
        path: Box<str>,
        /// Where that path landed, after every link was followed.
        landing: Box<str>,
    },
    /// A path beneath the root has no UTF-8 spelling.
    #[error("{path} beneath the repository root is not valid UTF-8")]
    PathEncoding {
        /// The offending path, rendered lossily for the message alone.
        path: Box<str>,
    },
    /// A source could not be read.
    #[error("cannot read {path}: {reason}")]
    SourceRead {
        /// The repository path that failed.
        path: Box<str>,
        /// The underlying failure.
        reason: Box<str>,
    },
    /// A source's bytes are not valid UTF-8.
    #[error("{path} is not valid UTF-8: {reason}")]
    SourceEncoding {
        /// The repository path that failed.
        path: Box<str>,
        /// The refusal the decoder stated, naming the offending byte.
        reason: Box<str>,
    },
    /// A source states no complete structure inventory.
    #[error("{path} states no complete structure inventory: {reason}")]
    Parser {
        /// The repository path that failed.
        path: Box<str>,
        /// The refusal its language owner stated.
        reason: Box<str>,
    },
    /// This build links no structure inventory for the source's language.
    ///
    /// Separate from [`Parser`](Self::Parser) on purpose. A file this build
    /// never read and a file it read and could not parse are opposite facts,
    /// and an operator told the second about the first would go looking for a
    /// malformed source that is not there.
    #[error("this build links no inventory for {path}'s language")]
    LanguageUnavailable {
        /// The repository path that was never read.
        path: Box<str>,
    },
    /// A retained structure span does not slice the source it was taken from.
    ///
    /// Separate from [`Parser`](Self::Parser), which a build raises about a
    /// source it could not read. This one is raised at query time about a
    /// source the build accepted: the span and the text came from one read of
    /// one file, so a span that misses it is a broken inventory. Separate from
    /// [`UnknownStructure`](Self::UnknownStructure) too, because a structure is
    /// indexed at the position the caller named — it cannot be read.
    #[error("{path} holds a structure span that does not slice its retained source")]
    BrokenSpan {
        /// The repository path whose inventory is broken.
        path: Box<str>,
    },
    /// One project authority did not load, snapshot, or resolve.
    ///
    /// The stage is the closed enum itself rather than its token. Carried as
    /// text it was written back out by one producer as a hand-typed literal and
    /// read back by the classifier through a parse whose failure arm answered
    /// [`IssueStage::Authority`](super::issue::IssueStage::Authority) — so a
    /// misspelling reported every project refusal at the wrong stage and
    /// nothing went red.
    #[error("project {authority} failed at {}: {reason}", stage.token())]
    Project {
        /// The authority path the project was selected by.
        authority: Box<str>,
        /// Which stage refused.
        stage: super::issue::IssueStage,
        /// The refusal that stage stated.
        reason: Box<str>,
    },
    /// One project's graph did not build.
    #[error("graph for {authority} failed: {reason}")]
    Graph {
        /// The authority path the project was selected by.
        authority: Box<str>,
        /// The refusal the graph builder stated.
        reason: Box<str>,
    },
    /// A configured ceiling refused before the first excess record.
    #[error("{owner} refused {collection}: {observed} passes the ceiling of {limit}")]
    Capacity {
        /// Which owner's ceiling refused.
        owner: CapacityOwner,
        /// Which collection it addresses.
        collection: CapacityCollection,
        /// The count that would have been retained.
        observed: u64,
        /// The ceiling that refused it.
        limit: u64,
    },
    /// A handle was issued by another or an older index revision.
    #[error("the supplied handle belongs to another index revision")]
    StaleRevision,
    /// A handle names no structure in this revision.
    #[error("no structure is indexed at the supplied position")]
    UnknownStructure,
    /// A handle names no project in this revision.
    #[error("no project is indexed at the supplied position")]
    UnknownProject,
    /// A path names no admitted source in this revision.
    #[error("{path} is not an admitted source in this index revision")]
    UnknownFile {
        /// The requested repository path.
        path: Box<str>,
    },
    /// A page of no items is a page nobody can read.
    #[error("a page carries at least one item")]
    EmptyPage,
    /// A page cursor does not continue the query it was supplied to.
    ///
    /// One refusal for every way that can be true — another index, another
    /// health, another parameter, another page size, another offset — because
    /// a cursor is one claim about all of them and continuing it under any
    /// other would present a different result set as the rest of the first.
    #[error("the supplied page cursor does not continue this query")]
    CursorDrift,
    /// The requested evidence does not exist for the named entity.
    ///
    /// Distinct from an empty answer on purpose. A repository with no Python
    /// resolver and a Python function that calls nothing produce the same empty
    /// neighborhood and opposite facts, so the absence of evidence is stated
    /// rather than rendered as evidence of absence.
    #[error("no graph evidence stands behind the requested entity: {reason}")]
    UnavailableCoverage {
        /// What evidence the entity does state.
        coverage: super::coverage::StructureCoverage,
        /// Why the requested evidence is not among it.
        reason: Box<str>,
    },
    /// A query states a selection this index does not admit.
    #[error("the query states a selection this index does not admit: {reason}")]
    InvalidQuerySelection {
        /// Which part of the selection, and what it would have taken.
        reason: Box<str>,
    },
    /// A requested point is not a position in the file.
    #[error("{path} states no position at line {line}, column {column}")]
    UnknownPoint {
        /// The requested repository path.
        path: Box<str>,
        /// The one-based line requested.
        line: u32,
        /// The one-based byte column requested, one where it was omitted.
        column: u32,
    },
    /// No indexed structure contains the requested point.
    #[error("no indexed structure contains {path} at line {line}, column {column}")]
    UnenclosedPoint {
        /// The requested repository path.
        path: Box<str>,
        /// The one-based line requested.
        line: u32,
        /// The one-based byte column requested, one where it was omitted.
        column: u32,
    },
}

/// The sentence a refusal prints names the owner its wire form sends.
///
/// Written through [`token`](CapacityOwner::token) rather than through a table
/// of its own. A refusal reaches an operator as prose and as JSON, and two
/// spellings of one owner would leave the two disagreeing about which ceiling
/// refused.
impl fmt::Display for CapacityOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// The same, for the collection a refusal addresses.
impl fmt::Display for CapacityCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// One capacity refusal, stated once so every owner spells it the same way.
pub(crate) fn capacity(
    owner: CapacityOwner,
    collection: CapacityCollection,
    observed: u64,
    limit: u64,
) -> CodeIntelligenceError {
    CodeIntelligenceError::Capacity {
        owner,
        collection,
        observed,
        limit,
    }
}

/// The first count a ceiling refuses, widened before addition.
///
/// One owner for the rule, whatever width the ceiling's own publisher used: a
/// caller holding a `u32` is widened before the addition, and a caller already
/// holding a `u64` has nothing left to widen. Saturating rather than wrapping —
/// a ceiling of `u64::MAX` admits every count, so there is no first excess to
/// name and the ceiling itself is the honest answer.
pub(crate) fn first_excess<Wide: Into<u64>>(limit: Wide) -> u64 {
    limit.into().saturating_add(1)
}
