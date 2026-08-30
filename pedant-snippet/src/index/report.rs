//! The wire shape of one refusal.
//!
//! [`CodeIntelligenceError`] is a Rust value: it carries an `std::io` cause in
//! places and a borrowed reason in others, and neither is something a client
//! reads. What a client reads is a stable code, the sentence the error already
//! states, and whichever of the seven qualifying fields this refusal has. So the
//! error is projected here rather than serialized where it is defined, and the
//! projection is the one both transports send.
//!
//! The code is written down per variant rather than derived from the variant
//! name. A refusal a client branches on is part of the contract, and a rename
//! that silently changed one would break every caller without changing a test.

use serde::Serialize;

use super::coverage::StructureCoverage;
use super::error::{CapacityCollection, CapacityOwner, CodeIntelligenceError};
use super::issue::IssueStage;

/// The stable token one refusal is branched on.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The requested root is not a canonical, readable directory.
    InvalidRoot,
    /// A path is not a normalized, repository-relative spelling.
    PathEscape,
    /// A path resolves outside the canonical root.
    SymlinkEscape,
    /// A path beneath the root has no UTF-8 spelling.
    PathEncoding,
    /// A source could not be read.
    SourceRead,
    /// A source's bytes are not valid UTF-8.
    SourceEncoding,
    /// A source states no complete structure inventory.
    Parser,
    /// This build links no structure inventory for the source's language.
    LanguageUnavailable,
    /// A retained structure span does not slice the source it was taken from.
    BrokenSpan,
    /// One project authority did not load, snapshot, or resolve.
    Project,
    /// One project's graph did not build.
    Graph,
    /// A configured ceiling refused before the first excess record.
    Capacity,
    /// A handle was issued by another or an older index revision.
    StaleRevision,
    /// A handle names no structure in this revision.
    UnknownStructure,
    /// A handle names no project in this revision.
    UnknownProject,
    /// A path names no admitted source in this revision.
    UnknownFile,
    /// A page of no items is a page nobody can read.
    EmptyPage,
    /// A page cursor does not continue the query it was supplied to.
    CursorDrift,
    /// The requested evidence does not exist for the named entity.
    UnavailableCoverage,
    /// A query states a selection this index does not admit.
    InvalidQuerySelection,
    /// A requested point is not a position in the file.
    UnknownPoint,
    /// No indexed structure contains the requested point.
    UnenclosedPoint,
}

/// One refusal, as a client reads it.
///
/// Every qualifying field is omitted where the refusal does not state it, so a
/// capacity refusal carries its four numbers and a stale handle carries none.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ErrorReport {
    code: ErrorCode,
    message: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<Box<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<Box<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<IssueStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    coverage: Option<StructureCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<CapacityOwner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    collection: Option<CapacityCollection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,
}

/// The four numbers a capacity refusal states, and nothing else states.
///
/// One value rather than four parameters: they are supplied together or not at
/// all, and a constructor taking four `Option`s would let three of them be set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Overrun {
    owner: CapacityOwner,
    collection: CapacityCollection,
    observed: u64,
    limit: u64,
}

impl ErrorReport {
    /// Project one refusal into the shape both transports send.
    pub fn of(error: &CodeIntelligenceError) -> Self {
        let message = error.to_string().into_boxed_str();
        let stated = Classified::of(error);
        let overrun = stated.overrun;
        Self {
            code: stated.code,
            message,
            path: stated.path.map(Box::from),
            project: stated.project.map(Box::from),
            stage: stated.stage,
            coverage: stated.coverage,
            owner: overrun.map(|overrun| overrun.owner),
            collection: overrun.map(|overrun| overrun.collection),
            observed: overrun.map(|overrun| overrun.observed),
            limit: overrun.map(|overrun| overrun.limit),
        }
    }

    /// The stable token this refusal is branched on.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// The sentence the error states.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The repository path this refusal is about, where it names one.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// The project authority this refusal is about, where it names one.
    pub fn project(&self) -> Option<&str> {
        self.project.as_deref()
    }

    /// Which stage of the build refused, for a project refusal.
    ///
    /// The field that separates "the authority did not load" from "the graph
    /// did not build". Both arrive under one code carrying one authority path,
    /// and a client left to tell them apart would be reading the prose — the
    /// exact failure [`coverage`](Self::coverage) exists to prevent one variant
    /// down.
    pub fn stage(&self) -> Option<IssueStage> {
        self.stage
    }

    /// What evidence the entity does state, for an unavailable-coverage
    /// refusal.
    ///
    /// The one field that separates "this build has no resolver for the
    /// language" from "a graph exists and this declaration is not in it". Both
    /// arrive under one code, and a client left to branch on the prose reason
    /// would be branching on a sentence nobody promised to keep.
    pub fn coverage(&self) -> Option<StructureCoverage> {
        self.coverage
    }

    /// Which owner's ceiling refused, for a capacity refusal.
    pub fn owner(&self) -> Option<CapacityOwner> {
        self.owner
    }

    /// Which bounded collection it addresses, for a capacity refusal.
    pub fn collection(&self) -> Option<CapacityCollection> {
        self.collection
    }

    /// The count that would have been retained, for a capacity refusal.
    pub fn observed(&self) -> Option<u64> {
        self.observed
    }

    /// The ceiling that refused it, for a capacity refusal.
    pub fn limit(&self) -> Option<u64> {
        self.limit
    }
}

/// One fatal refusal, in the shape a build that produced no state sends.
///
/// No revisions and no health, because there is no state to take them from: a
/// build that refused published nothing to answer about.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct FatalReport {
    error: ErrorReport,
}

impl FatalReport {
    /// The report one fatal refusal sends.
    pub fn of(error: &CodeIntelligenceError) -> Self {
        Self {
            error: ErrorReport::of(error),
        }
    }

    /// The refusal it carries.
    pub fn error(&self) -> &ErrorReport {
        &self.error
    }
}

/// The code, the path, the project, the coverage, and the overrun one refusal
/// states, borrowed from the error itself.
///
/// The projection reads five things from one refusal and at most two of them
/// are ever set together. Named here rather than returned as a five-place tuple
/// so each is read by name, and so the four ways a refusal qualifies itself are
/// four constructors rather than four positions a caller counts.
struct Classified<'error> {
    code: ErrorCode,
    path: Option<&'error str>,
    project: Option<&'error str>,
    stage: Option<IssueStage>,
    coverage: Option<StructureCoverage>,
    overrun: Option<Overrun>,
}

impl<'error> Classified<'error> {
    /// A refusal that states its code and nothing else.
    fn bare(code: ErrorCode) -> Self {
        Self {
            code,
            path: None,
            project: None,
            stage: None,
            coverage: None,
            overrun: None,
        }
    }

    /// A refusal about one repository path.
    fn at(code: ErrorCode, path: &'error str) -> Self {
        Self {
            path: Some(path),
            ..Self::bare(code)
        }
    }

    /// A refusal about one project authority, at the stage that refused.
    fn under(code: ErrorCode, authority: &'error str, stage: IssueStage) -> Self {
        Self {
            project: Some(authority),
            stage: Some(stage),
            ..Self::bare(code)
        }
    }

    /// A refusal that states what evidence the entity does have.
    fn covering(code: ErrorCode, coverage: StructureCoverage) -> Self {
        Self {
            coverage: Some(coverage),
            ..Self::bare(code)
        }
    }

    /// A refusal that states which ceiling refused, and by how much.
    fn over(overrun: Overrun) -> Self {
        Self {
            overrun: Some(overrun),
            ..Self::bare(ErrorCode::Capacity)
        }
    }

    /// Everything the projection reads from one refusal.
    ///
    /// One match over the closed variant set, so a variant added later fails to
    /// compile here rather than reaching a client under a code that means
    /// something else.
    fn of(error: &'error CodeIntelligenceError) -> Self {
        use CodeIntelligenceError as Refusal;

        match error {
            Refusal::InvalidRoot { path, .. } => Self::at(ErrorCode::InvalidRoot, path),
            Refusal::PathEscape { path } => Self::at(ErrorCode::PathEscape, path),
            Refusal::SymlinkEscape { path, .. } => Self::at(ErrorCode::SymlinkEscape, path),
            Refusal::PathEncoding { path } => Self::at(ErrorCode::PathEncoding, path),
            Refusal::SourceRead { path, .. } => Self::at(ErrorCode::SourceRead, path),
            Refusal::SourceEncoding { path, .. } => Self::at(ErrorCode::SourceEncoding, path),
            Refusal::Parser { path, .. } => Self::at(ErrorCode::Parser, path),
            Refusal::LanguageUnavailable { path } => Self::at(ErrorCode::LanguageUnavailable, path),
            Refusal::BrokenSpan { path } => Self::at(ErrorCode::BrokenSpan, path),
            Refusal::UnknownFile { path } => Self::at(ErrorCode::UnknownFile, path),
            Refusal::UnknownPoint { path, .. } => Self::at(ErrorCode::UnknownPoint, path),
            Refusal::UnenclosedPoint { path, .. } => Self::at(ErrorCode::UnenclosedPoint, path),
            Refusal::Project { authority, .. } => {
                Self::under(ErrorCode::Project, authority, IssueStage::of(error))
            }
            Refusal::Graph { authority, .. } => {
                Self::under(ErrorCode::Graph, authority, IssueStage::of(error))
            }
            Refusal::UnavailableCoverage { coverage, .. } => {
                Self::covering(ErrorCode::UnavailableCoverage, *coverage)
            }
            Refusal::Capacity {
                owner,
                collection,
                observed,
                limit,
            } => Self::over(Overrun {
                owner: *owner,
                collection: *collection,
                observed: *observed,
                limit: *limit,
            }),
            Refusal::StaleRevision => Self::bare(ErrorCode::StaleRevision),
            Refusal::UnknownStructure => Self::bare(ErrorCode::UnknownStructure),
            Refusal::UnknownProject => Self::bare(ErrorCode::UnknownProject),
            Refusal::EmptyPage => Self::bare(ErrorCode::EmptyPage),
            Refusal::CursorDrift => Self::bare(ErrorCode::CursorDrift),
            Refusal::InvalidQuerySelection { .. } => Self::bare(ErrorCode::InvalidQuerySelection),
        }
    }
}
