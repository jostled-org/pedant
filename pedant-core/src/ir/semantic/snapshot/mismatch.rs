//! Typed reasons a semantic database may refuse a snapshot.

#[derive(Debug, thiserror::Error)]
pub(crate) enum SemanticSnapshotMismatch {
    #[error("the semantic database was loaded at another repository root: {loaded}")]
    Root { loaded: Box<str> },
    #[error("the resolution snapshot claim is malformed: {detail}")]
    MalformedClaim { detail: Box<str> },
    #[error("the semantic database holds no crate for the requested target {name}")]
    RequestedTarget { name: Box<str> },
    #[error("the semantic database's unit graph differs from the snapshot: {detail}")]
    UnitGraph { detail: Box<str> },
    #[error("the semantic database does not activate {name}")]
    Activation { name: Box<str> },
    #[error("unit {name} holds a different source set in the semantic database: {detail}")]
    PathSet { name: Box<str>, detail: Box<str> },
    #[error("{path} is not a source of the semantic database")]
    SourceAbsent { path: Box<str> },
    #[error("{path} could not be read from the semantic database")]
    SourceUnreadable { path: Box<str> },
    #[error("{path} holds different bytes in the semantic database")]
    SourceDigest { path: Box<str> },
    #[error("{path} could not be analyzed by the semantic database")]
    SourceAnalysis { path: Box<str> },
    #[error("{path} could not be addressed in the snapshot's coordinates")]
    SourceCoordinates { path: Box<str> },
}
