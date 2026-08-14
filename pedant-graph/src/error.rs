//! Why a graph build refused.
//!
//! Every variant names the exact join or ceiling that failed. No refusal
//! returns a partial graph, none panics, and none exposes the snapshot identity
//! bytes it compared.

use crate::limits::GraphCollection;

/// A refusal taken while projecting one resolution into a graph.
#[derive(Debug, thiserror::Error)]
pub enum GraphBuildError {
    /// The supplied snapshot and resolution were requested for other targets.
    #[error("the snapshot and the resolution describe different root targets")]
    RootTargetMismatch,
    /// The supplied snapshot is not the one the resolution was validated
    /// against, even though both name the same root target.
    #[error("the snapshot is not the one this resolution was validated against")]
    SnapshotFingerprintMismatch,
    /// A report unit has no graph container, or no source scope beneath one.
    #[error("unit {unit} has no binding in this resolution")]
    MissingUnitBinding {
        /// The report-local unit identifier that no binding answers for.
        unit: u32,
    },
    /// A report unit is bound to a build unit the supplied snapshot does not
    /// hold, which is a binding that names nothing rather than a missing one.
    #[error("unit {unit} is bound to a build unit this snapshot does not hold")]
    DanglingUnitBinding {
        /// The report-local unit identifier whose binding names nothing.
        unit: u32,
    },
    /// Two report units are bound to one build unit, so one unit-qualified
    /// source would have two owners.
    #[error("report units {held} and {unit} are bound to one build unit")]
    SharedUnitBinding {
        /// The report-local unit identifier that bound the build unit first.
        held: u32,
        /// The report-local unit identifier that bound it again.
        unit: u32,
    },
    /// A snapshot dependency edge names a build unit with no graph container.
    #[error(
        "dependency edge {edge} ({alias}) names a build unit this graph holds no container for"
    )]
    MissingDependencyUnit {
        /// The edge's position among the snapshot's dependency edges.
        edge: u32,
        /// The namespace-local name that edge declares its target under.
        alias: Box<str>,
    },
    /// A stated site names a source the bound unit does not instantiate.
    #[error("unit {unit} instantiates no source at {path}")]
    MissingSourceNode {
        /// The report-local unit identifier the site belongs to.
        unit: u32,
        /// The normalized repository-relative path the site named.
        path: Box<str>,
    },
    /// One report unit instantiates one normalized path twice, so a second file
    /// node would be minted for a source that already holds one.
    #[error("unit {unit} instantiates the source at {path} more than once")]
    RepeatedUnitSource {
        /// The report-local unit identifier that instantiates it twice.
        unit: u32,
        /// The normalized repository-relative path stated more than once.
        path: Box<str>,
    },
    /// The report states a different number of references and resolution
    /// records, so no pairing between them is stated at all.
    #[error("the report states {references} references and {records} resolution records")]
    ReferenceRecordMismatch {
        /// How many references the report states.
        references: u32,
        /// How many resolution records the report states.
        records: u32,
    },
    /// A stated join names a definition this graph holds no node for.
    #[error("definition {definition} has no node in this graph")]
    MissingDefinitionNode {
        /// The report-local definition identifier that named nothing.
        definition: u32,
    },
    /// An edge was produced for a reference record this graph does not hold.
    #[error("reference {reference} has no record in this graph")]
    MissingReferenceRecord {
        /// The reference identity that answers for no record.
        reference: u32,
    },
    /// A containment edge names a node this graph holds no record for.
    #[error("containment names node {node}, which this graph holds no record for")]
    UnknownContainmentNode {
        /// The node identity the containment relation named.
        node: u32,
    },
    /// One node is contained by more than one parent.
    #[error("node {child} is contained by more than one parent, including {parent}")]
    MultiplyContained {
        /// One parent the child is contained by.
        parent: u32,
        /// The multiply-contained child.
        child: u32,
    },
    /// One node below the unit roots is contained by nothing.
    #[error("node {node} is contained by no parent and is not a unit root")]
    UnparentedNode {
        /// The node no containment edge claims.
        node: u32,
    },
    /// One unit root is contained by another node.
    #[error("unit root {root} is contained by node {parent}")]
    RootHasParent {
        /// The unit root that must own itself.
        root: u32,
        /// The node that claims it.
        parent: u32,
    },
    /// One containment chain returns to a node it already visited.
    #[error("node {node} contains itself through its own ancestors")]
    ContainmentCycle {
        /// The node the chain returned to.
        node: u32,
    },
    /// One collection reached its configured ceiling.
    #[error("the {collection} collection cannot exceed {limit} entries")]
    CapacityExceeded {
        /// Which collection refused the insertion.
        collection: GraphCollection,
        /// The ceiling that collection is bounded by.
        limit: u32,
    },
}
