//! Why a Cargo-project gate run refused.
//!
//! Every variant names the project root or the root target it failed for, so a
//! buffered run that discards its verdicts still tells the operator which
//! target could not be judged. No variant carries a partial result.

use pedant_core::check_config::ConfigError;
use pedant_core::resolution::rust::{RustProjectError, RustResolutionError, RustSnapshotError};
use pedant_graph::{GraphAnalysisError, GraphBuildError};

use super::evidence::EvidenceError;

/// A refusal taken anywhere on the project gate path.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProjectGateError {
    /// The stated project root could not be canonicalized.
    #[error("project root {root} cannot be resolved: {source}")]
    ProjectRoot {
        /// The root exactly as the caller wrote it.
        root: Box<str>,
        /// What the filesystem reported.
        #[source]
        source: std::io::Error,
    },
    /// A selected configuration source could not be read or parsed.
    #[error("config file {path} cannot be used: {source}")]
    Config {
        /// The configuration path that was selected.
        path: Box<str>,
        /// Why it could not be used.
        #[source]
        source: ConfigError,
    },
    /// The project beneath the canonical root could not be indexed.
    #[error("project {root} cannot be loaded: {source}")]
    ProjectLoad {
        /// The canonical project root.
        root: Box<str>,
        /// Why loading refused.
        #[source]
        source: RustProjectError,
    },
    /// A declared target names a package the loaded project does not hold.
    ///
    /// Defensive: the project authority mints both records, so a miss is a
    /// broken invariant rather than an operator error. It is a refusal and not
    /// a skip, because silently dropping the target would report a narrower
    /// judgment as a complete one.
    #[error("target {target} names a package the project does not declare")]
    UnknownPackage {
        /// The target name exactly as the project declared it.
        target: Box<str>,
    },
    /// No workspace member declares a library, binary, or build-script target.
    #[error("project {root} declares no library, binary, or build-script target")]
    NoPrimaryTarget {
        /// The canonical project root.
        root: Box<str>,
    },
    /// One selected target's source closure could not be taken.
    #[error("target {target} cannot be snapshotted: {source}")]
    Snapshot {
        /// The root-target label.
        target: Box<str>,
        /// Why the snapshot refused.
        #[source]
        source: RustSnapshotError,
    },
    /// One selected target's names could not be resolved.
    #[error("target {target} cannot be resolved: {source}")]
    Resolution {
        /// The root-target label.
        target: Box<str>,
        /// Why resolution refused.
        #[source]
        source: RustResolutionError,
    },
    /// One selected target's resolution could not be projected into a graph.
    #[error("target {target} cannot be projected into a graph: {source}")]
    GraphBuild {
        /// The root-target label.
        target: Box<str>,
        /// Why the build refused.
        #[source]
        source: GraphBuildError,
    },
    /// One selected target's graph could not be analyzed under the ceilings.
    #[error("target {target} cannot be analyzed: {source}")]
    Analysis {
        /// The root-target label.
        target: Box<str>,
        /// Why the analysis refused.
        #[source]
        source: GraphAnalysisError,
    },
    /// One selected target's topology did not project into neutral evidence.
    #[error("target {target} produced unusable structural evidence: {source}")]
    Evidence {
        /// The root-target label.
        target: Box<str>,
        /// Why the projection refused.
        #[source]
        source: EvidenceError,
    },
    /// An explicit semantic request could not load a verified context.
    #[error("project {root} has no loadable semantic context for --semantic")]
    SemanticContext {
        /// The canonical project root.
        root: Box<str>,
    },
}
