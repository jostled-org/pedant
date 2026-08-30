//! Go module project authority, and the bounded package snapshots taken from
//! it: the main module, the local replacements it requires, every directive its
//! root manifest states, and every source those modules' packages hold.
//!
//! The loader reads `go.mod` files beneath one canonical repository root, and a
//! snapshot reads the `.go` sources its package walk admits. Neither invokes
//! the Go command, a compiler, a code generator, a language server, or a
//! network client, and neither consults a toolchain environment, module cache,
//! workspace file, or host selection state. The root manifest is the sole
//! `replace` and `exclude` authority, matching a single-main-module build, and
//! a build predicate is retained unevaluated rather than resolved against the
//! machine taking the snapshot.

mod binding_fact;
mod condition;
mod declaration_fact;
mod directive;
mod discovery;
mod error;
mod exclusion;
mod facts;
mod fault;
mod fingerprint;
mod identity;
mod import_fact;
mod inventory;
mod limits;
mod load;
mod manifest;
mod module;
mod packages;
mod paths;
mod project;
mod provider;
mod reference_fact;
mod replacement;
mod requirement;
mod resolve;
mod signature_fact;
mod snapshot;
mod snapshot_error;
mod snapshot_module;
mod source;
mod store;
mod unit;
mod unit_table;
mod written_type_fact;

/// Proof-only restatement of the snapshot claims a fingerprint covers.
#[cfg(feature = "resolution-test-support")]
mod test_support;

pub use binding_fact::{GoBindingRecord, GoInitializerRecord};
pub use condition::GoBuildCondition;
pub use declaration_fact::GoDeclarationRecord;
pub use error::GoProjectError;
pub use exclusion::GoExclusion;
pub use facts::GoSourceFacts;
pub use fault::GoSourceFault;
pub use fingerprint::GoSnapshotFingerprint;
pub use identity::GoModuleId;
pub use import_fact::GoImportRecord;
pub use inventory::GoFileInventory;
pub use limits::GoResolutionLimits;
pub use module::GoModule;
pub use project::GoProject;
pub use provider::{GoSourceProvider, GoSourceRules};
pub use reference_fact::GoReferenceRecord;
pub use replacement::{GoReplacement, GoReplacementTarget};
pub use requirement::{GoRequirement, GoRequirementResolution};
pub use resolve::{GoProjectResolution, GoResolutionError, GoResolver, GoUnitBinding};
pub use signature_fact::GoSignatureTermRecord;
pub use snapshot::GoResolutionSnapshot;
pub use snapshot_error::{GoSnapshotError, GoSourceDefect};
pub use snapshot_module::{GoSnapshotEdge, GoSnapshotModule, GoSnapshotModuleId};
pub use source::GoSource;
pub use unit::{GoPackageContext, GoResolutionUnit, GoSnapshotUnitId};
pub use written_type_fact::GoWrittenTypeRecord;

/// The closed grammar vocabulary a retained Go fact inventory speaks.
///
/// Re-exported rather than restated: `pedant-syntax` owns the one Go grammar
/// mapping, so a consumer of this crate names the same kinds the extraction
/// produced instead of a copy that could drift from them.
pub use pedant_syntax::go::{
    GoBindingKind, GoBuildConditionKind, GoDeclarationKind, GoFactSpan, GoImportForm,
    GoInitializerForm, GoReferenceKind, GoScopeFact, GoScopeKind, GoSignatureRole,
};

#[cfg(feature = "resolution-test-support")]
pub use test_support::{
    GoEdgeFingerprintClaim, GoModuleFingerprintClaim, GoSnapshotFingerprintClaim,
    GoSourceFingerprintClaim, GoUnitFingerprintClaim,
};
