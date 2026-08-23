//! Opaque, project-scoped identities.
//!
//! Every identity carries the canonical-root fingerprint and the manifest
//! revision of the project that issued it, so an identity from one project can
//! never select a record in another project that happens to share a local
//! index. Both are minted from the one shared declaration, so the two cannot
//! answer the scoping question differently.

use crate::resolution::identity::scoped_id;

pub(super) use crate::resolution::identity::{ProjectAuthority, index_of, position};

scoped_id!(
    PackageId,
    "Opaque identity of a Cargo package inside one loaded project."
);

scoped_id!(
    TargetId,
    "Opaque identity of a Cargo target inside one loaded project."
);
