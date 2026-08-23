//! Opaque, project-scoped Go module identities.
//!
//! An identity carries the canonical-root fingerprint and the manifest revision
//! of the project that issued it, so an identity from one project can never
//! select a record in another project that happens to share a local index. It
//! is minted from the one shared declaration, so this language cannot answer
//! the scoping question differently from the other.

use crate::resolution::identity::scoped_id;

pub(super) use crate::resolution::identity::{ProjectAuthority, index_of, position};

scoped_id!(
    GoModuleId,
    "Opaque identity of a Go module inside one loaded project."
);
