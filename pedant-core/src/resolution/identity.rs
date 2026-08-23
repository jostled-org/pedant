//! The scoping and indexing shared by every language's opaque identities.
//!
//! An identity issued by one project must never select a record in another
//! project that happens to share a local index, and every language model needs
//! that guarantee in the same shape. One owner, because a second language
//! cannot answer the question differently.
//!
//! The identity type itself is stated once too, as a macro rather than as a
//! generic. Each language publishes its own named type — a caller must not be
//! able to hand a module identity to a package lookup — and a shared generic
//! would either publish one type parameterised by a marker or make every
//! identity the same type. The macro emits the named type and keeps the one
//! body: the same fields, the same three accessors, and the same redacted
//! rendering.

/// The root fingerprint and manifest revision that scope every issued identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProjectAuthority {
    root: [u8; 32],
    revision: [u8; 32],
}

impl ProjectAuthority {
    /// Bind a canonical-root fingerprint to a manifest revision.
    pub(crate) fn new(root: [u8; 32], revision: [u8; 32]) -> Self {
        Self { root, revision }
    }

    /// Whether both authorities describe the same canonical repository root.
    pub(crate) fn same_root(&self, other: &Self) -> bool {
        self.root == other.root
    }

    /// Whether both authorities describe the same manifest revision.
    pub(crate) fn same_revision(&self, other: &Self) -> bool {
        self.revision == other.revision
    }
}

/// The slice position one stored index names.
///
/// Every index this crate stores is a `u32`, and every slice it reads is
/// addressed by `usize`. On a target where `usize` is narrower than `u32` the
/// saturating answer selects no element, which each caller already treats as
/// absence.
pub(crate) fn index_of(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// The stored index one slice position is recorded as.
///
/// The saturating answer names no record, which each caller reports rather
/// than resolves.
pub(crate) fn position(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Declare one project-scoped opaque identity.
///
/// The expansion states the two scoping fields, the issuing constructor, the
/// two views a lookup reads, and a `Debug` that prints the local index alone —
/// the scoping fingerprints are provenance, not something a rendered identity
/// should carry into a log.
macro_rules! scoped_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name {
            authority: $crate::resolution::identity::ProjectAuthority,
            index: u32,
        }

        impl $name {
            /// Issue an identity for the record at `index`.
            pub(super) fn new(
                authority: $crate::resolution::identity::ProjectAuthority,
                index: u32,
            ) -> Self {
                Self { authority, index }
            }

            /// The issuing project's authority.
            pub(super) fn authority(&self) -> $crate::resolution::identity::ProjectAuthority {
                self.authority
            }

            /// The project-local index this identity selects.
            pub(super) fn index(&self) -> u32 {
                self.index
            }
        }

        impl ::std::fmt::Debug for $name {
            /// Render the identity without exposing its scoping fingerprints.
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::write!(
                    formatter,
                    ::std::concat!(::std::stringify!($name), "({})"),
                    self.index
                )
            }
        }
    };
}

pub(crate) use scoped_id;
