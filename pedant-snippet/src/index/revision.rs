//! The two identities every answer carries.
//!
//! [`IndexRevision`] identifies what the index holds. [`StateRevision`]
//! identifies what a caller was told, which is the index plus the exact sorted
//! issues that qualify it. They are separate because they change on different
//! events: a file that starts failing changes what a caller is told without
//! changing a single admitted byte, and a cursor that survived that transition
//! would be paging a health it no longer has.
//!
//! Both are read back through `Deserialize` alone. A transport hands a caller a
//! revision as text and receives it back as text, and this crate's own token
//! reader hands that text to the derived decoder — so the digits are checked by
//! the visitor that states the expectation, once. A `FromStr` beside it was a
//! second decode path with a third refusal sentence that no caller reached.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::hex::Hex;

/// The width of every claim this crate seals.
type Digest = Hex<32>;

/// The identity of one index's contents.
///
/// A SHA-256 claim over the schema, the enabled language and graph-coverage
/// vectors, every host ceiling, every admitted path and digest, and every
/// project key. It excludes the absolute spelling of the root and the order the
/// filesystem enumerated anything in, so the same repository checked out at two
/// paths states one identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IndexRevision {
    digest: Digest,
}

/// The identity of one published state: an index and the issues qualifying it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StateRevision {
    digest: Digest,
}

impl IndexRevision {
    /// Seal one claimed digest as an index identity.
    pub(crate) fn of(digest: [u8; 32]) -> Self {
        Self {
            digest: Digest::of(digest),
        }
    }

    /// The claimed digest, for a state claim taken over this index.
    pub(crate) fn claimed(&self) -> &[u8; 32] {
        self.digest.bytes()
    }
}

impl StateRevision {
    /// Seal one claimed digest as a state identity.
    pub(crate) fn of(digest: [u8; 32]) -> Self {
        Self {
            digest: Digest::of(digest),
        }
    }

    /// The claimed digest, for a cursor claim taken over this state.
    pub(crate) fn claimed(&self) -> &[u8; 32] {
        self.digest.bytes()
    }
}

impl fmt::Display for IndexRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.digest.fmt(formatter)
    }
}

impl fmt::Display for StateRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.digest.fmt(formatter)
    }
}
