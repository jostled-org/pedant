//! One fixed-width byte string, written and read as lowercase hex.
//!
//! Three published values are opaque byte strings a caller has to carry across
//! a transport and hand back: an index revision, a state revision, and a page
//! cursor. All three want the same wire form, the same `Display`, and the same
//! refusal for a spelling that is not one — so the encoding is stated once
//! here rather than three times beside the values that use it.
//!
//! The bytes stay private. A revision a caller could assemble from parts is a
//! revision that proves nothing about the index it names, and a cursor a caller
//! could assemble is a page nobody offered.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::digits::Digits;

/// `N` bytes, spelled as `2 * N` lowercase hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Hex<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Hex<N> {
    /// How many lowercase hex digits spell this value.
    ///
    /// The one statement of the width. A refusal that spelled it out would keep
    /// naming the old number after the claim width changed, and the sentence a
    /// caller reads would be the only thing still lying about it.
    pub(crate) const DIGITS: usize = N * 2;

    /// The value `bytes` spells.
    pub(crate) fn of(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// The bytes this value holds.
    pub(crate) fn bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> fmt::Display for Hex<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Digits::<N>)
    }
}
