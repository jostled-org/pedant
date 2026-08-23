//! The framed digest every language's snapshot fingerprint is built from.
//!
//! Two claims must never run together into one byte stream, so every field is
//! hashed with its own length and every list with its own element count. Both
//! lengths are fixed-width `u64` rather than pointer-width, so a 32-bit host
//! and a 64-bit host state one digest for one repository state.
//!
//! One owner, because a second framing rule would let a Rust snapshot and a Go
//! snapshot disagree about what "the same claim" means.
//!
//! One exception exists and must stay: `crate::hash` frames the persisted
//! supply-chain attestation the same way but with big-endian lengths. That
//! stream is hashed into receipts already committed to repositories, so
//! unifying its byte order would invalidate every one of them. It is a
//! different claim about different bytes, and it is named here so a later
//! reader finds it admitted rather than merging the two.

use sha2::{Digest, Sha256};

/// A SHA-256 stream that frames everything it is given.
pub(crate) struct ClaimDigest {
    hasher: Sha256,
}

impl ClaimDigest {
    /// An empty stream.
    pub(crate) fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Hash one field, length first.
    pub(crate) fn field(&mut self, bytes: &[u8]) {
        self.hasher.update((bytes.len() as u64).to_le_bytes());
        self.hasher.update(bytes);
    }

    /// Hash one text field in its exact bytes.
    pub(crate) fn text(&mut self, text: &str) {
        self.field(text.as_bytes());
    }

    /// Hash one list's element count, in the same framed form as a field.
    ///
    /// A field length delimits one field; it does not say where a list ends.
    /// Without the count, a claim of two units and one edge runs field-for-field
    /// against one of one unit and two edges.
    pub(crate) fn count(&mut self, elements: usize) {
        self.field(&(elements as u64).to_le_bytes());
    }

    /// Hash one optional text, presence tag first.
    ///
    /// An absent claim and a present but empty one are different facts, so the
    /// tag is hashed beside the text rather than instead of it.
    pub(crate) fn optional_text(&mut self, text: Option<&str>) {
        match text {
            None => self.field(&[0]),
            Some(held) => {
                self.field(&[1]);
                self.text(held);
            }
        }
    }

    /// Seal the stream.
    pub(crate) fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}
