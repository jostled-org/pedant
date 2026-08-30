//! Everything one language decides about retaining a source in its own
//! snapshot.
//!
//! Five decisions, and they are the five the two snapshot stores genuinely
//! disagree on: the root and the distinct-file ceiling they measure against,
//! the record each retains, and the vocabulary each refusal is published in.
//! Everything else about retaining a source — the key buffer, the interning
//! map, the order the ceilings are charged in, the sorted finish — belongs to
//! the one [`SnapshotStoreOf`](super::snapshot_store::SnapshotStoreOf) that
//! reads through this.
//!
//! Stated apart from that store for the same reason
//! [`SourceLanguage`](super::source_language::SourceLanguage) is stated apart
//! from the record cache: what a language owes is a contract a language module
//! reads, and what the store does with it is not.

use std::path::Path;

use super::path_normalization::RelativePathError;
use super::read::{ByteCeilings, ReadFault};

/// The language-owned half of one snapshot retention.
///
/// The byte ceilings are the supertrait's, because they are the one part of
/// this contract the shared charge itself applies: a language that stated them
/// here as well would be stating them twice for one comparison.
pub(crate) trait SnapshotRules: ByteCeilings {
    /// The facts a provider extracted from one source.
    type Inventory;

    /// Why the provider states no record for a normalized path.
    type Fault;

    /// Why this snapshot's own seam states no source.
    type Refusal;

    /// What this seam names a refusal against beside the path.
    ///
    /// A Rust closure names the target entry or `mod` item that asked for the
    /// source, because a caller has to know which declaration leads to it. A Go
    /// package walk names only the path, so it states the unit type.
    type Site;

    /// One retained record, as this language holds it.
    type Stored;

    /// The canonical repository root every retained path is measured against.
    ///
    /// The rules own it rather than the store, so the root a refusal names and
    /// the root a key is rendered from cannot become two values.
    fn root(&self) -> &Path;

    /// The most distinct sources this snapshot may hold.
    fn max_source_files(&self) -> u32;

    /// The normalized path one retained record is keyed and sorted by.
    fn stored_path(stored: &Self::Stored) -> &str;

    /// Why this seam states no repository-relative key for one path.
    fn unrelative(&self, error: RelativePathError, at: (&Self::Site, &Path)) -> Self::Refusal;

    /// Why this seam admits no further source.
    fn source_files(&self, at: (&Self::Site, &str)) -> Self::Refusal;

    /// Why a rendered key is not a request a provider accepts.
    fn unnormalized(&self, at: (&Self::Site, &str)) -> Self::Refusal;

    /// This seam's own refusal for one refused provider request.
    fn refused(&self, fault: Self::Fault, at: (&Self::Site, &str)) -> Self::Refusal;

    /// This seam's own refusal for a record past one of its byte ceilings.
    fn oversized(&self, fault: ReadFault, at: (&Self::Site, &str)) -> Self::Refusal;
}
