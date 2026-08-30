//! The generic contract a source provider answers, and the record it answers
//! with.
//!
//! One repository holds one copy of each physical source, and several project
//! slices may reach it. A loader that opened the file itself would give one
//! revision as many byte strings as it has slices, and would walk one source
//! once per slice for the facts that source already states. The contract here
//! is the seam that makes those one each: a loader asks for a normalized path
//! and receives a shared immutable record, and whoever implements this trait
//! owns the read, the decode, and the one call into the language owner that
//! creates the inventory.
//!
//! Nothing here names a repository root, an absolute path, a language, or a
//! fact type. A root is the implementor's, because only it can confine a read;
//! the fact type is the language owner's, because only it can parse. This crate
//! states the shape they meet in and nothing else, which is why it can sit
//! beneath every one of them.

use std::fmt;
use std::sync::Arc;

/// One normalized, repository-relative, `/`-separated source path.
///
/// The type is the claim: a value of it has already been normalized, so a
/// provider that receives one is not the stage that has to decide whether
/// `../../etc/passwd` is a source in this repository. Construction is the only
/// place that decision is made, and it refuses rather than repairs, because a
/// repaired path is a path the caller and the provider disagree about.
///
/// Borrowed rather than owned: a request outlives nothing, and a provider that
/// keys records by this text owns its own copy of the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourcePath<'path> {
    text: &'path str,
}

impl<'path> SourcePath<'path> {
    /// One request path, if `text` is already normalized.
    ///
    /// Normalized means every segment is a real name: no empty segment, so the
    /// text is neither trailing-slashed nor doubly separated; no `.` or `..`
    /// segment, so it cannot climb; no backslash, so one separator spells one
    /// boundary; and no leading `/` or Windows drive prefix, so the text is
    /// relative on every host rather than only on the one that built it.
    pub fn new(text: &'path str) -> Option<Self> {
        is_normalized(text).then_some(Self { text })
    }

    /// The normalized text.
    pub fn as_str(self) -> &'path str {
        self.text
    }
}

impl fmt::Display for SourcePath<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text)
    }
}

/// Whether every segment of `text` is a real name.
///
/// A leading alphabetic drive prefix is refused on every host. A colon inside a
/// real segment has no path-root meaning and remains valid source text.
fn is_normalized(text: &str) -> bool {
    !text.contains('\\')
        && !has_windows_drive_prefix(text)
        && text
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | ".."))
}

/// Whether `text` opens with Windows' drive-qualified `letter:` spelling.
fn has_windows_drive_prefix(text: &str) -> bool {
    matches!(
        text.as_bytes(),
        [drive, b':', ..] if drive.is_ascii_alphabetic()
    )
}

/// One physical source a provider admitted: its exact text, its digest, and
/// the fact inventory its language owner extracted from it.
///
/// Every field is a shared immutable handle, so handing the same record to a
/// second slice copies two pointers rather than a file. `Facts` is the language
/// owner's own inventory type: this crate never names one, because the crate
/// that can parse a language is the crate that decides what its facts are.
#[derive(Debug)]
pub struct SourceRecord<Facts> {
    text: Arc<str>,
    digest: [u8; 32],
    facts: Arc<Facts>,
}

impl<Facts> SourceRecord<Facts> {
    /// Seal one admitted source.
    pub fn new(text: Arc<str>, digest: [u8; 32], facts: Arc<Facts>) -> Self {
        Self {
            text,
            digest,
            facts,
        }
    }

    /// The exact UTF-8 text that was read.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The same text, shared rather than copied.
    pub fn shared_text(&self) -> Arc<str> {
        Arc::clone(&self.text)
    }

    /// SHA-256 of the exact bytes behind [`Self::text`].
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The language owner's inventory for this source.
    pub fn facts(&self) -> &Facts {
        &self.facts
    }

    /// The same inventory, shared rather than copied.
    pub fn shared_facts(&self) -> Arc<Facts> {
        Arc::clone(&self.facts)
    }
}

/// A second handle to the same source, whatever the facts are.
///
/// Written out rather than derived: `derive(Clone)` would require `Facts:
/// Clone`, and the whole point of the record is that a second holder shares the
/// one inventory instead of copying it.
impl<Facts> Clone for SourceRecord<Facts> {
    fn clone(&self) -> Self {
        Self {
            text: Arc::clone(&self.text),
            digest: self.digest,
            facts: Arc::clone(&self.facts),
        }
    }
}

/// The one reader a bounded loader asks for a source.
///
/// Implemented once per fact type, so one store can answer for several
/// languages and each answer carries that language's own inventory and its own
/// typed refusal. The error is an associated type rather than a shared enum
/// because the reasons a Rust source is refused are not the reasons a Go source
/// is, and a caller that had to read a neutral cause would state a worse error
/// than the one its own seam already publishes.
///
/// `&mut self` because providing is admitting: the first request for a path
/// reads it, and every later one returns what that read produced.
pub trait SourceProvider<Facts> {
    /// Why one request states no record.
    type Error;

    /// The record for one normalized path, reading it if this is its first
    /// request.
    fn source(&mut self, path: SourcePath<'_>) -> Result<SourceRecord<Facts>, Self::Error>;
}
