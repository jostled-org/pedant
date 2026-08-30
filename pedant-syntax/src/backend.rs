//! Which parser backend this build links for a syntax language, and what its
//! parser reads.
//!
//! One selector, read by every operation that needs a parse: enclosing-unit
//! extraction and structure inventories both ask here. A disabled feature
//! removes its variant, so a configuration that links no parser leaves this
//! type uninhabited and every operation absent — which is why each operation's
//! own body can be exhaustive without naming an "absent backend" case.
//!
//! Selecting a backend and stating the text it lexes are one answer, so they sit
//! together: a backend that discards a leading prefix is the only reason the two
//! differ at all, and the selector is where that is known.

#[cfg(feature = "rust")]
use std::ops::Range;

use crate::language::SyntaxLanguage;

/// The byte-order mark `syn` discards before it lexes.
#[cfg(feature = "rust")]
const BYTE_ORDER_MARK: &str = "\u{feff}";

/// The text one backend's parser sees, inside the source its caller handed in.
///
/// A parser that discards a leading prefix reports every position against what
/// is left, so two answers are needed and both come from here: the string an
/// index must cover, and the source those positions are published against.
/// Reading the second separately — stripping the prefix again at another site —
/// would be a second derivation of one fact, free to disagree with the first
/// after a parser changed what it discards.
#[cfg(any(feature = "rust", feature = "_ts"))]
#[derive(Clone, Copy)]
pub(crate) struct ParsedSource<'source> {
    /// The caller's whole source, exactly as it was handed in.
    source: &'source str,
    /// How much of that source's front the parser dropped.
    ///
    /// The prefix length rather than the remaining slice, because it is the
    /// number both readers want: the text is that many bytes in, and a reported
    /// position is that many bytes short.
    discarded: usize,
}

#[cfg(any(feature = "rust", feature = "_ts"))]
impl<'source> ParsedSource<'source> {
    /// The whole of `source`, as a parser that discards nothing reads it.
    #[cfg(feature = "_ts")]
    fn whole(source: &'source str) -> Self {
        Self {
            source,
            discarded: 0,
        }
    }

    /// `source` past `prefix`, when it opens with one.
    #[cfg(feature = "rust")]
    fn past(source: &'source str, prefix: &str) -> Self {
        Self {
            source,
            discarded: match source.starts_with(prefix) {
                true => prefix.len(),
                false => 0,
            },
        }
    }

    /// The exact text the parser lexes, which every position it reports is
    /// measured against.
    ///
    /// The absent slice is unreachable: the offset is zero, or the length of a
    /// prefix the source was found to open with, so it always names a boundary
    /// inside the string. It is asserted rather than trusted, because the
    /// fallback is the unstripped source — every Rust position on line 1 short
    /// by the mark's three bytes, and a truncated body returned with nothing
    /// red. The convention is `select.rs`'s: a `debug_assert!` beside the
    /// fallible read, so a broken invariant fails a test instead of shipping a
    /// shifted answer.
    pub(crate) fn text(self) -> &'source str {
        let text = self.source.get(self.discarded..);
        debug_assert!(
            text.is_some(),
            "a discarded prefix ends on a boundary inside the parsed source"
        );
        text.unwrap_or(self.source)
    }

    /// The caller's own source, which every published byte offset indexes.
    ///
    /// A structure inventory is sealed over this string rather than over the
    /// parsed text, because its spans outlive the parse: `retained()` drops the
    /// source binding, and the consumer holding those offsets slices the file it
    /// read.
    #[cfg(feature = "rust")]
    pub(crate) fn source(self) -> &'source str {
        self.source
    }

    /// One byte range the parser reported, as a range in the caller's source.
    ///
    /// Saturating, the way every other narrowing in this crate is: the discarded
    /// prefix is three bytes of a string the caller already holds, so no sum
    /// here can overflow — but an unchecked one is a panic at a library boundary
    /// rather than an answer.
    #[cfg(feature = "rust")]
    pub(crate) fn at(self, range: Range<usize>) -> Range<usize> {
        range.start.saturating_add(self.discarded)..range.end.saturating_add(self.discarded)
    }
}

/// The parser backend this build links for a syntax language.
#[derive(Clone, Copy)]
pub(crate) enum Backend {
    /// `syn`, behind the `rust` feature.
    #[cfg(feature = "rust")]
    Rust,
    /// A tree-sitter grammar, behind the matching `ts-*` feature.
    #[cfg(feature = "_ts")]
    TreeSitter(SyntaxLanguage),
}

/// The backend `language` selects in this build.
///
/// A tree-sitter language selects the shared tree-sitter backend whenever the
/// build links any grammar; whether that backend links *this* grammar is
/// [`crate::tree_sitter::parse`]'s question, and a missing one is absence
/// there. Rust is the one language whose backend is its own feature.
pub(crate) fn backend(language: SyntaxLanguage) -> Option<Backend> {
    match language {
        #[cfg(feature = "rust")]
        SyntaxLanguage::Rust => Some(Backend::Rust),
        #[cfg(feature = "_ts")]
        SyntaxLanguage::Python
        | SyntaxLanguage::JavaScript
        | SyntaxLanguage::TypeScript
        | SyntaxLanguage::Tsx
        | SyntaxLanguage::Go
        | SyntaxLanguage::Bash => Some(Backend::TreeSitter(language)),
        // Present only while a backend is absent: a language whose feature
        // this build disables selects nothing.
        #[cfg(not(all(feature = "rust", feature = "_ts")))]
        _ => None,
    }
}

impl Backend {
    /// The exact text this backend's parser sees.
    ///
    /// A parser that discards a prefix reports every position against what is
    /// left, so an index over the source must cover that same string. `syn`
    /// strips a leading byte-order mark before lexing; indexing the unstripped
    /// source instead leaves every position on line 1 short by the mark's three
    /// bytes, which returns a shifted name and a truncated body rather than an
    /// error. A tree-sitter grammar strips nothing and indexes the source as
    /// given.
    ///
    /// `syn` also drops a leading shebang, but it keeps that line's newline, so
    /// line numbers and every later column already agree.
    ///
    /// The answer carries the caller's source beside the parsed text, because a
    /// structure inventory publishes byte offsets that outlive the parse and
    /// must index the string its caller holds. See [`ParsedSource`].
    #[cfg(any(feature = "rust", feature = "_ts"))]
    pub(crate) fn parsed_source(self, source: &str) -> ParsedSource<'_> {
        match self {
            #[cfg(feature = "rust")]
            Self::Rust => ParsedSource::past(source, BYTE_ORDER_MARK),
            #[cfg(feature = "_ts")]
            Self::TreeSitter(_) => ParsedSource::whole(source),
        }
    }
}
