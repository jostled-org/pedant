//! One reference site, as the resolution states it before a record is written.
//!
//! The span, the text, and the definition holding the site come from the source
//! that wrote it; what the site names comes from the corpus. Both are settled
//! here so the record stage reads one shape rather than re-deciding either.

use std::sync::Arc;

use pedant_types::{ReferenceKind, ResolutionGap, SourceSpan};

/// One reference site, with what it names and why that answer is incomplete.
pub(super) struct Denotation {
    pub(super) kind: ReferenceKind,
    pub(super) text: Arc<str>,
    pub(super) span: SourceSpan,
    pub(super) enclosing: Option<usize>,
    pub(super) candidates: Box<[usize]>,
    pub(super) gap: Option<ResolutionGap>,
    /// Whether an unevaluated build predicate governs the source stating it.
    pub(super) conditional: bool,
    /// Whether the answer stays possible however few candidates it names.
    ///
    /// An interface dispatch is the one such answer: the target is chosen at
    /// run time, so a corpus holding exactly one implementor states a possible
    /// candidate rather than a resolved one.
    pub(super) possible_only: bool,
}
