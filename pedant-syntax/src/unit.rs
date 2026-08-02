//! The extracted declaration returned at the syntax boundary.

use serde::{Deserialize, Serialize};

use crate::span::LineSpan;

/// The kind of declaration a [`SourceUnit`] describes.
///
/// Closed over the declarations every backend recognizes. Blocks, statements,
/// expressions, anonymous functions, and module declarations are not units.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SourceUnitKind {
    /// A free function.
    Function,
    /// A function an impl, a trait, a class, or an object literal owns.
    ///
    /// Ownership is the grammar's, not the reader's: a JavaScript object
    /// literal states its members with the same `method_definition` a class
    /// body does, and both answer here. A function merely nested inside another
    /// one is [`Self::Function`].
    Method,
    /// A struct definition.
    Struct,
    /// An enum definition.
    Enum,
    /// A union definition.
    Union,
    /// A trait definition.
    Trait,
    /// A type alias.
    TypeAlias,
    /// A Rust `impl` block.
    Impl,
    /// A class definition.
    Class,
}

/// One recognized declaration and its byte-exact source text.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SourceUnit {
    /// What kind of declaration this is.
    pub kind: SourceUnitKind,
    /// The declared name, when the grammar names the declaration.
    pub name: Option<Box<str>>,
    /// The declaration's one-based inclusive line range.
    pub span: LineSpan,
    /// The declaration's source text, copied byte-for-byte.
    pub text: Box<str>,
}
