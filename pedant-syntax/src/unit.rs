//! The extracted declaration returned at the syntax boundary.

use pedant_types::StructureKind;
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

impl SourceUnitKind {
    /// The unit one structure kind declares, when this model declares one.
    ///
    /// Every unit is a structure, and the reverse is partial: a module, an
    /// interface, a defined type, a constant, a static, a variable, a field, and
    /// a package are structures an outline shows and declarations this model
    /// states no kind for. A caller inside one of them reads the declaration
    /// that holds it instead.
    ///
    /// An `Option`, not a `Result`. The refused kind is the one the caller
    /// already handed in, so handing it back said nothing a caller did not know,
    /// and every caller dropped it: this is absence, and a `Result` no reader
    /// reads is an `Option` spelled the long way.
    ///
    /// Total, so a structure kind the vocabulary gains fails to compile here
    /// rather than silently joining the unit model or silently leaving it.
    pub fn of(kind: StructureKind) -> Option<Self> {
        match kind {
            StructureKind::Function => Some(Self::Function),
            StructureKind::Method => Some(Self::Method),
            StructureKind::Struct => Some(Self::Struct),
            StructureKind::Enum => Some(Self::Enum),
            StructureKind::Union => Some(Self::Union),
            StructureKind::Trait => Some(Self::Trait),
            StructureKind::TypeAlias => Some(Self::TypeAlias),
            StructureKind::Impl => Some(Self::Impl),
            StructureKind::Class => Some(Self::Class),
            StructureKind::Module
            | StructureKind::Interface
            | StructureKind::DefinedType
            | StructureKind::Constant
            | StructureKind::Static
            | StructureKind::Variable
            | StructureKind::Field
            | StructureKind::Package => None,
        }
    }
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
