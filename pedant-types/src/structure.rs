//! The neutral vocabulary of logical source structures.

use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::SymbolKind;

/// What one logical source structure declares.
///
/// Closed over the structures every supported language states, so a consumer
/// projecting an outline names one vocabulary rather than one per grammar. A
/// language emits only the subset its own table permits, and nothing here is
/// derived from a graph or report category.
///
/// This is the structure counterpart of
/// [`SymbolKind`](crate::SymbolKind), and it is a separate name rather than a
/// widened one because the two answer different questions. A symbol is
/// something a resolution report may name, so every symbol has a name; a
/// structure is something an outline may show, and [`Self::Impl`] has none.
/// Merging them would put an unnameable variant in the report schema.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum StructureKind {
    /// A module: a named namespace declared inside one source.
    Module,
    /// A free or associated function.
    Function,
    /// A function an impl, a trait, a class, or an interface owns.
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
    /// A Rust `impl` block, which declares no name of its own.
    Impl,
    /// A class definition.
    Class,
    /// An interface: a named method set a concrete type may satisfy.
    Interface,
    /// A defined type: a named type declared over an underlying one.
    DefinedType,
    /// A constant.
    Constant,
    /// A static.
    Static,
    /// A variable: a named binding at package or module scope.
    Variable,
    /// A field: a named member declared inside a type.
    Field,
    /// A package: the namespace a group of sources compile into together.
    Package,
}

impl StructureKind {
    /// Every kind, in the order they are declared.
    ///
    /// The one list a transport describes its vocabulary from, so a schema that
    /// tells a client which tokens it may send is built from the same table the
    /// deserializer reads them back through.
    pub const ALL: [Self; 17] = [
        Self::Module,
        Self::Function,
        Self::Method,
        Self::Struct,
        Self::Enum,
        Self::Union,
        Self::Trait,
        Self::TypeAlias,
        Self::Impl,
        Self::Class,
        Self::Interface,
        Self::DefinedType,
        Self::Constant,
        Self::Static,
        Self::Variable,
        Self::Field,
        Self::Package,
    ];

    /// The stable token this kind is claimed under.
    ///
    /// Exhaustive, so a kind the vocabulary gains fails to compile here rather
    /// than publishing a schema one token short of what it accepts. Every
    /// spelling is the one the `snake_case` rename above produces.
    pub fn token(self) -> &'static str {
        match self {
            Self::Module => "module",
            Self::Function => "function",
            Self::Method => "method",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Union => "union",
            Self::Trait => "trait",
            Self::TypeAlias => "type_alias",
            Self::Impl => "impl",
            Self::Class => "class",
            Self::Interface => "interface",
            Self::DefinedType => "defined_type",
            Self::Constant => "constant",
            Self::Static => "static",
            Self::Variable => "variable",
            Self::Field => "field",
            Self::Package => "package",
        }
    }
}

impl From<SymbolKind> for StructureKind {
    /// Every symbol a report may name is also a structure an outline may show.
    ///
    /// Total in this direction and absent in the other: [`StructureKind::Impl`]
    /// and [`StructureKind::Class`] have no symbol counterpart, so a producer
    /// that states one of those states it directly rather than through a symbol
    /// it would have to invent.
    fn from(kind: SymbolKind) -> Self {
        match kind {
            SymbolKind::Module => Self::Module,
            SymbolKind::Function => Self::Function,
            SymbolKind::Method => Self::Method,
            SymbolKind::Struct => Self::Struct,
            SymbolKind::Enum => Self::Enum,
            SymbolKind::Union => Self::Union,
            SymbolKind::Trait => Self::Trait,
            SymbolKind::TypeAlias => Self::TypeAlias,
            SymbolKind::Constant => Self::Constant,
            SymbolKind::Static => Self::Static,
            SymbolKind::Package => Self::Package,
            SymbolKind::Interface => Self::Interface,
            SymbolKind::DefinedType => Self::DefinedType,
            SymbolKind::Variable => Self::Variable,
            SymbolKind::Field => Self::Field,
        }
    }
}

/// Where one structure sits in the source its inventory was taken from.
///
/// Both a byte range and the lines its ends fall on, because the two consumers
/// ask different questions: slicing and point lookup index bytes, while an
/// outline states lines. Deriving either from the other needs the source
/// string, which a single record does not carry.
///
/// Bytes are zero-based and half-open, so `start_byte..end_byte` slices the
/// retained source exactly. Lines are one-based and inclusive, so a structure
/// written on one line has equal ends and a [`Self::line_count`] of one.
///
/// The constructor is public because two crates mint spans — the syntax
/// substrate's bounded inventory builder and `pedant-core`'s Rust site
/// inventory — and each mints from a source it has just read. It sits here
/// rather than with either of them for the reason [`StructureKind`] does: a
/// vocabulary several crates state has to be one type, or the outline they
/// compose states two.
///
/// Line numbers arrive already narrowed. A minter reads its lines from an index
/// or a grammar position and knows what a source too large to number means;
/// this type cannot, so it takes the width it stores rather than narrowing a
/// caller's `usize` behind its back.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StructureSpan {
    start_byte: u64,
    end_byte: u64,
    start_line: u32,
    end_line: u32,
}

impl StructureSpan {
    /// The extent covering `bytes`, opening on one-based `start_line` and
    /// closing on one-based `end_line`.
    pub fn new(bytes: Range<usize>, start_line: u32, end_line: u32) -> Self {
        Self {
            start_byte: wire_offset(bytes.start),
            end_byte: wire_offset(bytes.end),
            start_line,
            end_line,
        }
    }

    /// The byte range this structure covers, as a slice index.
    pub fn byte_range(self) -> Range<usize> {
        slice_offset(self.start_byte)..slice_offset(self.end_byte)
    }

    /// The zero-based offset of the structure's first byte.
    pub fn start_byte(self) -> u64 {
        self.start_byte
    }

    /// The zero-based offset one past the structure's last byte.
    pub fn end_byte(self) -> u64 {
        self.end_byte
    }

    /// The one-based line the structure opens on.
    pub fn start_line(self) -> u32 {
        self.start_line
    }

    /// The one-based line the structure closes on, inclusive.
    pub fn end_line(self) -> u32 {
        self.end_line
    }

    /// The number of physical lines the structure covers.
    pub fn line_count(self) -> u32 {
        self.end_line
            .saturating_sub(self.start_line)
            .saturating_add(1)
    }

    /// Whether this extent strictly contains `inner`.
    ///
    /// Strict, because an owner that merely equals its child states no
    /// ownership: two structures at one extent are one structure recognized
    /// twice, which is the shape an owner forest must not admit.
    pub fn strictly_contains(self, inner: Self) -> bool {
        self.start_byte <= inner.start_byte
            && inner.end_byte <= self.end_byte
            && (self.start_byte, self.end_byte) != (inner.start_byte, inner.end_byte)
    }
}

/// One source offset as the wire type states it.
///
/// A `usize` is never wider than a `u64` on any platform this workspace builds
/// for, so nothing is lost. It is written as a checked conversion rather than a
/// cast so a wider platform states the largest offset the wire can carry — an
/// extent nothing can slice — instead of a small one a reader would accept.
fn wire_offset(offset: usize) -> u64 {
    u64::try_from(offset).unwrap_or(u64::MAX)
}

/// One wire offset as a slice index.
///
/// Saturating for the same reason: a document naming an offset this platform
/// cannot address states an extent that slices nothing, and the saturated index
/// is the one value guaranteed to fail that slice rather than name other bytes.
fn slice_offset(offset: u64) -> usize {
    usize::try_from(offset).unwrap_or(usize::MAX)
}

/// One logical structure, retained past the parse that recognized it.
///
/// The owned counterpart of a borrowed structure fact. A fact borrows its name
/// from the source its inventory indexes, which is right while the parse is
/// alive and impossible once a repository index outlives it. The owner stays a
/// position in the same source's record list, because a record list holds one
/// entry per site and cannot name a structure in another file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructureRecord {
    kind: StructureKind,
    name: Option<Box<str>>,
    span: StructureSpan,
    owner: Option<u32>,
}

impl StructureRecord {
    /// Retain one recognized structure.
    pub fn new(
        kind: StructureKind,
        name: Option<Box<str>>,
        span: StructureSpan,
        owner: Option<u32>,
    ) -> Self {
        Self {
            kind,
            name,
            span,
            owner,
        }
    }

    /// What this structure declares.
    pub fn kind(&self) -> StructureKind {
        self.kind
    }

    /// The declared name, in its source spelling.
    ///
    /// Absent for a structure its grammar states no name for. This contract
    /// states two: the Rust `impl` block, and the file module a Python or
    /// ECMAScript source declares no node for.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The extent of the whole declaration.
    pub fn span(&self) -> StructureSpan {
        self.span
    }

    /// The nearest structure that lexically owns this one, as a position in the
    /// same source's record list.
    pub fn owner(&self) -> Option<u32> {
        self.owner
    }
}
