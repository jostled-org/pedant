use serde::{Deserialize, Serialize};

use crate::{CapabilityProfile, Language, SourceLocation};

/// The callable form a capability symbol takes.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySymbolKind {
    /// A free function.
    Function,
    /// A function declared on a type, trait, class, or object.
    Method,
}

/// The lexical callable that contains capability evidence.
///
/// Name and declaration location together are the identity, so overloads, equal
/// names in separate files, and nested functions stay distinct. This is not a
/// repository resolution identity: it carries no `DefinitionId`, graph node,
/// qualified path, or cross-file claim.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySymbol {
    /// Source language of the file that declared this callable.
    pub language: Language,
    /// Whether the callable is a free function or a method.
    pub kind: CapabilitySymbolKind,
    /// Declared name; `Box<str>` because one symbol identity owns it.
    pub name: Box<str>,
    /// One-based position of the declaration itself, not of any finding.
    pub declaration: SourceLocation,
}

/// One callable and the capability findings it contains.
///
/// A Pedant-emitted profile is non-empty and holds an ordered subsequence of
/// the flat findings. It clones only the finding records; their `Arc<str>` file
/// and evidence payloads stay shared with the flat profile.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SymbolCapabilityProfile {
    /// The callable that owns every finding below.
    pub symbol: CapabilitySymbol,
    /// This callable's findings, in flat detection order.
    pub profile: CapabilityProfile,
}
