//! Which named structures a search selects, and how it compares them.

use pedant_types::{Language, StructureKind};
use serde::{Deserialize, Serialize};

/// How a search compares its text with a declared name.
///
/// Explicit and closed. A search whose mode was inferred from the text would
/// change what it returns when a caller's query happened to look like a prefix,
/// and a caller cannot tell that from a repository that changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// The name is the query.
    Exact,
    /// The name opens with the query.
    Prefix,
    /// The name holds the query anywhere.
    Contains,
}

impl MatchMode {
    /// Every mode, in the order they are declared.
    ///
    /// The one list a transport describes its vocabulary from, so a schema that
    /// tells a client which tokens it may send is built from the same table the
    /// deserializer reads them back through.
    pub const ALL: [Self; 3] = [Self::Exact, Self::Prefix, Self::Contains];

    /// The stable token this mode is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Prefix => "prefix",
            Self::Contains => "contains",
        }
    }

    /// Whether `name` answers `query` under this mode.
    ///
    /// Case-sensitive, because every supported language has case-sensitive
    /// identifiers: a search that folded case would state a match no compiler
    /// would.
    pub(crate) fn matches(self, name: &str, query: &str) -> bool {
        match self {
            Self::Exact => name == query,
            Self::Prefix => name.starts_with(query),
            Self::Contains => name.contains(query),
        }
    }
}

/// Which named structures a search selects.
///
/// The filters are separate fields rather than one predicate because each of
/// them is part of the cursor binding: a continuation is only the rest of the
/// same result if every one of them is unchanged, and a closure cannot be
/// claimed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolQuery {
    /// The text to compare with each declared name.
    pub text: Box<str>,
    /// How to compare it.
    pub mode: MatchMode,
    /// Keep only structures recognized in this language.
    #[serde(default)]
    pub language: Option<Language>,
    /// Keep only structures of this kind.
    #[serde(default)]
    pub kind: Option<StructureKind>,
    /// Keep only structures whose nearest named owner is this.
    #[serde(default)]
    pub owner_name: Option<Box<str>>,
    /// Keep only structures declared beneath this normalized repository path.
    #[serde(default)]
    pub path_prefix: Option<Box<str>>,
}
