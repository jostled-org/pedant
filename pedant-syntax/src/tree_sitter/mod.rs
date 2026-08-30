//! Shared tree-sitter helpers for structured AST extraction.
//!
//! Feature-gated: only compiled when at least one `ts-*` language feature is
//! enabled. Grammar selection lives here, so a consumer names a
//! [`SyntaxLanguage`](crate::SyntaxLanguage) and never a grammar crate. The
//! node and tree types the public signatures below name are re-exported,
//! because this module is a cross-crate API.
//!
//! Three private owners split the work, and each exports its surface here. The
//! parser constructs the crate's only tree-sitter parser and selects grammars:
//! [`parse`] and [`parse_bound`]. The session owns a parsed tree bound to the
//! exact source that produced it and answers declaration questions about it
//! without parsing, one location or a whole slice of them at a time:
//! [`ParsedSyntax`] and [`SourceUnitAnchor`]. The traversal walks a tree and
//! reads node text: [`walk_descendants`] and [`node_text`].

mod parser;
mod session;
mod traversal;

pub use ::tree_sitter::{Node, Tree};

pub(crate) use parser::links_grammar;
pub use parser::{parse, parse_bound};
pub use session::{ParsedSyntax, SourceUnitAnchor};
// Visible to the crate, not just to this module: the structure walk and the Go
// fact walk each ascend the same cursor the same way, one of them closing the
// contexts it leaves, so the loop is shared rather than copied per walk.
#[cfg(any(feature = "ts-go", feature = "_ts_generic"))]
pub(crate) use traversal::advance;
pub use traversal::{node_text, walk_descendants};
