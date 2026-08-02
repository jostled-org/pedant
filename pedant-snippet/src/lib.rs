//! Enclosing-declaration extraction for one point in one file.
//!
//! Reads a source file as UTF-8, detects its syntax language, and returns the
//! narrowest declaration containing a location. The `pedant-snippet` binary
//! serves this same operation over a CLI and an MCP stdio transport, and both
//! transports serialize the same [`Extraction`] envelope.
//!
//! The location model, the returned declaration, and the byte-exact extraction
//! rules all belong to `pedant-syntax`; the types this crate re-exports are that
//! crate's, so a consumer needs only this dependency. [`Extraction::to_json`]
//! reports a serializer failure, so [`JsonError`] is re-exported on the same
//! terms.

mod envelope;
mod error;
mod extract;

pub use envelope::Extraction;
pub use error::SnippetError;
pub use extract::extract_path;
pub use pedant_syntax::{LineSpan, Location, SourceUnit, SourceUnitKind, invalidate_parser_cache};
pub use serde_json::Error as JsonError;
