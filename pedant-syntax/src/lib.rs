//! Syntax substrate for pedant.
//!
//! Owns language classification, tree-sitter parser selection, and the model
//! types that describe a source declaration. Depends only on `pedant-types`
//! and parser crates, so any consumer can use it without linking analysis.
//!
//! Every feature is off by default, so most of the extraction surface is
//! conditional. The published documentation labels each conditional item with
//! the feature that supplies it; the attribute is inert unless `docsrs` is set,
//! which only the docs.rs build does.
#![cfg_attr(docsrs, feature(doc_cfg))]

mod classify;
mod extract;
mod language;
mod location;
mod span;
#[cfg(feature = "_ts")]
#[cfg_attr(docsrs, doc(cfg(feature = "_ts")))]
pub mod tree_sitter;
mod unit;

pub use classify::{FileClassification, classify_path, detect_language};
pub use extract::enclosing_unit;
#[cfg(feature = "rust")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust")))]
pub use extract::invalidate_parser_cache;
pub use language::{SyntaxLanguage, syntax_language};
pub use location::Location;
pub use span::LineSpan;
pub use unit::{SourceUnit, SourceUnitKind};
