//! The authoritative definition and reference site inventory one extraction
//! pass produces.
//!
//! Every fact that names a repository-level symbol points at a site here rather
//! than inventing a second identity, and every occurrence is kept: two
//! identical path texts at two locations are two reference sites. Coordinates
//! are the line/column pairs `syn` reports; converting them to the report's
//! zero-based UTF-8 byte columns needs the exact source text and therefore
//! belongs to the resolver that owns it.
//!
//! One kind of path is deliberately absent. A single-segment path in value
//! position states no reference site, because without types this tier cannot
//! tell a unit-struct value from a local binding; such a path is read for
//! receiver inference only. Every other path states one site: a callee, a
//! qualified path, a type mention, a struct literal, an import leaf, and an
//! external `mod` item.

/// One `mod` item and the source or inline body it selects.
mod declaration;
/// One definition a resolution report may name.
mod definition;
/// A half-open source range.
mod range;
/// One reference site and where it came from.
mod reference;
/// One lexical module scope inside a single source.
mod scope;
/// One physical declaration site and the definition it states.
mod structure;

pub use declaration::ModuleDeclarationSite;
pub use definition::DefinitionSite;
pub use range::IrRange;
pub use reference::ReferenceSite;
pub use scope::ModuleScope;
pub use structure::{DefinitionSiteId, StructureSite, StructureSiteId};

pub(crate) use reference::ReferenceOrigin;
