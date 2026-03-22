/// Single-pass AST visitor that populates [`FileIr`] from a parsed source file.
pub mod extract;
/// IR data structures: fact types, spans, and enums.
pub mod facts;
/// Adapter for `ra_ap_ide` semantic analysis (type resolution, trait queries).
///
/// Always available — the [`SemanticContext`](semantic::SemanticContext) type
/// is unconstructable without the `semantic` feature, but exists so that
/// `analyze()` can accept `Option<&SemanticContext>` unconditionally.
pub mod semantic;
pub(crate) mod type_introspection;

pub use extract::extract;
pub use facts::*;

/// The Rust path separator token used when building qualified paths.
pub(crate) const PATH_SEPARATOR: &str = "::";
