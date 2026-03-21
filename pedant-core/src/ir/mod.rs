pub mod extract;
pub mod facts;
pub(crate) mod type_introspection;

pub use extract::extract;
pub use facts::*;

/// The Rust path separator token used when building qualified paths.
pub(crate) const PATH_SEPARATOR: &str = "::";
