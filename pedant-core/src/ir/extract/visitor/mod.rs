//! AST traversal: the `syn::visit::Visit` dispatch that drives [`IrExtractor`].
//!
//! Each override records the facts its node carries, then delegates to the
//! default `syn::visit::visit_*` to continue the walk. Nodes that open a scope
//! (functions, loops, branches, impls) bracket that delegation with the
//! extractor's scaffolding so nesting state unwinds correctly.

mod implementation;
