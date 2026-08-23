//! The language-neutral projection every graph this crate returns is minted
//! through.
//!
//! A language adapter reads its own snapshot and its own report and states what
//! they claim as drafts. Nothing beneath this root names a language: the drafts
//! hold no dense identity, the placement decides where each stated record sits
//! and what stable identity it takes, the state holds the tables one assembly
//! resolves its symbolic joins through, and the assembler mints every identity,
//! proves every join, enforces every ceiling, and seals the one immutable
//! graph.
//!
//! Splitting it this way is what makes a second adapter cheap and a second
//! assembler impossible. An adapter that wanted different containment, a
//! different mint order, or a different capacity rule would have to change this
//! family, where every other adapter would see it.

/// The one checked assembler every returned graph is minted by.
pub(crate) mod assembly;
/// The graph-neutral drafts one projection plan is made of.
pub(crate) mod draft;
/// Containment as one acyclic forest of unit-rooted trees.
mod forest;
/// Where each stated record sits, and the stable identity it takes.
pub(crate) mod placement;
/// The tables one assembly resolves its symbolic joins through.
pub(crate) mod state;
/// Every neutral join, checked before a graph exists.
pub(crate) mod validation;
