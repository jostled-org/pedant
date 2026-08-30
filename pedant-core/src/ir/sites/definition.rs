//! One definition a resolution report may name.

use std::sync::Arc;

use pedant_types::SymbolKind;

use crate::ir::cfg::RustCfgCondition;

use super::range::IrRange;

/// A definition site: what one name in one source declares.
///
/// Local bindings, parameters, labels, and lifetimes are absent by design; the
/// owned seam is repository-level modules, functions, methods, types, and
/// constants.
#[derive(Debug)]
pub struct DefinitionSite {
    /// What kind of definition this is.
    pub kind: SymbolKind,
    /// The declared name.
    pub name: Box<str>,
    /// Where the declared name sits in the source.
    pub range: IrRange,
    /// The scope this definition is declared in.
    pub scope: usize,
    /// The definition that lexically owns this one, inside the same source.
    pub parent: Option<usize>,
    /// The `impl` self type or trait this associated item belongs to.
    ///
    /// Shared with the traversal state the owner is read from, and with the
    /// lookup table a later pass keys on it: every associated item under one
    /// `impl` block names the same owner, so the name is held once rather than
    /// copied per item and again per table entry.
    pub associated_with: Option<Arc<str>>,
    pub(crate) condition: RustCfgCondition,
}

impl DefinitionSite {
    /// The conditional-compilation predicates guarding this definition.
    pub(crate) fn condition(&self) -> &RustCfgCondition {
        &self.condition
    }
}
