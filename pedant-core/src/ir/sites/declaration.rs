//! One `mod` item and the source or inline body it selects.

use crate::ir::cfg::RustCfgCondition;

/// A `mod` item, whether it holds an inline body or names another source.
///
/// The module closure reads this table rather than walking the syntax tree a
/// second time, so `#[path]`, inline bodies, and conditional compilation have
/// one owner.
#[derive(Debug)]
pub struct ModuleDeclarationSite {
    /// The declared module name.
    pub name: Box<str>,
    /// Every `#[path = "…"]` override the item carries, in attribute order.
    ///
    /// Usually empty or one entry. Several appear when mutually exclusive
    /// `cfg_attr` predicates give one module a source per configuration, which
    /// is how a crate selects between a platform's or feature's
    /// implementations. Conditions are recorded, never evaluated, so every
    /// alternative stays visible.
    pub declared_paths: Box<[Box<str>]>,
    /// Index into `FileIr::definition_sites` of the module this item defines.
    pub definition: usize,
    /// The scope this item opens, for an inline module only.
    pub inline_scope: Option<usize>,
    /// The scope this item is declared in.
    pub scope: usize,
    pub(crate) condition: RustCfgCondition,
}

impl ModuleDeclarationSite {
    /// The condition guarding this declaration, and through it the whole
    /// module instance the declaration selects.
    pub(crate) fn condition(&self) -> &RustCfgCondition {
        &self.condition
    }
}
