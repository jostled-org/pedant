//! The `mod` items one stored source declares, projected from its IR.
//!
//! The one-pass extractor already recorded every `mod` item, its `#[path]`
//! override, and the scope an inline body opens, so the closure reads that
//! table instead of walking the syntax tree a second time. The projection runs
//! once per distinct source, when the source is interned: a unit that
//! instantiates one source at several positions, and several units that share
//! it, all read the same shared per-scope tables.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::ir::FileIr;
use crate::resolution::rust::identity::position;

/// One `mod` item the closure must resolve.
#[derive(Debug)]
pub(super) struct ModuleDeclaration {
    pub(super) name: Arc<str>,
    /// Every `#[path]` override this item selects, unconditional or applied by
    /// a `cfg_attr`. Empty when the standard `name.rs`/`name/mod.rs` lookup
    /// answers instead.
    pub(super) declared_paths: Box<[Arc<str>]>,
    /// The scope an inline body opens; absent when the item names a source.
    pub(super) inline_scope: Option<u32>,
    /// This item's position in the declaring source's IR declaration table.
    pub(super) index: u32,
}

/// Every `mod` item `ir` declares, grouped by the scope that declares it.
///
/// A scope with no `mod` item holds no entry, so an absent key means the scope
/// declares nothing rather than that the source is unknown.
pub(super) fn declarations_by_scope(ir: &FileIr) -> BTreeMap<u32, Arc<[ModuleDeclaration]>> {
    let mut scopes: BTreeMap<u32, Vec<ModuleDeclaration>> = BTreeMap::new();
    for (index, site) in ir.module_declarations.iter().enumerate() {
        scopes
            .entry(position(site.scope))
            .or_default()
            .push(ModuleDeclaration {
                name: Arc::from(&*site.name),
                declared_paths: site
                    .declared_paths
                    .iter()
                    .map(|path| Arc::from(&**path))
                    .collect(),
                inline_scope: site.inline_scope.map(position),
                index: position(index),
            });
    }
    scopes
        .into_iter()
        .map(|(scope, declarations)| (scope, Arc::from(declarations)))
        .collect()
}
