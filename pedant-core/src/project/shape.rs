use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::check_config::CheckConfig;
use crate::ir::{FileIr, FnFact, IrSpan};

/// Where a type name is defined, for the one-definition-site identity rule.
#[derive(Debug, Clone)]
pub struct TypeDefSite {
    /// Name of the defined type, as written.
    pub type_name: Box<str>,
    /// Location of the definition keyword.
    pub span: IrSpan,
}

/// One type's inherent-impl footprint within a single file, under one set of
/// `#[cfg]` predicates.
///
/// A file contributes one site per `(type, predicate set)` pair, because only
/// impls sharing a predicate set are guaranteed to compile into the same build.
#[derive(Debug, Clone)]
pub struct InherentImplSite {
    /// Name of the implemented type, as written.
    pub type_name: Box<str>,
    /// Sorted, deduplicated `#[cfg]` predicates guarding these impls within the
    /// file. Empty means they are in every build of the file.
    pub cfg_predicates: Box<[Box<str>]>,
    /// Location of the first inherent `impl` for the type under these gates.
    pub first_impl: IrSpan,
    /// Inherent methods contributed here, after forwarder exclusion.
    pub method_count: usize,
}

/// A `mod` declaration guarded by `#[cfg(…)]`.
///
/// The gate is only ever written in the *parent* file, so it is invisible from
/// inside the module's own file. Carrying it here is what lets the project pass
/// attribute `unix.rs` to `#[cfg(unix)]`.
#[derive(Debug, Clone)]
pub struct CfgGatedModule {
    /// Module name, which names the file or directory it pulls in.
    pub name: Box<str>,
    /// Sorted, deduplicated predicates guarding the declaration.
    pub cfg_predicates: Box<[Box<str>]>,
}

/// The slice of a file's IR that whole-crate checks need.
///
/// This is a projection, not a copy: only type definition sites, per-type
/// inherent-impl footprints, and `#[cfg]`-gated `mod` declarations survive, so
/// the project pass never holds a [`FileIr`] and never re-parses a file.
#[derive(Debug, Clone)]
pub struct FileShape {
    /// Path of the file this shape was projected from.
    pub file_path: Arc<str>,
    /// Every struct, enum, union, and trait defined in this file.
    pub type_defs: Box<[TypeDefSite]>,
    /// Per-type, per-predicate-set inherent-impl footprints.
    pub inherent_impls: Box<[InherentImplSite]>,
    /// `mod` declarations in this file carrying a `#[cfg(…)]`.
    pub cfg_gated_modules: Box<[CfgGatedModule]>,
}

/// Project the facts whole-crate checks need out of a file's IR.
pub fn project_shape(ir: &FileIr, config: &CheckConfig) -> FileShape {
    FileShape {
        file_path: Arc::clone(&ir.file_path),
        type_defs: collect_type_defs(ir),
        inherent_impls: collect_inherent_impls(ir, config),
        cfg_gated_modules: collect_cfg_gated_modules(ir),
    }
}

/// Canonical form of a predicate set: sorted and deduplicated, so two items
/// under the same gates produce equal keys.
pub(super) fn canonical_predicates<'a>(
    predicates: impl IntoIterator<Item = &'a str>,
) -> Box<[Box<str>]> {
    predicates
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Box::from)
        .collect()
}

fn predicate_key(predicates: &[Arc<str>]) -> Box<[Box<str>]> {
    canonical_predicates(predicates.iter().map(|predicate| &**predicate))
}

/// Every type definition in the file, of every kind.
///
/// Kind is deliberately dropped. A name that is both a `struct` and a `trait`
/// is two definition sites, which is exactly the ambiguity that must suppress a
/// finding rather than be resolved by guessing.
fn collect_type_defs(ir: &FileIr) -> Box<[TypeDefSite]> {
    ir.type_defs
        .iter()
        .map(|def| TypeDefSite {
            type_name: Box::from(&*def.name),
            span: def.span,
        })
        .collect()
}

/// Key identifying one `(type, predicate set)` footprint within a file.
type SiteKey<'a> = (&'a str, Box<[Box<str>]>);

fn collect_inherent_impls(ir: &FileIr, config: &CheckConfig) -> Box<[InherentImplSite]> {
    let mut sites: BTreeMap<SiteKey<'_>, (IrSpan, usize)> = BTreeMap::new();
    seed_impl_blocks(ir, &mut sites);
    count_methods(ir, config, &mut sites);
    sites
        .into_iter()
        .map(
            |((type_name, cfg_predicates), (first_impl, method_count))| InherentImplSite {
                type_name: Box::from(type_name),
                cfg_predicates,
                first_impl,
                method_count,
            },
        )
        .collect()
}

/// Record each inherent `impl` block, so a type reads as present under its
/// gates even when the block is empty or holds only forwarders.
fn seed_impl_blocks<'a>(ir: &'a FileIr, sites: &mut BTreeMap<SiteKey<'a>, (IrSpan, usize)>) {
    let inherent = ir.impl_blocks.iter().filter(|imp| imp.trait_name.is_none());
    for imp in inherent {
        sites
            .entry((&imp.self_type, predicate_key(&imp.cfg_predicates)))
            .or_insert((imp.span, 0));
    }
}

/// Add each method to the footprint for its own gates, which may be stricter
/// than its `impl` block's when the method carries a `#[cfg]` of its own.
fn count_methods<'a>(
    ir: &'a FileIr,
    config: &CheckConfig,
    sites: &mut BTreeMap<SiteKey<'a>, (IrSpan, usize)>,
) {
    for func in &ir.functions {
        let Some(type_name) = &func.inherent_method_of else {
            continue;
        };
        if !counts_toward_surface(func, config) {
            continue;
        }
        let entry = sites
            .entry((&**type_name, predicate_key(&func.cfg_predicates)))
            .or_insert((func.span, 0));
        entry.1 += 1;
    }
}

/// Pure forwarders carry no responsibility of their own, matching
/// `high-method-count`. Conditional methods are *not* excluded here — the
/// project pass groups them by predicate instead, because excluding them would
/// let a `#[cfg]` on a default-on feature hide a god-object that ships.
fn counts_toward_surface(func: &FnFact, config: &CheckConfig) -> bool {
    !func.is_pure_forwarder || config.count_forwarders
}

fn collect_cfg_gated_modules(ir: &FileIr) -> Box<[CfgGatedModule]> {
    ir.modules
        .iter()
        .filter(|module| !module.cfg_predicates.is_empty())
        .map(|module| CfgGatedModule {
            name: module.name.clone(),
            cfg_predicates: predicate_key(&module.cfg_predicates),
        })
        .collect()
}
