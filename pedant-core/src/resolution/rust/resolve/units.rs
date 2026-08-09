//! The report units one snapshot's Cargo target instances become.
//!
//! A unit's stable key is its normalized manifest path plus target kind and
//! target name; its display name is the canonical Cargo crate name. Dependency
//! aliases stay beside the units rather than inside their keys, because a
//! rename is a property of the namespace that declares the edge.

use std::collections::BTreeMap;

use pedant_types::{ResolutionReportBuilder, ResolutionUnitHandle};

use crate::ir::cfg::RustCfgCondition;
use crate::resolution::rust::dependency::DependencyActivation;
use crate::resolution::rust::identity::index_of;
use crate::resolution::rust::snapshot::{RustResolutionSnapshot, RustResolutionUnit};

use super::error::RustResolutionError;
use super::target::{crate_name, unit_key};

/// Every snapshot unit as the report and the resolver address it.
pub(super) struct Units {
    pub(super) handles: Box<[ResolutionUnitHandle]>,
    pub(super) conditions: Box<[RustCfgCondition]>,
    crate_names: Box<[Box<str>]>,
    dependencies: BTreeMap<usize, BTreeMap<Box<str>, usize>>,
}

impl Units {
    /// The unit one namespace-local dependency alias selects, or the unit
    /// itself when the name is its own crate name.
    pub(super) fn named(&self, unit: usize, name: &str) -> Option<usize> {
        let aliased = self
            .dependencies
            .get(&unit)
            .and_then(|edges| edges.get(name))
            .copied();
        aliased.or_else(|| self.own(unit, name))
    }

    fn own(&self, unit: usize, name: &str) -> Option<usize> {
        self.crate_names
            .get(unit)
            .filter(|own| &***own == name)
            .map(|_| unit)
    }
}

/// State every unit and record how the resolver addresses it.
pub(super) fn add_units(
    builder: &mut ResolutionReportBuilder,
    snapshot: &RustResolutionSnapshot,
) -> Result<Units, RustResolutionError> {
    let mut handles = Vec::with_capacity(snapshot.units().len());
    let mut crate_names = Vec::with_capacity(snapshot.units().len());
    for unit in snapshot.units() {
        let name = crate_name(unit);
        handles.push(builder.add_unit(
            pedant_types::Language::Rust,
            unit_key(unit),
            std::sync::Arc::clone(&name),
        )?);
        crate_names.push(Box::from(&*name));
    }
    Ok(Units {
        handles: handles.into_boxed_slice(),
        conditions: snapshot.units().iter().map(activation).collect(),
        crate_names: crate_names.into_boxed_slice(),
        dependencies: dependency_names(snapshot),
    })
}

/// A conditional unit contributes its unevaluated predicate to every candidate
/// it holds; an always-active one contributes nothing.
fn activation(unit: &RustResolutionUnit) -> RustCfgCondition {
    match unit.activation() {
        DependencyActivation::Always => RustCfgCondition::default(),
        DependencyActivation::Conditional(predicate) => RustCfgCondition::stated(predicate),
    }
}

fn dependency_names(
    snapshot: &RustResolutionSnapshot,
) -> BTreeMap<usize, BTreeMap<Box<str>, usize>> {
    let mut edges: BTreeMap<usize, BTreeMap<Box<str>, usize>> = BTreeMap::new();
    for edge in snapshot.edges() {
        let source = index_of(edge.source().index());
        let target = index_of(edge.target().index());
        edges
            .entry(source)
            .or_default()
            .insert(alias(edge.name()), target);
    }
    edges
}

/// Cargo exposes a dependency under its name with dashes replaced.
fn alias(name: &str) -> Box<str> {
    name.replace('-', "_").into_boxed_str()
}
