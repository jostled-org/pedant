//! Binding claimed units to semantic database crates.

use super::prelude::*;
use super::{SemanticSnapshotClaim, SemanticSnapshotMismatch, SemanticUnitClaim};

pub(super) struct CrateIndex {
    entries: Box<[(FileId, Crate)]>,
}

impl CrateIndex {
    pub(super) fn build(context: &SemanticContext) -> Self {
        let db = context.host.raw_database();
        let mut entries: Vec<(FileId, Crate)> = Crate::all(db)
            .into_iter()
            .map(|krate| (krate.root_file(db), krate))
            .collect();
        entries.sort_by_key(|(file, _)| *file);
        Self {
            entries: entries.into_boxed_slice(),
        }
    }

    /// Every crate the database roots at one file.
    ///
    /// The entries are sorted by root file, so the run of entries sharing one
    /// root is a search and a walk of that run alone.
    fn at(&self, file: FileId) -> &[(FileId, Crate)] {
        let start = self.entries.partition_point(|(root, _)| *root < file);
        let rooted = self.entries.get(start..).unwrap_or_default();
        let shared = rooted.iter().take_while(|(root, _)| *root == file).count();
        rooted.get(..shared).unwrap_or_default()
    }
}

/// The database crate of every claimed unit, requested target first checked.
///
/// The requested target is bound once: the crate it binds to is reused where
/// its own unit appears in the claim rather than looked up a second time.
pub(super) fn bind_units(
    context: &SemanticContext,
    claim: &SemanticSnapshotClaim,
    index: &CrateIndex,
) -> Result<Box<[Crate]>, SemanticSnapshotMismatch> {
    let requested = claim.units.get(claim.requested).ok_or_else(|| {
        SemanticSnapshotMismatch::MalformedClaim {
            detail: format!(
                "the requested unit {} is not one of the {} units the claim holds",
                claim.requested,
                claim.units.len()
            )
            .into_boxed_str(),
        }
    })?;
    let bound = bound_crate(context, requested, index)?.ok_or_else(|| {
        SemanticSnapshotMismatch::RequestedTarget {
            name: Box::from(&*requested.name),
        }
    })?;
    claim
        .units
        .iter()
        .enumerate()
        .map(|(position, unit)| match position == claim.requested {
            true => Ok(bound),
            false => bind_unit(context, unit, index),
        })
        .collect()
}

fn bind_unit(
    context: &SemanticContext,
    unit: &SemanticUnitClaim,
    index: &CrateIndex,
) -> Result<Crate, SemanticSnapshotMismatch> {
    bound_crate(context, unit, index)?.ok_or_else(|| missing(unit.conditional, &unit.name))
}

/// The crate rooted at one claimed unit's entry source, when its name agrees.
///
/// Two crates rooted at one file leave no stated way to pick between them, so
/// the ambiguity is refused rather than settled by whichever the database
/// listed first.
fn bound_crate(
    context: &SemanticContext,
    unit: &SemanticUnitClaim,
    index: &CrateIndex,
) -> Result<Option<Crate>, SemanticSnapshotMismatch> {
    let db = context.host.raw_database();
    let Some(file) = context.file_id(&context.absolute(&unit.crate_root)) else {
        return Ok(None);
    };
    let krate = match index.at(file) {
        [] => return Ok(None),
        [(_, only)] => *only,
        rooted => return Err(ambiguous_root(&unit.crate_root, rooted.len())),
    };
    let named = krate
        .display_name(db)
        .map(|name| name.canonical_name().as_str().replace('-', "_"));
    Ok(named.filter(|name| *name == *unit.name).map(|_| krate))
}

/// More than one crate rooted at one claimed entry source.
fn ambiguous_root(crate_root: &str, rooted: usize) -> SemanticSnapshotMismatch {
    SemanticSnapshotMismatch::UnitGraph {
        detail: format!("the semantic database roots {rooted} crates at {crate_root}")
            .into_boxed_str(),
    }
}

/// A claimed unit or edge the database lacks: a refusal whose kind depends on
/// whether the snapshot said the unit was conditional.
pub(super) fn missing(conditional: bool, name: &str) -> SemanticSnapshotMismatch {
    match conditional {
        true => SemanticSnapshotMismatch::Activation {
            name: Box::from(name),
        },
        false => SemanticSnapshotMismatch::UnitGraph {
            detail: format!("no crate answers for unit {name}").into_boxed_str(),
        },
    }
}
