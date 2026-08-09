//! Verification of claimed Cargo dependency edges.

use super::prelude::*;
use super::units::missing;
use super::{SemanticSnapshotClaim, SemanticSnapshotMismatch};

/// Every claimed edge must exist in the database, and the database must expose
/// no other in-repository dependency the snapshot did not claim.
pub(super) fn check_edges(
    context: &SemanticContext,
    claim: &SemanticSnapshotClaim,
    crates: &[Crate],
) -> Result<(), SemanticSnapshotMismatch> {
    check_claimed_edges(context, claim, crates)?;
    check_no_extra_edges(context, crates, &claimed_pairs(claim, crates))
}

/// Every claimed edge must exist in the database.
fn check_claimed_edges(
    context: &SemanticContext,
    claim: &SemanticSnapshotClaim,
    crates: &[Crate],
) -> Result<(), SemanticSnapshotMismatch> {
    let db = context.host.raw_database();
    for edge in &claim.edges {
        let (Some(source), Some(target)) = (crates.get(edge.source), crates.get(edge.target))
        else {
            return Err(SemanticSnapshotMismatch::UnitGraph {
                detail: Box::from("an edge names a unit the snapshot does not hold"),
            });
        };
        let alias = edge.alias.replace('-', "_");
        let stated = source
            .dependencies(db)
            .into_iter()
            .any(|found| found.krate == *target && found.name.as_str() == alias);
        if !stated {
            return Err(missing(edge.conditional, &edge.alias));
        }
    }
    Ok(())
}

/// Which unit each claimed edge joins to which, as one searchable set.
///
/// Both ends are named by the unit a database crate first answers for, so two
/// claimed units bound to one crate agree here exactly as they did when each
/// edge was compared one at a time.
fn claimed_pairs(claim: &SemanticSnapshotClaim, crates: &[Crate]) -> BTreeSet<(usize, usize)> {
    claim
        .edges
        .iter()
        .filter_map(|edge| {
            let target = crates.get(edge.target)?;
            Some((edge.source, unit_of(crates, *target)?))
        })
        .collect()
}

/// The first claimed unit one database crate answers for.
fn unit_of(crates: &[Crate], krate: Crate) -> Option<usize> {
    crates.iter().position(|found| *found == krate)
}

fn check_no_extra_edges(
    context: &SemanticContext,
    crates: &[Crate],
    claimed: &BTreeSet<(usize, usize)>,
) -> Result<(), SemanticSnapshotMismatch> {
    for (index, krate) in crates.iter().enumerate() {
        check_unit_edges(context, crates, claimed, (index, *krate))?;
    }
    Ok(())
}

/// One unit's in-repository dependencies must all be claimed edges.
fn check_unit_edges(
    context: &SemanticContext,
    crates: &[Crate],
    claimed: &BTreeSet<(usize, usize)>,
    unit: (usize, Crate),
) -> Result<(), SemanticSnapshotMismatch> {
    let (index, krate) = unit;
    let db = context.host.raw_database();
    let unclaimed = krate
        .dependencies(db)
        .into_iter()
        .filter_map(|dependency| {
            let target = unit_of(crates, dependency.krate)?;
            Some((dependency, target))
        })
        .find(|(_, target)| !claimed.contains(&(index, *target)));
    match unclaimed {
        Some((dependency, _)) => Err(SemanticSnapshotMismatch::UnitGraph {
            detail: format!(
                "the database exposes an unclaimed dependency named {}",
                dependency.name.as_str()
            )
            .into_boxed_str(),
        }),
        None => Ok(()),
    }
}
