//! The inventory both tiers state, and the records a tier writes over it.
//!
//! Units, definitions, and references come from the snapshot alone, so both
//! tiers state the same ones in the same order. Only the records — the
//! candidates and gaps of each reference — depend on which tier is answering,
//! which is why the two entry points share everything above this line.

use pedant_types::{ResolutionReportBuilder, ResolutionReportLimits, ResolutionTier};

use crate::resolution::rust::snapshot::RustResolutionSnapshot;

use crate::resolution::line_index::LineIndex;

use super::coordinates;
use super::corpus::Corpus;
use super::error::RustResolutionError;
use super::graph::{self, Graph};
use super::index::{self, Index};
use super::promotion::Promotion;
use super::references::{self, ReferenceEntry};
use super::target::RustTargetResolution;
use super::units::{self, Units};
use super::{imports, records};

/// The inventory one snapshot states, before any reference is answered.
pub(super) struct Inventory {
    pub(super) graph: Graph,
    pub(super) units: Units,
    pub(super) index: Index,
    pub(super) entries: Box<[ReferenceEntry]>,
    builder: ResolutionReportBuilder,
}

/// State every unit, definition, and reference one snapshot holds.
pub(super) fn inventory(
    snapshot: &RustResolutionSnapshot,
    tier: ResolutionTier,
) -> Result<Inventory, RustResolutionError> {
    let mut builder = ResolutionReportBuilder::new(tier, ResolutionReportLimits::default());
    let lines: Box<[LineIndex]> = coordinates::index_sources(snapshot);
    let graph = graph::build(snapshot)?;
    let units = units::add_units(&mut builder, snapshot)?;
    let index = index::build(&mut builder, snapshot, (&graph, &units, &lines))?;
    let entries =
        references::add_references(&mut builder, snapshot, &graph, (&index, &units, &lines))?;
    Ok(Inventory {
        graph,
        units,
        index,
        entries,
        builder,
    })
}

/// Answer every reference of `inventory` and bind the report to its snapshot.
pub(super) fn finish<P: Promotion>(
    inventory: Inventory,
    snapshot: &RustResolutionSnapshot,
    promotion: &P,
) -> Result<RustTargetResolution, RustResolutionError> {
    let Inventory {
        graph,
        units,
        index,
        entries,
        mut builder,
    } = inventory;
    let corpus = Corpus {
        graph: &graph,
        index: &index,
        units: &units,
    };
    let imports = imports::bind(&corpus, snapshot, &entries)?;
    records::write(
        &mut builder,
        &corpus,
        (&imports, promotion),
        (snapshot, &entries, snapshot.limits()),
    )?;
    RustTargetResolution::try_new(snapshot, builder.finish()?)
}
