//! The inventory both tiers state, and the records a tier writes over it.
//!
//! Units, definitions, and references come from the snapshot alone, so both
//! tiers state the same ones in the same order. Only the records — the
//! candidates and gaps of each reference — depend on which tier is answering,
//! which is why the two entry points share everything above this line.

use pedant_types::{ResolutionReportBuilder, ResolutionReportLimits, ResolutionTier};

use crate::resolution::rust::snapshot::RustResolutionSnapshot;

use crate::resolution::line_index::{LineIndex, index_sources};

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
///
/// The line tables are retained rather than dropped. They are built here from
/// the snapshot's texts alone, and the boundary that binds the finished report
/// proves every stated coordinate against those same texts, so dropping them
/// would mean scanning every source byte a second time to rebuild a table this
/// stage already held.
pub(super) struct Inventory<'snapshot> {
    pub(super) graph: Graph,
    pub(super) units: Units,
    pub(super) index: Index,
    pub(super) entries: Box<[ReferenceEntry]>,
    lines: Box<[LineIndex<'snapshot>]>,
    builder: ResolutionReportBuilder,
}

/// State every unit, definition, and reference one snapshot holds.
pub(super) fn inventory(
    snapshot: &RustResolutionSnapshot,
    tier: ResolutionTier,
) -> Result<Inventory<'_>, RustResolutionError> {
    let mut builder = ResolutionReportBuilder::new(tier, ResolutionReportLimits::default());
    let lines = index_sources(snapshot.sources());
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
        lines,
        builder,
    })
}

/// Answer every reference of `inventory` and bind the report to its snapshot.
pub(super) fn finish<'snapshot, P: Promotion>(
    inventory: Inventory<'snapshot>,
    snapshot: &'snapshot RustResolutionSnapshot,
    promotion: &P,
) -> Result<RustTargetResolution, RustResolutionError> {
    let Inventory {
        graph,
        units,
        index,
        entries,
        lines,
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
    RustTargetResolution::try_new_indexed(snapshot, builder.finish()?, lines)
}
