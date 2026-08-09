//! The definition edges a verified snapshot may consume.
//!
//! Nothing here carries a database value: every site is a snapshot unit, a
//! repository-relative path, and a zero-based line and UTF-8 byte column — the
//! same coordinates a resolution report states. The collection carries the
//! verified snapshot's fingerprint, so a report can never join edges taken
//! against another snapshot.
//!
//! A verified source that will not analyze, and a verified source that will not
//! state a coordinate, are refusals rather than empty answers. Tier 2 answers
//! for every verified source or for none: one source quietly contributing
//! nothing would leave a Tier 1 report wearing a Tier 2 label.

use std::collections::BTreeMap;
use std::sync::Arc;

use ra_ap_hir::Crate;
use ra_ap_ide::{Analysis, FileId};

use super::SemanticContext;
use super::snapshot::{SemanticSnapshotMismatch, VerifiedSnapshot, VerifiedSource, VerifiedUnit};
use super::targets::{EdgeSite, SemanticEdge};

/// Where one end of an edge sits, in the snapshot's own coordinates.
#[derive(Clone)]
pub(crate) struct SemanticSite {
    /// The snapshot-local unit index.
    pub(crate) unit: usize,
    /// The repository-relative, `/`-separated source.
    pub(crate) path: Arc<str>,
    /// The zero-based line.
    pub(crate) line: u32,
    /// The zero-based UTF-8 byte column.
    pub(crate) column: u32,
}

/// One reference and the definition a verified database proved it denotes.
pub(crate) struct SemanticDefinitionEdge {
    pub(crate) source: SemanticSite,
    pub(crate) target: SemanticSite,
    /// Whether the target is one member of a dispatch set rather than the one
    /// concrete definition the call reaches.
    pub(crate) enumerated: bool,
}

/// Every definition edge one verified snapshot's sources state.
pub(crate) struct SemanticDefinitionTargets {
    /// The snapshot identity these edges were taken against.
    pub(crate) fingerprint: [u8; 32],
    pub(crate) edges: Box<[SemanticDefinitionEdge]>,
}

/// The database identity of one verified source: the crate that answers for the
/// unit holding it, and the file itself.
///
/// `ra_ap_hir::Crate` states no order, so the salsa input it wraps is what an
/// ordered map is keyed on.
type SourceKey = (ra_ap_ide::Crate, FileId);

/// Every verified source, addressed the way an edge names it, holding the unit
/// that owns it and the path the snapshot calls it by.
type SourceIndex = BTreeMap<SourceKey, (usize, Arc<str>)>;

fn source_key(krate: Crate, file: FileId) -> SourceKey {
    (krate.base(), file)
}

/// Where every verified source sits, and the one database snapshot every
/// coordinate of one query is read through.
///
/// Each file's line index is a memoized query, so asking for it again costs a
/// lookup rather than another pass over the text. Each source's unit and
/// snapshot path are taken once from the snapshot the database was already
/// proved to hold, so recovering them costs a search rather than a scan of
/// every unit and every source it holds.
struct Projection<'a> {
    context: &'a SemanticContext,
    analysis: Analysis,
    sources: SourceIndex,
}

/// Ask every verified source for the definitions its references denote.
pub(super) fn collect(
    context: &SemanticContext,
    verified: &VerifiedSnapshot,
) -> Result<SemanticDefinitionTargets, SemanticSnapshotMismatch> {
    let projection = Projection {
        context,
        analysis: context.host.analysis(),
        sources: source_index(context, verified)?,
    };
    let mut edges: Vec<SemanticDefinitionEdge> = Vec::new();
    for unit in verified.units.iter().enumerate() {
        projection.add_unit(unit, &mut edges)?;
    }
    Ok(SemanticDefinitionTargets {
        fingerprint: verified.fingerprint,
        edges: edges.into_boxed_slice(),
    })
}

/// The unit and snapshot path of every verified source, taken once.
fn source_index(
    context: &SemanticContext,
    verified: &VerifiedSnapshot,
) -> Result<SourceIndex, SemanticSnapshotMismatch> {
    let mut sources = SourceIndex::new();
    for unit in verified.units.iter().enumerate() {
        add_unit_sources(context, unit, &mut sources)?;
    }
    Ok(sources)
}

fn add_unit_sources(
    context: &SemanticContext,
    unit: (usize, &VerifiedUnit),
    sources: &mut SourceIndex,
) -> Result<(), SemanticSnapshotMismatch> {
    let (index, verified_unit) = unit;
    for source in &verified_unit.sources {
        let Some(file) = context.file_id(&source.absolute) else {
            return Err(SemanticSnapshotMismatch::SourceAbsent {
                path: Box::from(&*source.path),
            });
        };
        sources.insert(
            source_key(verified_unit.krate(), file),
            (index, Arc::clone(&source.path)),
        );
    }
    Ok(())
}

impl Projection<'_> {
    fn add_unit(
        &self,
        unit: (usize, &VerifiedUnit),
        edges: &mut Vec<SemanticDefinitionEdge>,
    ) -> Result<(), SemanticSnapshotMismatch> {
        let (_, verified_unit) = unit;
        for source in &verified_unit.sources {
            self.add_source(unit, source, edges)?;
        }
        Ok(())
    }

    /// Every edge one verified source states under one verified unit.
    ///
    /// Only the edges the database resolved in that unit's own crate are read,
    /// so one physical source instantiated under two Cargo targets never
    /// answers for the wrong one.
    fn add_source(
        &self,
        unit: (usize, &VerifiedUnit),
        source: &VerifiedSource,
        edges: &mut Vec<SemanticDefinitionEdge>,
    ) -> Result<(), SemanticSnapshotMismatch> {
        let (index, verified_unit) = unit;
        let path = &source.path;
        let Some(analysis) = self.context.analyze_snapshot_file(path, &source.absolute) else {
            return Err(SemanticSnapshotMismatch::SourceAnalysis {
                path: Box::from(&**path),
            });
        };
        let stated = analysis
            .semantic_edges()
            .iter()
            .filter(|edge| edge.source.krate == verified_unit.krate());
        for edge in stated {
            edges.extend(self.project((index, path), edge)?);
        }
        Ok(())
    }

    /// One database edge in snapshot coordinates, when its target belongs to
    /// the verified snapshot.
    fn project(
        &self,
        source: (usize, &Arc<str>),
        edge: &SemanticEdge,
    ) -> Result<Option<SemanticDefinitionEdge>, SemanticSnapshotMismatch> {
        let (unit, path) = source;
        let Some(target) = self.site(edge.target)? else {
            return Ok(None);
        };
        let (line, column) = self.position(path, edge.source)?;
        Ok(Some(SemanticDefinitionEdge {
            source: SemanticSite {
                unit,
                path: Arc::clone(path),
                line,
                column,
            },
            target,
            enumerated: edge.enumerated,
        }))
    }

    /// Where one end of an edge sits, when the snapshot holds that source.
    ///
    /// A definition outside the snapshot — anything in a dependency or the
    /// sysroot — is absent rather than refused: the snapshot never claimed it.
    fn site(&self, site: EdgeSite) -> Result<Option<SemanticSite>, SemanticSnapshotMismatch> {
        let Some((unit, path)) = self.sources.get(&source_key(site.krate, site.file)) else {
            return Ok(None);
        };
        let (line, column) = self.position(path, site)?;
        Ok(Some(SemanticSite {
            unit: *unit,
            path: Arc::clone(path),
            line,
            column,
        }))
    }

    /// The zero-based line and UTF-8 byte column one offset sits at.
    ///
    /// The site names a source the snapshot holds, so a database that will not
    /// state that source's line index, and an offset the source does not
    /// contain, are differences rather than missing edges.
    fn position(&self, path: &str, site: EdgeSite) -> Result<(u32, u32), SemanticSnapshotMismatch> {
        let found = self
            .analysis
            .file_line_index(site.file)
            .ok()
            .and_then(|index| index.try_line_col(site.offset));
        match found {
            Some(position) => Ok((position.line, position.col)),
            None => Err(SemanticSnapshotMismatch::SourceCoordinates {
                path: Box::from(path),
            }),
        }
    }
}
