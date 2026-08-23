//! Prove every site a report states exists in the exact sources it describes.
//!
//! A report states zero-based lines and zero-based UTF-8 byte columns over
//! snapshotted bytes, and that is the same question whichever language produced
//! it. One owner, because a copy per language is one implementation a later fix
//! reaches only half of: each binding hands over the texts its own snapshot
//! holds and maps the refusal into its own typed error.

use std::collections::BTreeMap;

use pedant_types::{ResolutionReport, SourceSpan, SymbolDefinition, SymbolReference};

use crate::resolution::line_index::LineIndex;

/// Every snapshotted source text a report may name, keyed by its
/// repository-relative path.
pub(crate) type SourceTexts<'snapshot> = BTreeMap<&'snapshot str, &'snapshot str>;

/// Why one stated site does not describe the sources it names.
///
/// Crate-private and never published: each language's binding maps it into the
/// typed error its own seam refuses through, so a caller still reads which
/// stage failed rather than one shared cause every stage returns.
pub(crate) enum SiteError {
    /// A site names a file the snapshot does not hold.
    UnknownFile {
        /// The repository-relative path the site named.
        file: Box<str>,
    },
    /// A site's coordinate does not exist in the exact snapshotted source.
    InvalidCoordinate {
        /// The source the coordinate claimed to sit in.
        file: Box<str>,
        /// The zero-based line.
        line: u32,
        /// The zero-based UTF-8 byte column.
        column: u32,
    },
}

/// Prove every stated coordinate against the exact snapshotted source.
///
/// Each source is indexed once rather than once per site: a report states many
/// thousands of sites over the same files, and building the line table per site
/// rescanned whole sources for coordinates derived from those same tables.
pub(crate) fn validate_sites(
    sources: &SourceTexts<'_>,
    report: &ResolutionReport,
) -> Result<(), SiteError> {
    let lines = indexed(sources);
    for definition in report.definitions() {
        validate_span(sources, &lines, SymbolDefinition::span(definition))?;
    }
    for reference in report.references() {
        validate_span(sources, &lines, SymbolReference::span(reference))?;
    }
    Ok(())
}

fn indexed<'snapshot>(sources: &SourceTexts<'snapshot>) -> BTreeMap<&'snapshot str, LineIndex> {
    sources
        .iter()
        .map(|(path, text)| (*path, LineIndex::new(text)))
        .collect()
}

fn validate_span(
    sources: &SourceTexts<'_>,
    lines: &BTreeMap<&str, LineIndex>,
    span: &SourceSpan,
) -> Result<(), SiteError> {
    let stated = sources
        .get(span.file())
        .zip(lines.get(span.file()))
        .ok_or_else(|| SiteError::UnknownFile {
            file: Box::from(span.file()),
        })?;
    let (text, index) = stated;
    for at in [span.start(), span.end()] {
        if !index.holds(text, at.line(), at.column()) {
            return Err(SiteError::InvalidCoordinate {
                file: Box::from(span.file()),
                line: at.line(),
                column: at.column(),
            });
        }
    }
    Ok(())
}
