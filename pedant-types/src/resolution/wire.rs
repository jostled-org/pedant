//! Incremental report decoding through the same validator `finish` uses.

use std::fmt;
use std::sync::Arc;

use rustc_hash::FxHashSet;
use serde::de::{DeserializeSeed, Error as DeserializeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::builder::ResolutionReportLimits;
use super::definition::SymbolDefinition;
use super::error::ReportCollection;
use super::record::ResolutionRecord;
use super::reference::SymbolReference;
use super::report::{ResolutionReport, ResolutionTier};
use super::span::SourceSpan;
use super::unit::ResolutionUnit;
use super::validate::validate;
use super::wire_field::ReportField;
use super::wire_sequence::LimitedSequenceDecoder;

const REPORT_FIELDS: &[&str] = &["tier", "units", "definitions", "references", "resolutions"];

/// Deserialize one validated report without retaining entries past `limits`.
pub(super) fn deserialize_with_limits<'de, D>(
    deserializer: D,
    limits: ResolutionReportLimits,
) -> Result<ResolutionReport, D::Error>
where
    D: Deserializer<'de>,
{
    WireReportDecoder { limits }.deserialize(deserializer)
}

impl<'de> Deserialize<'de> for ResolutionReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_with_limits(deserializer, ResolutionReportLimits::default())
    }
}

/// Private seed and visitor carrying limits through the report map.
struct WireReportDecoder {
    limits: ResolutionReportLimits,
}

impl<'de> DeserializeSeed<'de> for WireReportDecoder {
    type Value = ResolutionReport;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct("ResolutionReport", REPORT_FIELDS, self)
    }
}

impl<'de> Visitor<'de> for WireReportDecoder {
    type Value = ResolutionReport;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a resolution report")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let tier = require_next(&mut sequence, "tier")?;
        let units = require_next_seed(
            &mut sequence,
            LimitedSequenceDecoder::new(self.limits.max_units, ReportCollection::Units),
            "units",
        )?;
        let definitions = require_next_seed(
            &mut sequence,
            LimitedSequenceDecoder::new(self.limits.max_definitions, ReportCollection::Definitions),
            "definitions",
        )?;
        let references = require_next_seed(
            &mut sequence,
            LimitedSequenceDecoder::new(self.limits.max_references, ReportCollection::References),
            "references",
        )?;
        let resolutions = require_next_seed(
            &mut sequence,
            LimitedSequenceDecoder::new(self.limits.max_references, ReportCollection::Resolutions),
            "resolutions",
        )?;
        finish_report(tier, units, definitions, references, resolutions)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut tier = None;
        let mut units = None;
        let mut definitions = None;
        let mut references = None;
        let mut resolutions = None;

        while let Some(field) = map.next_key()? {
            match field {
                ReportField::Tier => {
                    reject_duplicate(&tier, "tier")?;
                    tier = Some(map.next_value()?);
                }
                ReportField::Units => {
                    reject_duplicate(&units, "units")?;
                    units = Some(map.next_value_seed(LimitedSequenceDecoder::new(
                        self.limits.max_units,
                        ReportCollection::Units,
                    ))?);
                }
                ReportField::Definitions => {
                    reject_duplicate(&definitions, "definitions")?;
                    definitions = Some(map.next_value_seed(LimitedSequenceDecoder::new(
                        self.limits.max_definitions,
                        ReportCollection::Definitions,
                    ))?);
                }
                ReportField::References => {
                    reject_duplicate(&references, "references")?;
                    references = Some(map.next_value_seed(LimitedSequenceDecoder::new(
                        self.limits.max_references,
                        ReportCollection::References,
                    ))?);
                }
                ReportField::Resolutions => {
                    reject_duplicate(&resolutions, "resolutions")?;
                    resolutions = Some(map.next_value_seed(LimitedSequenceDecoder::new(
                        self.limits.max_references,
                        ReportCollection::Resolutions,
                    ))?);
                }
            }
        }

        finish_report(
            require_field(tier, "tier")?,
            require_field(units, "units")?,
            require_field(definitions, "definitions")?,
            require_field(references, "references")?,
            require_field(resolutions, "resolutions")?,
        )
    }
}

fn finish_report<E>(
    tier: ResolutionTier,
    units: Box<[ResolutionUnit]>,
    mut definitions: Box<[SymbolDefinition]>,
    mut references: Box<[SymbolReference]>,
    resolutions: Box<[ResolutionRecord]>,
) -> Result<ResolutionReport, E>
where
    E: DeserializeError,
{
    intern_paths(&mut definitions, &mut references);
    let report = ResolutionReport::new(tier, units, definitions, references, resolutions);
    validate(&report).map_err(E::custom)?;
    Ok(report)
}

fn require_next<'de, A, T>(sequence: &mut A, name: &'static str) -> Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: Deserialize<'de>,
{
    sequence
        .next_element()?
        .ok_or_else(|| A::Error::missing_field(name))
}

fn require_next_seed<'de, A, S>(
    sequence: &mut A,
    seed: S,
    name: &'static str,
) -> Result<S::Value, A::Error>
where
    A: SeqAccess<'de>,
    S: DeserializeSeed<'de>,
{
    sequence
        .next_element_seed(seed)?
        .ok_or_else(|| A::Error::missing_field(name))
}

fn reject_duplicate<T, E>(field: &Option<T>, name: &'static str) -> Result<(), E>
where
    E: DeserializeError,
{
    match field.is_some() {
        true => Err(E::duplicate_field(name)),
        false => Ok(()),
    }
}

fn require_field<T, E>(field: Option<T>, name: &'static str) -> Result<T, E>
where
    E: DeserializeError,
{
    field.ok_or_else(|| E::missing_field(name))
}

/// Point every span that names one path at one path value.
///
/// Serde's `rc` support allocates on the way in rather than restoring the
/// sharing the report was serialized from, so a decoded report would otherwise
/// hold one copy of a file name per site in it. One pass, before validation, so
/// no consumer ever sees the unshared shape.
fn intern_paths(definitions: &mut [SymbolDefinition], references: &mut [SymbolReference]) {
    let mut paths: FxHashSet<Arc<str>> = FxHashSet::default();
    for definition in definitions {
        intern(&mut paths, definition.span_mut());
    }
    for reference in references {
        intern(&mut paths, reference.span_mut());
    }
}

fn intern(paths: &mut FxHashSet<Arc<str>>, span: &mut SourceSpan) {
    let canonical = paths.get(span.file()).map(Arc::clone);
    match canonical {
        Some(canonical) => span.adopt_file(canonical),
        None => {
            paths.insert(Arc::clone(span.shared_file()));
        }
    }
}
