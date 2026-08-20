//! Every reference one Go package context states, and what each one denotes.
//!
//! A site is classified from the shape its source wrote and the scope it was
//! written in. An occurrence a lexical binding covers names that binding, which
//! is not a report entity, so it states no reference at all; every other
//! occurrence states one, with the definitions it names or the gap that stopped
//! it.

use std::sync::Arc;

use pedant_syntax::go::GoReferenceKind;
use pedant_types::{ReferenceKind, ResolutionGap, SourcePosition, SourceSpan};

use crate::resolution::go::facts::GoSourceFacts;
use crate::resolution::go::import_fact::GoImportRecord;
use crate::resolution::go::reference_fact::GoReferenceRecord;
use crate::resolution::go::unit::GoResolutionUnit;

use super::corpus::{Corpus, conditional};
use super::imports::{FileImports, ImportTarget, target};
use super::index::{Index, Slot};
use super::lookup::{self, Outcome};
use super::methods;
use super::scopes;
use super::types::{self, Site};

/// One reference site, with what it names and why that answer is incomplete.
pub(super) struct Denotation {
    pub(super) kind: ReferenceKind,
    pub(super) text: Arc<str>,
    pub(super) span: SourceSpan,
    pub(super) enclosing: Option<usize>,
    pub(super) candidates: Box<[usize]>,
    pub(super) gap: Option<ResolutionGap>,
    /// Whether an unevaluated build predicate governs the source stating it.
    pub(super) conditional: bool,
}

/// One file, as every classification below reads it.
struct FileSite<'a> {
    unit: usize,
    path: &'a Arc<str>,
    facts: &'a GoSourceFacts,
    imports: FileImports<'a>,
    conditional: bool,
}

/// Every reference one package context states, in source order per source.
pub(super) fn of_unit(
    index: &Index,
    corpus: &Corpus<'_>,
    stated: (usize, &GoResolutionUnit),
) -> Box<[Denotation]> {
    let (position, unit) = stated;
    let mut stated = Vec::new();
    for path in unit.sources() {
        let Some(source) = corpus.source(path) else {
            continue;
        };
        let site = FileSite {
            unit: position,
            path,
            facts: source.facts(),
            imports: FileImports::of(corpus, source.facts()),
            conditional: conditional(source),
        };
        stated.extend(of_file(index, corpus, &site));
    }
    stated.into_boxed_slice()
}

/// Every reference one file states: its imports first, then its occurrences.
fn of_file(index: &Index, corpus: &Corpus<'_>, site: &FileSite<'_>) -> Vec<Denotation> {
    let imported = site
        .facts
        .imports()
        .iter()
        .map(|import| imported(index, corpus, site, import));
    let occurrences = site
        .facts
        .references()
        .iter()
        .filter_map(|fact| denote(index, site, fact));
    imported.chain(occurrences).collect()
}

/// One import specification, which names the package it imports.
fn imported(
    index: &Index,
    corpus: &Corpus<'_>,
    site: &FileSite<'_>,
    import: &GoImportRecord,
) -> Denotation {
    let found = target(corpus, import);
    let package = found
        .unit
        .and_then(|unit| index.unit(unit))
        .map(|tables| tables.package);
    Denotation {
        kind: ReferenceKind::Import,
        text: Arc::from(import.path()),
        span: span_of(site.path, import.span()),
        enclosing: None,
        candidates: package.into_iter().collect(),
        gap: package
            .is_none()
            .then_some(ResolutionGap::ExternalDefinition),
        conditional: site.conditional,
    }
}

/// What one occurrence denotes, or nothing when a lexical binding covers it.
fn denote(index: &Index, site: &FileSite<'_>, fact: &GoReferenceRecord) -> Option<Denotation> {
    match (fact.kind(), fact.qualifier()) {
        (GoReferenceKind::Call, _) => Some(bare_call(index, site, fact)),
        (GoReferenceKind::QualifiedCall, Some(written)) => {
            Some(qualified(index, site, (fact, written), ReferenceKind::Call))
        }
        (GoReferenceKind::Selector, Some(written)) => Some(qualified(
            index,
            site,
            (fact, written),
            ReferenceKind::Value,
        )),
        (GoReferenceKind::QualifiedCall | GoReferenceKind::Selector, None) => None,
        (GoReferenceKind::Type, Some(written)) => {
            Some(qualified(index, site, (fact, written), ReferenceKind::Type))
        }
        (GoReferenceKind::Type, None) => plain(index, site, fact, ReferenceKind::Type),
        (GoReferenceKind::Value, _) => plain(index, site, fact, ReferenceKind::Value),
    }
}

/// A call whose callee is a bare name.
///
/// A callee a binding covers is a value chosen at run time, so it names no
/// static target; a callee naming a type converts rather than calls.
fn bare_call(index: &Index, site: &FileSite<'_>, fact: &GoReferenceRecord) -> Denotation {
    match covered(site, fact, fact.name()) {
        true => stated(
            index,
            site,
            fact,
            refused(ReferenceKind::Call, ResolutionGap::DynamicDispatch),
        ),
        false => {
            let found = lookup::bare(index, (site.unit, &site.imports), fact.name());
            stated(
                index,
                site,
                fact,
                classified(index, from_outcome(found), ReferenceKind::Call),
            )
        }
    }
}

/// A bare name outside call position: a type or a value the file can see.
///
/// A name a lexical binding covers names that binding, and a name an import
/// binds is the qualifier of the selector it stands in — the qualified site
/// beside it already states that relation, so stating it again would count
/// every package-qualified reference twice. Neither is a report reference.
fn plain(
    index: &Index,
    site: &FileSite<'_>,
    fact: &GoReferenceRecord,
    default: ReferenceKind,
) -> Option<Denotation> {
    if covered(site, fact, fact.name()) || site.imports.named(fact.name()).is_some() {
        return None;
    }
    let answer = from_outcome(lookup::bare(index, (site.unit, &site.imports), fact.name()));
    Some(stated(
        index,
        site,
        fact,
        classified(index, answer, default),
    ))
}

/// A site written behind a qualifier: a package's member, or a member of the
/// value the qualifier names.
fn qualified(
    index: &Index,
    site: &FileSite<'_>,
    written: (&GoReferenceRecord, &str),
    default: ReferenceKind,
) -> Denotation {
    let (fact, qualifier) = written;
    match package_target(site, fact, qualifier) {
        Some(package) => {
            let answer = from_outcome(lookup::qualified(index, package, fact.name()));
            stated(index, site, fact, classified(index, answer, default))
        }
        None => member(index, site, written, default),
    }
}

/// The package one qualifier binds, when an import binds it and no lexical
/// binding covers it.
fn package_target(
    site: &FileSite<'_>,
    fact: &GoReferenceRecord,
    qualifier: &str,
) -> Option<ImportTarget> {
    match covered(site, fact, qualifier) {
        true => None,
        false => site.imports.named(qualifier),
    }
}

/// A member of the value one qualifier names.
fn member(
    index: &Index,
    site: &FileSite<'_>,
    written: (&GoReferenceRecord, &str),
    default: ReferenceKind,
) -> Denotation {
    let (fact, qualifier) = written;
    let receiver = types::concrete(index, receiver_site(site, fact), qualifier);
    let Some(receiver) = receiver else {
        return stated(
            index,
            site,
            fact,
            refused(default, ResolutionGap::DynamicDispatch),
        );
    };
    let found = methods::members(index, receiver, fact.name());
    match found.is_empty() {
        true => stated(
            index,
            site,
            fact,
            refused(default, ResolutionGap::MissingDefinition),
        ),
        false => stated(index, site, fact, (default, found, None)),
    }
}

/// Where one qualified site's receiver is read.
fn receiver_site<'a>(site: &'a FileSite<'a>, fact: &GoReferenceRecord) -> Site<'a> {
    Site {
        unit: site.unit,
        facts: site.facts,
        imports: &site.imports,
        scope: fact.scope(),
        offset: fact.span().start_byte(),
    }
}

/// Whether a lexical binding covers one name at one occurrence.
fn covered(site: &FileSite<'_>, fact: &GoReferenceRecord, name: &str) -> bool {
    scopes::binding(site.facts, (fact.scope(), fact.span().start_byte()), name).is_some()
}

/// What one lookup outcome states: the definitions found, or the gap instead.
fn from_outcome(outcome: Outcome) -> (Box<[usize]>, Option<ResolutionGap>) {
    match outcome {
        Outcome::Found(found) => (found, None),
        Outcome::External => (Box::from([]), Some(ResolutionGap::ExternalDefinition)),
        Outcome::Missing => (Box::from([]), Some(ResolutionGap::MissingDefinition)),
    }
}

/// One site that names nothing, and the gap that says why.
fn refused(
    kind: ReferenceKind,
    gap: ResolutionGap,
) -> (ReferenceKind, Box<[usize]>, Option<ResolutionGap>) {
    (kind, Box::from([]), Some(gap))
}

/// The kind a site takes: a type whenever the definitions it names are types,
/// and the shape's own kind otherwise.
///
/// This is what keeps a conversion from becoming a call: `Label(raw)` and
/// `pkg.Label(raw)` are written exactly as calls are, and only the corpus can
/// say that `Label` is a type.
fn classified(
    index: &Index,
    answer: (Box<[usize]>, Option<ResolutionGap>),
    default: ReferenceKind,
) -> (ReferenceKind, Box<[usize]>, Option<ResolutionGap>) {
    let (found, gap) = answer;
    let converts = found
        .iter()
        .any(|slot| index.slot(*slot).is_some_and(Slot::is_type));
    let kind = match converts {
        true => ReferenceKind::Type,
        false => default,
    };
    (kind, found, gap)
}

/// One stated reference over the site its fact names.
fn stated(
    index: &Index,
    site: &FileSite<'_>,
    fact: &GoReferenceRecord,
    answer: (ReferenceKind, Box<[usize]>, Option<ResolutionGap>),
) -> Denotation {
    let (kind, candidates, gap) = answer;
    Denotation {
        kind,
        text: Arc::from(fact.name()),
        span: span_of(site.path, fact.span()),
        enclosing: fact
            .declaration()
            .and_then(|declaration| enclosing(index, site, declaration)),
        candidates,
        gap,
        conditional: site.conditional,
    }
}

/// The definition whose text holds one site.
///
/// The fact names the declaration it sits inside by position in its own
/// source, and the definition stage recorded which report definition each of
/// those became, so the answer is a join rather than a second containment walk.
fn enclosing(index: &Index, site: &FileSite<'_>, declaration: u32) -> Option<usize> {
    index.unit(site.unit)?.declared(site.path, declaration)
}

/// The report span one grammar span occupies in its own file.
fn span_of(path: &Arc<str>, span: pedant_syntax::go::GoFactSpan) -> SourceSpan {
    SourceSpan::new(
        Arc::clone(path),
        SourcePosition::new(line(span.start_line()), line(span.start_column())),
        SourcePosition::new(line(span.end_line()), line(span.end_column())),
    )
}

fn line(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
