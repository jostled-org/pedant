//! Every reference one Go package context states, and what each one denotes.
//!
//! A site is classified from the shape its source wrote and the scope it was
//! written in. An occurrence a lexical binding covers names that binding, which
//! is not a report entity, so it states no reference at all; every other
//! occurrence states one, with the definitions it names or the gap that stopped
//! it.
//!
//! A package context also states the structural relations its own concrete
//! types hold. Those sites are written at the type names rather than at an
//! occurrence, so they are gathered once per context after its sources.

use std::sync::Arc;

use pedant_syntax::go::GoReferenceKind;
use pedant_types::{ReferenceKind, ResolutionGap, SourcePosition, SourceSpan};

use crate::resolution::go::facts::GoSourceFacts;
use crate::resolution::go::import_fact::GoImportRecord;
use crate::resolution::go::reference_fact::GoReferenceRecord;
use crate::resolution::go::unit::GoResolutionUnit;

use super::answer::Answer;
use super::corpus::{Corpus, conditional};
use super::denotation::Denotation;
use super::dispatch;
use super::implementations::Implementations;
use super::imports::{FileImports, ImportTarget, target};
use super::index::{Index, Slot};
use super::lookup::{self, Outcome};
use super::methods;
use super::relations;
use super::scopes;
use super::types::{self, Site};

/// One file, as every classification below reads it.
struct FileSite<'a> {
    unit: usize,
    path: &'a Arc<str>,
    facts: &'a GoSourceFacts,
    imports: FileImports<'a>,
    conditional: bool,
}

/// Every reference one package context states: its sources' sites in source
/// order, then the structural relations its own types hold.
pub(super) fn of_unit(
    index: &Index,
    corpus: &Corpus<'_>,
    implementations: &Implementations,
    unit: (usize, &GoResolutionUnit),
) -> Box<[Denotation]> {
    let (position, held) = unit;
    let mut denoted = Vec::new();
    for path in held.sources() {
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
        denoted.extend(of_file(index, corpus, implementations, &site));
    }
    denoted.extend(relations::of_unit(index, implementations, position));
    denoted.into_boxed_slice()
}

/// Every reference one file states: its imports first, then its occurrences.
fn of_file(
    index: &Index,
    corpus: &Corpus<'_>,
    implementations: &Implementations,
    site: &FileSite<'_>,
) -> Vec<Denotation> {
    let imported = site
        .facts
        .imports()
        .iter()
        .map(|import| imported(index, corpus, site, import));
    let occurrences = site
        .facts
        .references()
        .iter()
        .filter_map(|fact| denote(index, implementations, site, fact));
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
        possible_only: false,
    }
}

/// What one occurrence denotes, or nothing when a lexical binding covers it.
fn denote(
    index: &Index,
    implementations: &Implementations,
    site: &FileSite<'_>,
    fact: &GoReferenceRecord,
) -> Option<Denotation> {
    match (fact.kind(), fact.qualifier()) {
        (GoReferenceKind::Call, _) => Some(bare_call(index, site, fact)),
        (GoReferenceKind::QualifiedCall, Some(written)) => Some(qualified(
            index,
            implementations,
            site,
            (fact, written),
            ReferenceKind::Call,
        )),
        (GoReferenceKind::Selector, Some(written)) => Some(qualified(
            index,
            implementations,
            site,
            (fact, written),
            ReferenceKind::Value,
        )),
        (GoReferenceKind::QualifiedCall | GoReferenceKind::Selector, None) => None,
        (GoReferenceKind::Type, Some(written)) => Some(qualified(
            index,
            implementations,
            site,
            (fact, written),
            ReferenceKind::Type,
        )),
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
            Answer::refused(ReferenceKind::Call, ResolutionGap::DynamicDispatch),
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
    implementations: &Implementations,
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
        None => member(index, implementations, site, written, default),
    }
}

/// The package one qualifier binds, when an import binds it and no lexical
/// binding covers it.
fn package_target<'a>(
    site: &'a FileSite<'a>,
    fact: &GoReferenceRecord,
    qualifier: &str,
) -> Option<ImportTarget<'a>> {
    match covered(site, fact, qualifier) {
        true => None,
        false => site.imports.named(qualifier),
    }
}

/// A member of the value one qualifier names.
fn member(
    index: &Index,
    implementations: &Implementations,
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
            Answer::refused(default, ResolutionGap::DynamicDispatch),
        );
    };
    let found = methods::members(index, receiver, fact.name());
    let answer = match found.is_empty() {
        true => Answer::refused(default, ResolutionGap::MissingDefinition),
        false => dispatch::selected(index, implementations, (default, fact.name()), found),
    };
    stated(index, site, fact, answer)
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
) -> Answer {
    let (found, gap) = answer;
    let converts = found
        .iter()
        .any(|slot| index.slot(*slot).is_some_and(Slot::is_type));
    let kind = match converts {
        true => ReferenceKind::Type,
        false => default,
    };
    Answer::found(kind, found, gap)
}

/// One stated reference over the site its fact names.
fn stated(
    index: &Index,
    site: &FileSite<'_>,
    fact: &GoReferenceRecord,
    answer: Answer,
) -> Denotation {
    Denotation {
        kind: answer.kind,
        text: Arc::from(fact.name()),
        span: span_of(site.path, fact.span()),
        enclosing: fact
            .declaration()
            .and_then(|declaration| enclosing(index, site, declaration)),
        candidates: answer.candidates,
        gap: answer.gap,
        conditional: site.conditional,
        possible_only: answer.possible_only,
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
