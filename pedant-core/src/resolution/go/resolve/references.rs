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
use pedant_types::{ReferenceKind, ResolutionGap};

use crate::resolution::go::binding_fact::GoBindingRecord;
use crate::resolution::go::facts::GoSourceFacts;
use crate::resolution::go::import_fact::GoImportRecord;
use crate::resolution::go::reference_fact::GoReferenceRecord;
use crate::resolution::go::unit::GoResolutionUnit;

use super::answer::Answer;
use super::corpus::{Corpus, UnitSource, conditional};
use super::denotation::Denotation;
use super::dispatch;
use super::error::GoResolutionError;
use super::implementations::Implementations;
use super::imports::{FileImports, ImportTarget, target};
use super::index::{self, Index, Slot};
use super::lookup::{self, Outcome};
use super::methods::{self, Member};
use super::relations;
use super::scopes;
use super::types::{self, Site};

/// One file, as every classification below reads it.
struct FileSite<'a> {
    unit: usize,
    path: &'a Arc<str>,
    facts: &'a GoSourceFacts,
    imports: &'a FileImports<'a>,
    conditional: bool,
}

impl<'a> FileSite<'a> {
    /// Read one source of one package context.
    fn of(unit: usize, held: UnitSource<'a>) -> Self {
        Self {
            unit,
            path: held.path,
            facts: held.source.facts(),
            imports: held.imports,
            conditional: conditional(held.source),
        }
    }
}

/// Every reference one package context states: its sources' sites in source
/// order, then the structural relations its own types hold.
pub(super) fn of_unit(
    index: &Index,
    corpus: &Corpus<'_>,
    implementations: &Implementations,
    unit: (usize, &GoResolutionUnit),
) -> Result<Box<[Denotation]>, GoResolutionError> {
    let (position, held) = unit;
    let mut denoted = Vec::new();
    for source in corpus.sources_of(held)?.iter() {
        of_file(
            index,
            corpus,
            implementations,
            &FileSite::of(position, *source),
            &mut denoted,
        );
    }
    denoted.extend(relations::of_unit(index, implementations, position));
    Ok(denoted.into_boxed_slice())
}

/// Every reference one file states, drained into the context's own list: its
/// imports first, then its occurrences.
fn of_file(
    index: &Index,
    corpus: &Corpus<'_>,
    implementations: &Implementations,
    site: &FileSite<'_>,
    denoted: &mut Vec<Denotation>,
) {
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
    denoted.extend(imported.chain(occurrences));
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
        span: index::site(site.path, import.span()),
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
            let found = lookup::bare(index, (site.unit, site.imports), fact.name());
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
    let answer = from_outcome(lookup::bare(index, (site.unit, site.imports), fact.name()));
    Some(stated(
        index,
        site,
        fact,
        classified(index, answer, default),
    ))
}

/// A site written behind a qualifier: a package's member, or a member of the
/// value the qualifier names.
///
/// The qualifier's own binding is resolved once here and handed to whichever
/// branch reads it. Both branches ask the same lexical question — "does a
/// binding cover this name?" — and each answer costs a linear scan of the
/// file's bindings plus the scope chain it walks them against.
fn qualified(
    index: &Index,
    implementations: &Implementations,
    site: &FileSite<'_>,
    written: (&GoReferenceRecord, &str),
    default: ReferenceKind,
) -> Denotation {
    let (fact, qualifier) = written;
    let bound = binding_of(site, fact, qualifier);
    match package_target(site, bound, qualifier) {
        Some(package) => {
            let answer = from_outcome(lookup::qualified(index, package, fact.name()));
            stated(index, site, fact, classified(index, answer, default))
        }
        None => member(index, implementations, site, (fact, bound), default),
    }
}

/// The binding the receiver name inside one qualifier sees, when the qualifier
/// reads a name at all.
fn binding_of<'a>(
    site: &'a FileSite<'a>,
    fact: &GoReferenceRecord,
    qualifier: &str,
) -> Option<&'a GoBindingRecord> {
    let base = types::plain_name(qualifier)?;
    scopes::binding(site.facts, (fact.scope(), fact.span().start_byte()), base)
}

/// The package one qualifier binds, when an import binds it and no lexical
/// binding covers it.
fn package_target<'a>(
    site: &'a FileSite<'a>,
    bound: Option<&GoBindingRecord>,
    qualifier: &str,
) -> Option<ImportTarget<'a>> {
    match bound {
        Some(_) => None,
        None => site.imports.named(qualifier),
    }
}

/// A member of the value one qualifier names.
///
/// A receiver whose binding this tier cannot read a named type from is a
/// receiver form this tier does not resolve — an index expression, a field
/// selection, a result named through another file's imports, a qualifier no
/// import binds. None of those chooses its target at run time, so the gap says
/// the syntax is unsupported rather than that the call dispatches: a consumer
/// counting dynamic-dispatch sites over Go would otherwise count every one.
fn member(
    index: &Index,
    implementations: &Implementations,
    site: &FileSite<'_>,
    written: (&GoReferenceRecord, Option<&GoBindingRecord>),
    default: ReferenceKind,
) -> Denotation {
    let (fact, bound) = written;
    let receiver = bound.and_then(|bound| types::from_binding(index, receiver_site(site), bound));
    let Some(receiver) = receiver else {
        return stated(
            index,
            site,
            fact,
            Answer::refused(default, ResolutionGap::UnsupportedSyntax),
        );
    };
    let found = methods::promoted(index, receiver, fact.name());
    let answer = answered(index, implementations, (default, fact.name()), &found);
    stated(index, site, fact, answer)
}

/// What the members one selector reaches state.
///
/// A member several embedding paths reach at one depth is an ambiguous selector
/// — a Go program error — so it names its definitions as possible candidates
/// with the gap that says so, never as one resolved target.
fn answered(
    index: &Index,
    implementations: &Implementations,
    asked: (ReferenceKind, &str),
    found: &[Member],
) -> Answer {
    let (default, name) = asked;
    let slots: Box<[usize]> = found.iter().map(|member| member.slot).collect();
    match (
        slots.is_empty(),
        found.iter().any(|member| member.multiples),
    ) {
        (true, _) => Answer::refused(default, ResolutionGap::MissingDefinition),
        (false, true) => Answer::multiple(default, slots),
        (false, false) => dispatch::selected(index, implementations, (default, name), slots),
    }
}

/// Where one qualified site's receiver is read.
fn receiver_site<'a>(site: &'a FileSite<'a>) -> Site<'a> {
    Site {
        unit: site.unit,
        imports: site.imports,
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
        span: index::site(site.path, fact.span()),
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
