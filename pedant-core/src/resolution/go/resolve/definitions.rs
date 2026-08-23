//! The definitions one Go package context declares, stated once into the
//! report and once into the lookup index.
//!
//! Go writes a method's declaration at package scope, but the method belongs to
//! its receiver's named type; a field belongs to its struct and an interface
//! method to its interface. The report states that logical ownership rather
//! than the file layout, so a type declared in one source owns a method
//! declared in another.

use std::sync::Arc;

use pedant_syntax::go::GoDeclarationKind;
use pedant_types::{Language, ResolutionReportBuilder, SourceSpan, SymbolKind};

use crate::resolution::go::binding_fact::GoBindingRecord;
use crate::resolution::go::declaration_fact::GoDeclarationRecord;
use crate::resolution::go::facts::GoSourceFacts;
use crate::resolution::go::unit::GoResolutionUnit;
use crate::resolution::identity::{index_of, position};

use super::corpus::{Corpus, UnitSource, conditional};
use super::error::GoResolutionError;
use super::index::{self, EmbeddedType, Embedding, Index, Slot, TypeName, UnitIndex};
use super::lookup::{self, Outcome};
use super::target::unit_key;
use super::types;

/// One source of one package context, as every stage below reads it.
#[derive(Clone, Copy)]
struct Site<'a> {
    /// The package context whose tables record what the source declares.
    unit: usize,
    /// The source itself, joined to the names its own imports bind.
    held: UnitSource<'a>,
}

/// State every unit, every package, and every declaration those packages hold.
pub(super) fn state(
    builder: &mut ResolutionReportBuilder,
    corpus: &Corpus<'_>,
) -> Result<Index, GoResolutionError> {
    let mut index = Index::default();
    for (position, unit) in corpus.units().iter().enumerate() {
        let opened = open_unit(builder, &mut index, corpus, (position, unit))?;
        index.open(opened);
    }
    for (position, unit) in corpus.units().iter().enumerate() {
        state_members(builder, &mut index, corpus, (position, unit))?;
    }
    for (position, unit) in corpus.units().iter().enumerate() {
        state_embeddings(&mut index, corpus, (position, unit))?;
    }
    for (position, unit) in corpus.units().iter().enumerate() {
        state_methods(builder, &mut index, corpus, (position, unit))?;
    }
    Ok(index)
}

/// State one unit and the single package definition it compiles into.
fn open_unit(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    corpus: &Corpus<'_>,
    stated: (usize, &GoResolutionUnit),
) -> Result<UnitIndex, GoResolutionError> {
    let (position, unit) = stated;
    let handle = builder.add_unit(Language::Go, unit_key(unit), Arc::from(unit.import_path()))?;
    let span = package_span(corpus, unit)?;
    let name: Arc<str> = Arc::from(unit.package_name());
    let slot = index.push(Slot {
        handle: builder.add_definition(
            &handle,
            SymbolKind::Package,
            Arc::clone(&name),
            span.clone(),
            None,
        )?,
        kind: SymbolKind::Package,
        declared: None,
        unit: position,
        name,
        site: span,
        holder: None,
        conditional: false,
        pointer_receiver: false,
        general_terms: false,
        result: None,
    });
    Ok(UnitIndex::new(handle, slot))
}

/// Where one unit's package clause is written.
///
/// The deterministic first source states it: a unit's sources are sorted, and
/// every source of a package repeats the same clause, so the first one is the
/// stable site. A unit whose first source states no clause cannot exist — the
/// snapshot refuses a source without one — and is refused again rather than
/// given a fabricated span.
fn package_span(
    corpus: &Corpus<'_>,
    unit: &GoResolutionUnit,
) -> Result<SourceSpan, GoResolutionError> {
    let held = corpus.sources_of(unit)?;
    let stated = held
        .first()
        .and_then(|source| Some((source.path, source.source.facts().package_span()?)));
    let (path, span) = stated.ok_or_else(|| GoResolutionError::UnitMapping {
        unit: unit.id().index(),
        reason: Box::from("no source of this package context states a package clause"),
    })?;
    Ok(index::site(path, span))
}

/// Every declaration one source writes, with the position it took in that
/// source's own inventory.
fn declarations(held: UnitSource<'_>) -> impl Iterator<Item = (u32, &GoDeclarationRecord)> {
    held.source
        .facts()
        .declarations()
        .iter()
        .enumerate()
        .map(|(ordinal, record)| (position(ordinal), record))
}

/// State every declaration one unit holds except its methods.
fn state_members(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    corpus: &Corpus<'_>,
    stated: (usize, &GoResolutionUnit),
) -> Result<(), GoResolutionError> {
    let (unit, held) = stated;
    for source in corpus.sources_of(held)?.iter() {
        state_source_members(
            builder,
            index,
            Site {
                unit,
                held: *source,
            },
        )?;
    }
    Ok(())
}

/// State every non-method declaration one source holds, in source order.
fn state_source_members(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    site: Site<'_>,
) -> Result<(), GoResolutionError> {
    let members = declarations(site.held).filter(|(_, record)| !is_method(record));
    for declared in members {
        state_member(builder, index, site, declared)?;
    }
    Ok(())
}

/// Whether one declaration is a method a named type receives.
fn is_method(record: &GoDeclarationRecord) -> bool {
    record.kind() == GoDeclarationKind::Method
}

/// State one non-method declaration, and record what it holds.
fn state_member(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    site: Site<'_>,
    declared: (u32, &GoDeclarationRecord),
) -> Result<(), GoResolutionError> {
    let (_, record) = declared;
    let parent = member_parent(index, site, record);
    let slot = state_definition(builder, index, site, declared, parent)?;
    record_membership(index, site, (record, slot))
}

/// The definition a non-method declaration is a child of.
fn member_parent(index: &Index, site: Site<'_>, record: &GoDeclarationRecord) -> Option<usize> {
    let unit = index.unit(site.unit)?;
    match record.parent() {
        Some(parent) => unit.declared(site.held.path, parent),
        None => Some(unit.package),
    }
}

/// Record what one stated declaration contributes to lookup.
fn record_membership(
    index: &mut Index,
    site: Site<'_>,
    stated: (&GoDeclarationRecord, usize),
) -> Result<(), GoResolutionError> {
    let (record, slot) = stated;
    let owner = holder_name(site, record);
    let tables = index.tables_mut(site.unit)?;
    match owner {
        None => tables.declare(record.name(), slot),
        Some(holder) => tables.hold(holder, slot),
    }
    Ok(())
}

/// The name of the declaration one member is written inside, absent at package
/// scope.
fn holder_name<'a>(site: Site<'a>, record: &GoDeclarationRecord) -> Option<&'a str> {
    record
        .parent()
        .and_then(|parent| facts_of(site).declarations().get(index_of(parent)))
        .map(GoDeclarationRecord::name)
}

/// The grammar facts one site's source retained.
fn facts_of(site: Site<'_>) -> &GoSourceFacts {
    site.held.source.facts()
}

/// Resolve every embedded type one unit writes, after all package definitions
/// are indexed.
fn state_embeddings(
    index: &mut Index,
    corpus: &Corpus<'_>,
    stated: (usize, &GoResolutionUnit),
) -> Result<(), GoResolutionError> {
    let (unit, held) = stated;
    for source in corpus.sources_of(held)?.iter() {
        state_source_embeddings(
            index,
            Site {
                unit,
                held: *source,
            },
        )?;
    }
    Ok(())
}

/// Resolve the embedded types written by one source through its own imports.
fn state_source_embeddings(index: &mut Index, site: Site<'_>) -> Result<(), GoResolutionError> {
    let embeddings = declarations(site.held)
        .filter(|(_, record)| record.kind() == GoDeclarationKind::EmbeddedField);
    for (_, record) in embeddings {
        state_embedding(index, site, record)?;
    }
    Ok(())
}

/// Record one uniquely identified in-snapshot embedded type.
fn state_embedding(
    index: &mut Index,
    site: Site<'_>,
    record: &GoDeclarationRecord,
) -> Result<(), GoResolutionError> {
    let stated = holder_name(site, record).zip(embedded_type(index, site, record));
    match stated {
        None => Ok(()),
        Some((parent, embedded)) => index.tables_mut(site.unit).map(|tables| {
            tables.embed(
                parent,
                Embedding {
                    embedded,
                    pointer: record.embedded_pointer(),
                },
            )
        }),
    }
}

/// The unique in-snapshot type one embedded declaration names.
fn embedded_type(
    index: &Index,
    site: Site<'_>,
    record: &GoDeclarationRecord,
) -> Option<EmbeddedType> {
    let name = record.embedded_name()?;
    let imports = site.held.imports;
    let outcome = match record.embedded_qualifier() {
        Some(qualifier) => imports
            .named(qualifier)
            .map(|target| lookup::qualified(index, target, name))
            .unwrap_or(Outcome::Missing),
        None => lookup::bare(index, (site.unit, imports), name),
    };
    let Outcome::Found(found) = outcome else {
        return None;
    };
    types::unique_type(index, &found, |_, slot| EmbeddedType {
        unit: slot.unit,
        name: Arc::clone(&slot.name),
    })
}

/// State every method one unit holds, beneath the named type that receives it.
fn state_methods(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    corpus: &Corpus<'_>,
    stated: (usize, &GoResolutionUnit),
) -> Result<(), GoResolutionError> {
    let (unit, held) = stated;
    for source in corpus.sources_of(held)?.iter() {
        state_source_methods(
            builder,
            index,
            Site {
                unit,
                held: *source,
            },
        )?;
    }
    Ok(())
}

/// State every method one source declares.
fn state_source_methods(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    site: Site<'_>,
) -> Result<(), GoResolutionError> {
    let methods = declarations(site.held).filter(|(_, record)| is_method(record));
    for declared in methods {
        state_method(builder, index, site, declared)?;
    }
    Ok(())
}

/// State one method beneath the named type that receives it.
///
/// A receiver this tier cannot identify names no holder at all. Go requires a
/// method's receiver base type to be declared in the same package, so a
/// receiver the corpus cannot name is a type the corpus does not hold. Filing
/// the method under the package instead makes `Package` a method holder, which
/// is a containment Go declares for nothing — and it disagrees with the method
/// set beside it, which records nothing for the same absence. The receiver's
/// own type reference already carries the gap that says why none was found.
fn state_method(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    site: Site<'_>,
    declared: (u32, &GoDeclarationRecord),
) -> Result<(), GoResolutionError> {
    let (_, record) = declared;
    let receiver = receiver_type(index, site, (facts_of(site), record));
    let slot = state_definition(
        builder,
        index,
        site,
        declared,
        receiver.map(|(held, _)| held),
    )?;
    hold_method(index, site, receiver, (record.name(), slot))
}

/// The named type one method's receiver states, as the slot holding it and the
/// name it is declared under.
fn receiver_type<'a>(
    index: &Index,
    site: Site<'_>,
    declared: (&'a GoSourceFacts, &GoDeclarationRecord),
) -> Option<(usize, &'a str)> {
    let (facts, record) = declared;
    let bound = facts.bindings().get(index_of(record.receiver()?))?;
    let name = bound.type_name()?;
    let unit = index.unit(site.unit)?;
    unit.named(name)
        .iter()
        .find(|slot| index.slot(**slot).is_some_and(Slot::is_type))
        .map(|slot| (*slot, name))
}

/// Record one method in the method set of the type that receives it.
///
/// A receiver this tier cannot identify holds nothing, which is exactly what
/// its definition states: neither the report nor the method set names an owner
/// for a method whose receiver type the corpus does not declare.
fn hold_method(
    index: &mut Index,
    site: Site<'_>,
    receiver: Option<(usize, &str)>,
    stated: (&str, usize),
) -> Result<(), GoResolutionError> {
    let (_, slot) = stated;
    match receiver {
        None => Ok(()),
        Some((_, owner)) => index
            .tables_mut(site.unit)
            .map(|tables| tables.hold(owner, slot)),
    }
}

/// State one declaration into the report and into the index.
fn state_definition(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    site: Site<'_>,
    declared: (u32, &GoDeclarationRecord),
    parent: Option<usize>,
) -> Result<usize, GoResolutionError> {
    let (ordinal, record) = declared;
    let held = parent
        .and_then(|slot| index.slot(slot))
        .map(|slot| slot.handle.clone());
    let name: Arc<str> = Arc::from(record.name());
    let handle = builder.add_definition(
        &index.unit_handle(site.unit)?,
        symbol_kind(record.kind()),
        Arc::clone(&name),
        index::site(site.held.path, record.span()),
        held.as_ref(),
    )?;
    let slot = index.push(Slot {
        handle,
        kind: symbol_kind(record.kind()),
        declared: Some(record.kind()),
        unit: site.unit,
        name,
        site: index::site(site.held.path, record.name_span()),
        holder: parent,
        conditional: conditional(site.held.source),
        pointer_receiver: receives_by_pointer(facts_of(site), record),
        general_terms: record.states_general_terms(),
        result: result_type(record),
    });
    index
        .tables_mut(site.unit)?
        .state(site.held.path, ordinal, slot);
    Ok(slot)
}

/// The single result one callable declares, as a type a later stage can join.
fn result_type(record: &GoDeclarationRecord) -> Option<TypeName> {
    record.result_name().map(|name| TypeName {
        qualifier: record.result_qualifier().map(Box::from),
        name: Box::from(name),
    })
}

/// Whether one method's receiver is written in pointer form.
///
/// A pointer receiver is what keeps a method out of its type's value method
/// set, so an interface a value is compared against reads this rather than the
/// declaration site.
fn receives_by_pointer(facts: &GoSourceFacts, record: &GoDeclarationRecord) -> bool {
    record
        .receiver()
        .and_then(|binding| facts.bindings().get(index_of(binding)))
        .is_some_and(GoBindingRecord::pointer)
}

/// What one Go declaration is in the shared report vocabulary.
///
/// Every Go kind is named. A kind added to the grammar inventory is therefore a
/// compile error here rather than a declaration that silently becomes something
/// else.
fn symbol_kind(kind: GoDeclarationKind) -> SymbolKind {
    match kind {
        GoDeclarationKind::Function => SymbolKind::Function,
        GoDeclarationKind::Method | GoDeclarationKind::InterfaceMethod => SymbolKind::Method,
        GoDeclarationKind::Struct => SymbolKind::Struct,
        GoDeclarationKind::Interface => SymbolKind::Interface,
        GoDeclarationKind::DefinedType => SymbolKind::DefinedType,
        GoDeclarationKind::TypeAlias => SymbolKind::TypeAlias,
        GoDeclarationKind::Constant => SymbolKind::Constant,
        GoDeclarationKind::Variable => SymbolKind::Variable,
        GoDeclarationKind::Field | GoDeclarationKind::EmbeddedField => SymbolKind::Field,
    }
}
