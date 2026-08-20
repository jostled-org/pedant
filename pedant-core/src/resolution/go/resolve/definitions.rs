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
use pedant_types::{
    Language, ResolutionReportBuilder, ResolutionUnitHandle, SourcePosition, SourceSpan, SymbolKind,
};

use crate::resolution::go::declaration_fact::GoDeclarationRecord;
use crate::resolution::go::facts::GoSourceFacts;
use crate::resolution::go::source::GoSource;
use crate::resolution::go::unit::GoResolutionUnit;

use super::corpus::{Corpus, conditional};
use super::error::GoResolutionError;
use super::index::{Index, Slot, TypeName, UnitIndex};
use super::target::unit_key;

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
    let key = unit_key(unit);
    let handle = builder.add_unit(
        Language::Go,
        Arc::clone(&key),
        Arc::from(unit.import_path()),
    )?;
    let span = package_span(corpus, unit)?;
    let slot = index.push(Slot {
        handle: builder.add_definition(
            &handle,
            SymbolKind::Package,
            Arc::from(unit.package_name()),
            span,
            None,
        )?,
        kind: SymbolKind::Package,
        unit: position,
        name: Box::from(unit.package_name()),
        conditional: false,
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
    let stated = unit
        .sources()
        .first()
        .and_then(|path| corpus.source(path).map(|source| (path, source)))
        .and_then(|(path, source)| source.facts().package_span().map(|span| (path, span)));
    let (path, span) = stated.ok_or_else(|| GoResolutionError::UnitMapping {
        unit: unit.id().index(),
        reason: Box::from("no source of this package context states a package clause"),
    })?;
    Ok(SourceSpan::new(
        Arc::clone(path),
        SourcePosition::new(line(span.start_line()), line(span.start_column())),
        SourcePosition::new(line(span.end_line()), line(span.end_column())),
    ))
}

/// State every declaration one unit holds except its methods.
fn state_members(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    corpus: &Corpus<'_>,
    stated: (usize, &GoResolutionUnit),
) -> Result<(), GoResolutionError> {
    let (position, unit) = stated;
    for path in unit.sources() {
        let Some(source) = corpus.source(path) else {
            continue;
        };
        state_source_members(builder, index, (position, path, source))?;
    }
    Ok(())
}

/// State every non-method declaration one source holds, in source order.
fn state_source_members(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    site: (usize, &str, &GoSource),
) -> Result<(), GoResolutionError> {
    let (_, _, source) = site;
    for (declaration, record) in source.facts().declarations().iter().enumerate() {
        state_member(
            builder,
            index,
            site,
            (u32::try_from(declaration).unwrap_or(u32::MAX), record),
        )?;
    }
    Ok(())
}

/// State one non-method declaration, and record what it holds or embeds.
fn state_member(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    site: (usize, &str, &GoSource),
    declared: (u32, &GoDeclarationRecord),
) -> Result<(), GoResolutionError> {
    let (position, path, source) = site;
    let (_, record) = declared;
    if record.kind() == GoDeclarationKind::Method {
        return Ok(());
    }
    let parent = member_parent(index, position, (path, record));
    let slot = state_definition(builder, index, site, declared, parent)?;
    record_membership(index, position, source, (record, slot));
    Ok(())
}

/// The definition a non-method declaration is a child of.
fn member_parent(
    index: &Index,
    position: usize,
    declared: (&str, &GoDeclarationRecord),
) -> Option<usize> {
    let (path, record) = declared;
    let unit = index.unit(position)?;
    match record.parent() {
        Some(parent) => unit.declared(path, parent),
        None => Some(unit.package),
    }
}

/// Record what one stated declaration contributes to lookup.
fn record_membership(
    index: &mut Index,
    position: usize,
    source: &GoSource,
    stated: (&GoDeclarationRecord, usize),
) {
    let (record, slot) = stated;
    let owner = record
        .parent()
        .and_then(|parent| source.facts().declarations().get(parent as usize))
        .map(|holder| Box::<str>::from(holder.name()));
    let Some(unit) = index.unit_mut(position) else {
        return;
    };
    match (owner, record.kind()) {
        (None, _) => unit.declare(record.name(), slot),
        (Some(holder), GoDeclarationKind::EmbeddedField) => {
            unit.embed(&holder, record.name());
            unit.hold(&holder, record.name(), slot);
        }
        (Some(holder), _) => unit.hold(&holder, record.name(), slot),
    }
}

/// State every method one unit holds, beneath the named type that receives it.
fn state_methods(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    corpus: &Corpus<'_>,
    stated: (usize, &GoResolutionUnit),
) -> Result<(), GoResolutionError> {
    let (position, unit) = stated;
    for path in unit.sources() {
        let Some(source) = corpus.source(path) else {
            continue;
        };
        state_source_methods(builder, index, (position, path, source))?;
    }
    Ok(())
}

/// State every method one source declares.
fn state_source_methods(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    site: (usize, &str, &GoSource),
) -> Result<(), GoResolutionError> {
    let (_, _, source) = site;
    let methods: Box<[(u32, &GoDeclarationRecord)]> = source
        .facts()
        .declarations()
        .iter()
        .enumerate()
        .filter(|(_, record)| record.kind() == GoDeclarationKind::Method)
        .map(|(declaration, record)| (u32::try_from(declaration).unwrap_or(u32::MAX), record))
        .collect();
    for (declaration, record) in methods.iter() {
        state_method(builder, index, site, (*declaration, record))?;
    }
    Ok(())
}

/// State one method beneath the named type that receives it.
fn state_method(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    site: (usize, &str, &GoSource),
    declared: (u32, &GoDeclarationRecord),
) -> Result<(), GoResolutionError> {
    let (position, _, source) = site;
    let (_, record) = declared;
    let receiver = receiver_type(index, position, (source.facts(), record));
    let parent = receiver
        .as_ref()
        .map(|(slot, _)| *slot)
        .or_else(|| index.unit(position).map(|unit| unit.package));
    let slot = state_definition(builder, index, site, declared, parent)?;
    hold_method(index, position, receiver, (record.name(), slot));
    Ok(())
}

/// The named type one method's receiver states, as the slot holding it and the
/// name it is declared under.
fn receiver_type(
    index: &Index,
    position: usize,
    declared: (&GoSourceFacts, &GoDeclarationRecord),
) -> Option<(usize, Box<str>)> {
    let (facts, record) = declared;
    let bound = facts.bindings().get(record.receiver()? as usize)?;
    let name = bound.type_name()?;
    let unit = index.unit(position)?;
    unit.named(name)
        .iter()
        .find(|slot| index.slot(**slot).is_some_and(Slot::is_type))
        .map(|slot| (*slot, Box::from(name)))
}

/// Record one method in the method set of the type that receives it.
fn hold_method(
    index: &mut Index,
    position: usize,
    receiver: Option<(usize, Box<str>)>,
    stated: (&str, usize),
) {
    let (name, slot) = stated;
    let Some((_, owner)) = receiver else {
        return;
    };
    if let Some(unit) = index.unit_mut(position) {
        unit.hold(&owner, name, slot);
    }
}

/// State one declaration into the report and into the index.
fn state_definition(
    builder: &mut ResolutionReportBuilder,
    index: &mut Index,
    site: (usize, &str, &GoSource),
    declared: (u32, &GoDeclarationRecord),
    parent: Option<usize>,
) -> Result<usize, GoResolutionError> {
    let (position, path, source) = site;
    let (declaration, record) = declared;
    let held = parent
        .and_then(|slot| index.slot(slot))
        .map(|slot| slot.handle.clone());
    let handle = builder.add_definition(
        &unit_handle(index, position)?,
        symbol_kind(record.kind()),
        Arc::from(record.name()),
        span_of(path, record),
        held.as_ref(),
    )?;
    let slot = index.push(Slot {
        handle,
        kind: symbol_kind(record.kind()),
        unit: position,
        name: Box::from(record.name()),
        conditional: conditional(source),
        result: result_type(record),
    });
    if let Some(unit) = index.unit_mut(position) {
        unit.state(path, declaration, slot);
    }
    Ok(slot)
}

/// The handle of the unit one declaration is stated in.
fn unit_handle(index: &Index, position: usize) -> Result<ResolutionUnitHandle, GoResolutionError> {
    index
        .unit(position)
        .map(|unit| unit.handle.clone())
        .ok_or_else(|| GoResolutionError::UnitMapping {
            unit: u32::try_from(position).unwrap_or(u32::MAX),
            reason: Box::from("no index was opened for this package context"),
        })
}

/// The single result one callable declares, as a type a later stage can join.
fn result_type(record: &GoDeclarationRecord) -> Option<TypeName> {
    record.result_name().map(|name| TypeName {
        qualifier: record.result_qualifier().map(Box::from),
        name: Box::from(name),
    })
}

/// The report span one declaration occupies.
fn span_of(path: &str, record: &GoDeclarationRecord) -> SourceSpan {
    let span = record.span();
    SourceSpan::new(
        Arc::from(path),
        SourcePosition::new(line(span.start_line()), line(span.start_column())),
        SourcePosition::new(line(span.end_line()), line(span.end_column())),
    )
}

fn line(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
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
