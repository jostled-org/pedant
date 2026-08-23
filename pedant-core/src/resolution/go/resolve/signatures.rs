//! The canonical signature every Go callable in the corpus states.
//!
//! Two methods match when their names match and their signatures are the same
//! type by type, and a type's identity is its package and its name rather than
//! the spelling one file happens to use. So each term is rewritten here to the
//! package it names — through the writing file's own imports for a qualified
//! term, and through the declaring package for a bare one — and the terms are
//! joined into one text two callables can be compared by.
//!
//! A term whose shape names no single type states no name in the grammar
//! inventory, and a name no package in reach declares cannot be qualified. Both
//! leave the callable without a canonical signature, which a comparison reports
//! as evidence it does not have rather than as a mismatch.

use std::collections::BTreeMap;

use pedant_syntax::go::{GoDeclarationKind, GoSignatureRole};

use crate::resolution::go::facts::GoSourceFacts;
use crate::resolution::go::signature_fact::GoSignatureTermRecord;

use super::corpus::Corpus;
use super::imports::FileImports;
use super::index::{Index, Slot};
use super::lookup::{self, Outcome};
use super::universe;

/// One file, and everything canonicalizing a term written in it depends on.
struct Written<'a> {
    unit: usize,
    facts: &'a GoSourceFacts,
    imports: FileImports<'a>,
}

impl<'a> Written<'a> {
    /// Read one source of one package context.
    fn of(corpus: &Corpus<'a>, unit: usize, facts: &'a GoSourceFacts) -> Self {
        Self {
            unit,
            facts,
            imports: FileImports::of(corpus, facts),
        }
    }

    /// The canonical text one callable's terms state, in the order it writes
    /// them.
    fn canonical(&self, index: &Index, corpus: &Corpus<'_>, declaration: u32) -> Option<Box<str>> {
        let parameters =
            self.role_text(index, corpus, (declaration, GoSignatureRole::Parameter))?;
        let results = self.role_text(index, corpus, (declaration, GoSignatureRole::Result))?;
        Some(format!("({parameters})({results})").into_boxed_str())
    }

    /// Every term one callable states in one role, comma-separated.
    fn role_text(
        &self,
        index: &Index,
        corpus: &Corpus<'_>,
        stated: (u32, GoSignatureRole),
    ) -> Option<Box<str>> {
        let (declaration, role) = stated;
        let named: Option<Box<[Box<str>]>> = self
            .facts
            .signature_terms()
            .iter()
            .filter(|term| term.declaration() == declaration && term.role() == role)
            .map(|term| self.term_type(index, corpus, term))
            .collect();
        let named = named?;
        let borrowed: Box<[&str]> = named.iter().map(|term| &**term).collect();
        Some(borrowed.join(",").into_boxed_str())
    }

    /// The canonical text one term states.
    fn term_type(
        &self,
        index: &Index,
        corpus: &Corpus<'_>,
        term: &GoSignatureTermRecord,
    ) -> Option<Box<str>> {
        let name = term.type_name()?;
        let package = self.package_of(index, corpus, (term.type_qualifier(), name))?;
        let variadic = match term.variadic() {
            true => "...",
            false => "",
        };
        let pointer = match term.pointer() {
            true => "*",
            false => "",
        };
        Some(format!("{variadic}{pointer}{package}{name}").into_boxed_str())
    }

    /// The package one written type belongs to, rendered as the prefix its
    /// canonical name opens with.
    ///
    /// A universe type belongs to no package and opens with nothing. Every
    /// other type opens with the import path of the package declaring it, so
    /// one type written `Token` where it is declared and `shape.Token` where it
    /// is imported states one canonical name.
    fn package_of(
        &self,
        index: &Index,
        corpus: &Corpus<'_>,
        written: (Option<&str>, &str),
    ) -> Option<Box<str>> {
        let (qualifier, name) = written;
        match qualifier {
            Some(package) => self
                .imports
                .named(package)
                .map(|target| prefix(target.path)),
            None => self.declared_package(index, corpus, name),
        }
    }

    /// The package a bare type name belongs to: the one package in reach that
    /// declares it, or none at all when the universe block does.
    fn declared_package(&self, index: &Index, corpus: &Corpus<'_>, name: &str) -> Option<Box<str>> {
        match self.declaring_unit(index, name) {
            Some(unit) => corpus.unit(unit).map(|found| prefix(found.import_path())),
            None => universe::is_predeclared(name).then(|| Box::from("")),
        }
    }

    /// The unit declaring the one type a bare name selects in this file.
    ///
    /// Several would be an ambiguous type name, which is a Go program error
    /// rather than a choice, so it states no canonical package here.
    fn declaring_unit(&self, index: &Index, name: &str) -> Option<usize> {
        let Outcome::Found(found) = lookup::bare(index, (self.unit, &self.imports), name) else {
            return None;
        };
        let mut units: Vec<usize> = found
            .iter()
            .filter_map(|slot| index.slot(*slot))
            .filter(|slot| Slot::is_type(slot))
            .map(|slot| slot.unit)
            .collect();
        units.sort_unstable();
        units.dedup();
        match *units {
            [only] => Some(only),
            _ => None,
        }
    }
}

/// One canonical signature per callable definition the corpus declares.
#[derive(Default)]
pub(super) struct Signatures {
    stated: BTreeMap<usize, Box<str>>,
}

impl Signatures {
    /// Read every callable the corpus declares.
    pub(super) fn of(index: &Index, corpus: &Corpus<'_>) -> Self {
        let mut signatures = Self::default();
        for (position, unit) in corpus.units().iter().enumerate() {
            for path in unit.sources() {
                let Some(source) = corpus.source(path) else {
                    continue;
                };
                let written = Written::of(corpus, position, source.facts());
                signatures.state_source(index, corpus, (&written, path));
            }
        }
        signatures
    }

    /// State the canonical signature of every callable one source declares.
    fn state_source(&mut self, index: &Index, corpus: &Corpus<'_>, site: (&Written<'_>, &str)) {
        let (written, path) = site;
        for (declaration, record) in written.facts.declarations().iter().enumerate() {
            let ordinal = u32::try_from(declaration).unwrap_or(u32::MAX);
            let canonical = is_callable(record.kind())
                .then(|| written.canonical(index, corpus, ordinal))
                .flatten();
            let slot = index
                .unit(written.unit)
                .and_then(|tables| tables.declared(path, ordinal));
            if let Some((slot, canonical)) = slot.zip(canonical) {
                self.stated.insert(slot, canonical);
            }
        }
    }

    /// The canonical signature one definition states, absent when a term names
    /// a type this model cannot name.
    pub(super) fn of_slot(&self, slot: usize) -> Option<&str> {
        self.stated.get(&slot).map(|stated| &**stated)
    }
}

/// Whether one declaration kind writes a signature.
fn is_callable(kind: GoDeclarationKind) -> bool {
    matches!(
        kind,
        GoDeclarationKind::Function
            | GoDeclarationKind::Method
            | GoDeclarationKind::InterfaceMethod
    )
}

/// One import path, as the prefix a canonical name opens with.
fn prefix(path: &str) -> Box<str> {
    format!("{path}.").into_boxed_str()
}
