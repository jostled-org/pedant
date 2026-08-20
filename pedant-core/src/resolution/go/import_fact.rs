//! One import specification a snapshotted Go source states.

use pedant_syntax::go::{GoFactSpan, GoImportFact, GoImportForm};

/// One Go import specification, exactly as its file wrote it.
///
/// The same claim [`GoImportFact`] makes, with its borrowed text owned so the
/// inventory outlives the bound tree it was walked from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoImportRecord {
    form: GoImportForm,
    path: Box<str>,
    alias: Option<Box<str>>,
    local_name: Option<Box<str>>,
    span: GoFactSpan,
}

impl GoImportRecord {
    /// Retain one extracted import.
    pub(super) fn of(fact: &GoImportFact<'_>) -> Self {
        Self {
            form: fact.form(),
            path: Box::from(fact.path()),
            alias: fact.alias().map(Box::from),
            local_name: fact.local_name().map(Box::from),
            span: fact.span(),
        }
    }

    /// The form the specification is written in.
    pub fn form(&self) -> GoImportForm {
        self.form
    }

    /// The import path, without its quotes.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The explicit alias, present only for [`GoImportForm::Aliased`].
    pub fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    /// The name this file binds for the package, absent for a dot or blank
    /// import.
    pub fn local_name(&self) -> Option<&str> {
        self.local_name.as_deref()
    }

    /// The extent of the specification.
    pub fn span(&self) -> GoFactSpan {
        self.span
    }
}
