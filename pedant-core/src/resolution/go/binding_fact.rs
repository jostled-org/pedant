//! One bound name a snapshotted Go source states.

use pedant_syntax::go::{
    GoBindingFact, GoBindingKind, GoFactSpan, GoInitializer, GoInitializerForm,
};

use super::written_type_fact::GoWrittenTypeRecord;

/// The type one short variable declaration's initializer names, retained by the
/// snapshot rather than borrowed from the parse it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoInitializerRecord {
    form: GoInitializerForm,
    written: GoWrittenTypeRecord,
}

impl GoInitializerRecord {
    /// Retain one extracted initializer.
    fn of(fact: GoInitializer<'_>) -> Self {
        Self {
            form: fact.form(),
            written: GoWrittenTypeRecord::of(fact.qualifier(), Some(fact.name()), fact.pointer()),
        }
    }

    /// What shape the initializer is written in.
    pub fn form(&self) -> GoInitializerForm {
        self.form
    }

    /// The type the initializer names, as its source spells it.
    pub fn written_type(&self) -> &GoWrittenTypeRecord {
        &self.written
    }

    /// The package qualifier written before the name, when the source writes
    /// one.
    pub fn qualifier(&self) -> Option<&str> {
        self.written.qualifier()
    }

    /// The name the initializer states, in its source spelling.
    ///
    /// An initializer is only retained when its shape names a type, so the
    /// written name is always present here.
    pub fn name(&self) -> &str {
        self.written.name().unwrap_or_default()
    }

    /// Whether the initializer states a pointer form.
    pub fn pointer(&self) -> bool {
        self.written.pointer()
    }
}

/// One name a Go source binds, exactly as its source wrote it.
///
/// The same claim [`GoBindingFact`] makes, with its borrowed text owned so the
/// inventory outlives the bound tree it was walked from. The written type is
/// kept as the two names the source states and never as a resolved type: what
/// a name denotes is the resolver's answer, not the grammar's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoBindingRecord {
    kind: GoBindingKind,
    name: Box<str>,
    span: GoFactSpan,
    scope: u32,
    declaration: Option<u32>,
    written: GoWrittenTypeRecord,
    initializer: Option<GoInitializerRecord>,
}

impl GoBindingRecord {
    /// Retain one extracted binding.
    pub(super) fn of(fact: &GoBindingFact<'_>) -> Self {
        Self {
            kind: fact.kind(),
            name: Box::from(fact.name()),
            span: fact.span(),
            scope: fact.scope(),
            declaration: fact.declaration(),
            written: GoWrittenTypeRecord::of(
                fact.type_qualifier(),
                fact.type_name(),
                fact.pointer(),
            ),
            initializer: fact.initializer().map(GoInitializerRecord::of),
        }
    }

    /// What binds this name.
    pub fn kind(&self) -> GoBindingKind {
        self.kind
    }

    /// The bound name, in its source spelling.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The extent of the bound name.
    pub fn span(&self) -> GoFactSpan {
        self.span
    }

    /// The index of the scope this name is bound in.
    pub fn scope(&self) -> u32 {
        self.scope
    }

    /// The index of the declaration this binding belongs to.
    pub fn declaration(&self) -> Option<u32> {
        self.declaration
    }

    /// The type this binding declares, as its source spells it.
    pub fn written_type(&self) -> &GoWrittenTypeRecord {
        &self.written
    }

    /// The package qualifier of the written type, when the source states one.
    pub fn type_qualifier(&self) -> Option<&str> {
        self.written.qualifier()
    }

    /// The name of the written type, when the source states one.
    pub fn type_name(&self) -> Option<&str> {
        self.written.name()
    }

    /// Whether the written type is a pointer.
    pub fn pointer(&self) -> bool {
        self.written.pointer()
    }

    /// The type this binding's initializer names, for a short variable
    /// declaration whose expression states one.
    pub fn initializer(&self) -> Option<&GoInitializerRecord> {
        self.initializer.as_ref()
    }
}
