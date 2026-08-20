//! One bound name a snapshotted Go source states.

use pedant_syntax::go::{
    GoBindingFact, GoBindingKind, GoFactSpan, GoInitializer, GoInitializerForm,
};

/// The type one short variable declaration's initializer names, retained by the
/// snapshot rather than borrowed from the parse it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoInitializerRecord {
    form: GoInitializerForm,
    qualifier: Option<Box<str>>,
    name: Box<str>,
    pointer: bool,
}

impl GoInitializerRecord {
    /// Retain one extracted initializer.
    fn of(fact: GoInitializer<'_>) -> Self {
        Self {
            form: fact.form(),
            qualifier: fact.qualifier().map(Box::from),
            name: Box::from(fact.name()),
            pointer: fact.pointer(),
        }
    }

    /// What shape the initializer is written in.
    pub fn form(&self) -> GoInitializerForm {
        self.form
    }

    /// The package qualifier written before the name, when the source writes
    /// one.
    pub fn qualifier(&self) -> Option<&str> {
        self.qualifier.as_deref()
    }

    /// The name the initializer states, in its source spelling.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the initializer states a pointer form.
    pub fn pointer(&self) -> bool {
        self.pointer
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
    type_qualifier: Option<Box<str>>,
    type_name: Option<Box<str>>,
    pointer: bool,
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
            type_qualifier: fact.type_qualifier().map(Box::from),
            type_name: fact.type_name().map(Box::from),
            pointer: fact.pointer(),
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

    /// The package qualifier of the written type, when the source states one.
    pub fn type_qualifier(&self) -> Option<&str> {
        self.type_qualifier.as_deref()
    }

    /// The name of the written type, when the source states one.
    pub fn type_name(&self) -> Option<&str> {
        self.type_name.as_deref()
    }

    /// Whether the written type is a pointer.
    pub fn pointer(&self) -> bool {
        self.pointer
    }

    /// The type this binding's initializer names, for a short variable
    /// declaration whose expression states one.
    pub fn initializer(&self) -> Option<&GoInitializerRecord> {
        self.initializer.as_ref()
    }
}
