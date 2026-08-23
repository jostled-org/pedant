//! The exact Go-to-graph vocabulary.
//!
//! Every consumed value maps one for one. Nothing is promoted: an interface
//! dispatch candidate stays possible, and a build-conditioned candidate keeps
//! the gap the resolver gave it.

use std::sync::Arc;

use pedant_types::{ReferenceKind, SymbolKind};

use crate::node::GraphNodeKind;
use crate::reference::GraphReferenceKind;

/// The lower-snake-case attribute vocabulary, allocated once per build.
///
/// Every declaration attribute repeats across a whole repository, so the graph
/// shares one allocation per token rather than one per node.
pub(crate) struct Vocabulary {
    module: Arc<str>,
    package: Arc<str>,
    function: Arc<str>,
    method: Arc<str>,
    interface_method: Arc<str>,
    structure: Arc<str>,
    interface: Arc<str>,
    defined_type: Arc<str>,
    type_alias: Arc<str>,
    constant: Arc<str>,
    variable: Arc<str>,
    field: Arc<str>,
}

impl Vocabulary {
    /// One shared allocation per attribute token.
    pub(crate) fn new() -> Self {
        Self {
            module: Arc::from("module"),
            package: Arc::from("package"),
            function: Arc::from("function"),
            method: Arc::from("method"),
            interface_method: Arc::from("interface_method"),
            structure: Arc::from("struct"),
            interface: Arc::from("interface"),
            defined_type: Arc::from("defined_type"),
            type_alias: Arc::from("type_alias"),
            constant: Arc::from("constant"),
            variable: Arc::from("variable"),
            field: Arc::from("field"),
        }
    }

    /// The node kind one admitted module's container takes.
    ///
    /// A module is declared by its own `go.mod` and by nothing inside the
    /// packages it holds, so the plan states this container itself.
    pub(crate) fn module_root(&self) -> GraphNodeKind {
        self.container(&self.module)
    }

    /// The node kind one Go definition takes, or `None` for a kind no Go report
    /// states.
    ///
    /// A method's declaration alone does not say which of the two callable
    /// levels it is: Go writes an interface's methods and a receiver's methods
    /// with the same report kind, and the interface that holds them is what
    /// tells them apart. The holder's kind is therefore read here rather than
    /// guessed from the name.
    ///
    /// Every `SymbolKind` is named, so a new one is a compile error here rather
    /// than a silent fallback category. The kinds another language owns are
    /// named too, and answer `None`: giving one of them a Go token would let
    /// this projection state a node for a definition the Go resolver refuses to
    /// emit at all.
    pub(crate) fn definition(
        &self,
        kind: SymbolKind,
        holder: Option<SymbolKind>,
    ) -> Option<GraphNodeKind> {
        match kind {
            SymbolKind::Package => Some(self.container(&self.package)),
            SymbolKind::Function => Some(self.callable(&self.function)),
            SymbolKind::Method => self.method_level(holder).map(|level| self.callable(level)),
            SymbolKind::Struct => Some(self.declared_type(&self.structure)),
            SymbolKind::Interface => Some(self.declared_type(&self.interface)),
            SymbolKind::DefinedType => Some(self.declared_type(&self.defined_type)),
            SymbolKind::TypeAlias => Some(self.declared_type(&self.type_alias)),
            SymbolKind::Constant => Some(self.value(&self.constant)),
            SymbolKind::Variable => Some(self.value(&self.variable)),
            SymbolKind::Field => Some(self.value(&self.field)),
            SymbolKind::Module
            | SymbolKind::Enum
            | SymbolKind::Union
            | SymbolKind::Trait
            | SymbolKind::Static => None,
        }
    }

    /// Which callable token one method takes, read from the definition that
    /// holds it, or `None` for a holder no Go method can have.
    ///
    /// Every holder a Go report can state is named, so a new `SymbolKind` is a
    /// compile error here rather than a method quietly filed under the receiver
    /// token. An interface's own method is the interface level; a method whose
    /// receiver names a struct, a defined type, or a type alias is the receiver
    /// level.
    ///
    /// No holder at all takes the receiver level beside them, because that is
    /// where the Go resolver states a method whose receiver type it could not
    /// identify. Go requires a method's receiver base type to be declared in
    /// the same package, so an unidentifiable receiver names a type the corpus
    /// does not hold — the method is still a receiver-level method, and
    /// refusing it would turn a repository the resolver admits into a graph
    /// that cannot be built. The package is named among the refusals instead:
    /// a package holding a method is a containment Go declares for nothing, so
    /// a report stating one is a report this projection will not draw from.
    /// Every other holder earns the same refusal an unnamed kind earns.
    fn method_level(&self, holder: Option<SymbolKind>) -> Option<&Arc<str>> {
        match holder {
            Some(SymbolKind::Interface) => Some(&self.interface_method),
            None | Some(SymbolKind::Struct | SymbolKind::DefinedType | SymbolKind::TypeAlias) => {
                Some(&self.method)
            }
            Some(
                SymbolKind::Package
                | SymbolKind::Module
                | SymbolKind::Function
                | SymbolKind::Method
                | SymbolKind::Enum
                | SymbolKind::Union
                | SymbolKind::Trait
                | SymbolKind::Constant
                | SymbolKind::Variable
                | SymbolKind::Static
                | SymbolKind::Field,
            ) => None,
        }
    }

    /// A namespace node under one shared token.
    fn container(&self, level: &Arc<str>) -> GraphNodeKind {
        GraphNodeKind::Container {
            level: Arc::clone(level),
        }
    }

    /// A callable node under one shared token.
    fn callable(&self, declaration: &Arc<str>) -> GraphNodeKind {
        GraphNodeKind::Function {
            declaration: Arc::clone(declaration),
        }
    }

    /// A type node under one shared token.
    fn declared_type(&self, declaration: &Arc<str>) -> GraphNodeKind {
        GraphNodeKind::Type {
            declaration: Arc::clone(declaration),
        }
    }

    /// A named-value node under one shared token.
    fn value(&self, declaration: &Arc<str>) -> GraphNodeKind {
        GraphNodeKind::Value {
            declaration: Arc::clone(declaration),
        }
    }
}

/// What one Go reference denotes at the graph layer, or `None` for a kind no Go
/// report states.
///
/// A type mention, a value mention, and a field selection are all general
/// source relations here, so five consumed kinds become four graph kinds. A
/// module declaration is another language's vocabulary and is refused for the
/// reason [`Vocabulary::definition`] gives.
pub(crate) fn reference_kind(kind: ReferenceKind) -> Option<GraphReferenceKind> {
    match kind {
        ReferenceKind::Call => Some(GraphReferenceKind::Call),
        ReferenceKind::Import => Some(GraphReferenceKind::Import),
        ReferenceKind::Implementation => Some(GraphReferenceKind::Implementation),
        ReferenceKind::Type | ReferenceKind::Value => Some(GraphReferenceKind::Reference),
        ReferenceKind::Module => None,
    }
}
