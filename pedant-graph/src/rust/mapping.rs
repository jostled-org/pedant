//! The exact Rust-to-graph vocabulary.
//!
//! Every consumed value maps one for one. Nothing is promoted: a possible
//! candidate stays possible, and a conditional dependency stays conditional.

use std::sync::Arc;

use pedant_core::resolution::rust::{CargoDependencyKind, CargoTargetKind, DependencyActivation};
use pedant_types::{ReferenceKind, ResolutionCertainty, SymbolKind};

use crate::edge::{GraphCertainty, GraphDependencyKind, GraphEdgeKind};
use crate::node::GraphNodeKind;
use crate::reference::GraphReferenceKind;

/// The lower-snake-case attribute vocabulary, allocated once per build.
///
/// Every declaration attribute repeats across a whole repository, so the graph
/// shares one allocation per token rather than one per node.
pub(crate) struct Vocabulary {
    library: Arc<str>,
    binary: Arc<str>,
    example: Arc<str>,
    test: Arc<str>,
    benchmark: Arc<str>,
    build_script: Arc<str>,
    module_level: Arc<str>,
    function: Arc<str>,
    method: Arc<str>,
    structure: Arc<str>,
    enumeration: Arc<str>,
    union: Arc<str>,
    trait_declaration: Arc<str>,
    type_alias: Arc<str>,
    constant: Arc<str>,
    static_declaration: Arc<str>,
}

impl Vocabulary {
    /// One shared allocation per attribute token.
    pub(crate) fn new() -> Self {
        Self {
            library: Arc::from("library"),
            binary: Arc::from("binary"),
            example: Arc::from("example"),
            test: Arc::from("test"),
            benchmark: Arc::from("benchmark"),
            build_script: Arc::from("build_script"),
            module_level: Arc::from("module"),
            function: Arc::from("function"),
            method: Arc::from("method"),
            structure: Arc::from("struct"),
            enumeration: Arc::from("enum"),
            union: Arc::from("union"),
            trait_declaration: Arc::from("trait"),
            type_alias: Arc::from("type_alias"),
            constant: Arc::from("constant"),
            static_declaration: Arc::from("static"),
        }
    }

    /// The node kind one resolution unit's root container takes.
    ///
    /// The Cargo target kind is the container level, because one package states
    /// a library and a binary under the same crate name and the two are
    /// different containers over different sources.
    pub(crate) fn unit_root(&self, kind: CargoTargetKind) -> GraphNodeKind {
        GraphNodeKind::Container {
            level: Arc::clone(self.target_level(kind)),
        }
    }

    /// The level attribute one Cargo target kind takes.
    ///
    /// Every kind is named, so a seventh is a compile error here rather than a
    /// second unit container nothing tells apart.
    fn target_level(&self, kind: CargoTargetKind) -> &Arc<str> {
        match kind {
            CargoTargetKind::Library => &self.library,
            CargoTargetKind::Binary => &self.binary,
            CargoTargetKind::Example => &self.example,
            CargoTargetKind::Test => &self.test,
            CargoTargetKind::Benchmark => &self.benchmark,
            CargoTargetKind::BuildScript => &self.build_script,
        }
    }

    /// The node kind one Rust definition takes, or `None` for a kind no Rust
    /// report states.
    pub(crate) fn definition(&self, kind: SymbolKind) -> Option<GraphNodeKind> {
        let (category, declaration) = self.declared(kind)?;
        Some(category.node(Arc::clone(declaration)))
    }

    /// Whether one held node kind is the kind this vocabulary states for
    /// `kind`.
    ///
    /// Read by borrow. The reuse guard asks this of every definition of every
    /// examined fragment, and minting the kind to compare it would share a
    /// token and drop it again for every answer, on the one path whose purpose
    /// is to cost less than deriving the projection would.
    pub(crate) fn states_definition(&self, held: &GraphNodeKind, kind: SymbolKind) -> bool {
        self.declared(kind)
            .is_some_and(|stated| DefinitionCategory::stated(held) == Some(stated))
    }

    /// The category and declaration token one Rust definition kind takes, or
    /// `None` for a kind no Rust report states.
    ///
    /// Every `SymbolKind` is named, so a new one is a compile error here rather
    /// than a silent fallback category. The kinds another language owns are
    /// named too, and answer `None`: giving one of them a Rust token would let
    /// this projection state a node for a definition the Rust resolver refuses
    /// to emit at all. This is the one statement of the vocabulary — minting a
    /// kind and comparing one both read it.
    fn declared(&self, kind: SymbolKind) -> Option<(DefinitionCategory, &Arc<str>)> {
        match kind {
            SymbolKind::Module => Some((DefinitionCategory::Container, &self.module_level)),
            SymbolKind::Function => Some((DefinitionCategory::Function, &self.function)),
            SymbolKind::Method => Some((DefinitionCategory::Function, &self.method)),
            SymbolKind::Struct => Some((DefinitionCategory::Type, &self.structure)),
            SymbolKind::Enum => Some((DefinitionCategory::Type, &self.enumeration)),
            SymbolKind::Union => Some((DefinitionCategory::Type, &self.union)),
            SymbolKind::Trait => Some((DefinitionCategory::Type, &self.trait_declaration)),
            SymbolKind::TypeAlias => Some((DefinitionCategory::Type, &self.type_alias)),
            SymbolKind::Constant => Some((DefinitionCategory::Value, &self.constant)),
            SymbolKind::Static => Some((DefinitionCategory::Value, &self.static_declaration)),
            SymbolKind::Package
            | SymbolKind::Interface
            | SymbolKind::DefinedType
            | SymbolKind::Variable
            | SymbolKind::Field => None,
        }
    }
}

/// Which graph node category one Rust definition lands in.
///
/// The category and the declaration token together are the whole node kind, so
/// a comparison reads both without minting one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DefinitionCategory {
    /// A namespace that owns other entities.
    Container,
    /// A callable entity.
    Function,
    /// A type entity.
    Type,
    /// A named value entity.
    Value,
}

impl DefinitionCategory {
    /// The node kind this category takes under one declaration token.
    fn node(self, declaration: Arc<str>) -> GraphNodeKind {
        match self {
            Self::Container => GraphNodeKind::Container { level: declaration },
            Self::Function => GraphNodeKind::Function { declaration },
            Self::Type => GraphNodeKind::Type { declaration },
            Self::Value => GraphNodeKind::Value { declaration },
        }
    }

    /// The category and declaration token one held node kind states.
    ///
    /// A file node states neither: it is minted from a path rather than from a
    /// definition, so no definition kind can equal it.
    fn stated(held: &GraphNodeKind) -> Option<(Self, &Arc<str>)> {
        match held {
            GraphNodeKind::File => None,
            GraphNodeKind::Container { level } => Some((Self::Container, level)),
            GraphNodeKind::Function { declaration } => Some((Self::Function, declaration)),
            GraphNodeKind::Type { declaration } => Some((Self::Type, declaration)),
            GraphNodeKind::Value { declaration } => Some((Self::Value, declaration)),
        }
    }
}

/// What one Rust reference denotes at the graph layer, or `None` for a kind no
/// Rust report states.
///
/// A module declaration and a type mention are both general source relations
/// here, so five consumed kinds become four graph kinds. A value reference is
/// another language's vocabulary and is refused for the reason
/// [`Vocabulary::declared`] gives.
pub(crate) fn reference_kind(kind: ReferenceKind) -> Option<GraphReferenceKind> {
    match kind {
        ReferenceKind::Call => Some(GraphReferenceKind::Call),
        ReferenceKind::Import => Some(GraphReferenceKind::Import),
        ReferenceKind::Implementation => Some(GraphReferenceKind::Implementation),
        ReferenceKind::Module | ReferenceKind::Type => Some(GraphReferenceKind::Reference),
        ReferenceKind::Value => None,
    }
}

/// The edge one candidate of a reference produces.
pub(crate) fn candidate_edge_kind(kind: GraphReferenceKind) -> GraphEdgeKind {
    match kind {
        GraphReferenceKind::Call => GraphEdgeKind::Call,
        GraphReferenceKind::Import => GraphEdgeKind::Import,
        GraphReferenceKind::Implementation => GraphEdgeKind::Implementation,
        GraphReferenceKind::Reference => GraphEdgeKind::Reference,
    }
}

/// How much one candidate is known.
pub(crate) fn certainty(certainty: ResolutionCertainty) -> GraphCertainty {
    match certainty {
        ResolutionCertainty::Resolved => GraphCertainty::Resolved,
        ResolutionCertainty::Possible => GraphCertainty::Possible,
    }
}

/// Which dependency table declared one Cargo edge.
pub(crate) fn dependency_kind(kind: CargoDependencyKind) -> GraphDependencyKind {
    match kind {
        CargoDependencyKind::Normal => GraphDependencyKind::Normal,
        CargoDependencyKind::Development => GraphDependencyKind::Development,
        CargoDependencyKind::Build => GraphDependencyKind::Build,
    }
}

/// How much one dependency edge is known, and what predicate it retained.
///
/// An always-active edge is proved by the manifest alone. A conditional one
/// keeps its unevaluated predicate and stays possible, because this layer
/// evaluates no configuration.
pub(crate) fn activation(activation: &DependencyActivation) -> (GraphCertainty, Option<Arc<str>>) {
    match activation {
        DependencyActivation::Always => (GraphCertainty::Resolved, None),
        DependencyActivation::Conditional(predicate) => {
            (GraphCertainty::Possible, Some(Arc::clone(predicate)))
        }
    }
}
