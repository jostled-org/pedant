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

    /// The node kind one Rust definition takes.
    ///
    /// Every `SymbolKind` a Rust report emits is named, so a new one is a
    /// compile error here rather than a silent fallback category.
    pub(crate) fn definition(&self, kind: SymbolKind) -> GraphNodeKind {
        match kind {
            SymbolKind::Module => GraphNodeKind::Container {
                level: Arc::clone(&self.module_level),
            },
            SymbolKind::Function => GraphNodeKind::Function {
                declaration: Arc::clone(&self.function),
            },
            SymbolKind::Method => GraphNodeKind::Function {
                declaration: Arc::clone(&self.method),
            },
            SymbolKind::Struct => GraphNodeKind::Type {
                declaration: Arc::clone(&self.structure),
            },
            SymbolKind::Enum => GraphNodeKind::Type {
                declaration: Arc::clone(&self.enumeration),
            },
            SymbolKind::Union => GraphNodeKind::Type {
                declaration: Arc::clone(&self.union),
            },
            SymbolKind::Trait => GraphNodeKind::Type {
                declaration: Arc::clone(&self.trait_declaration),
            },
            SymbolKind::TypeAlias => GraphNodeKind::Type {
                declaration: Arc::clone(&self.type_alias),
            },
            SymbolKind::Constant => GraphNodeKind::Value {
                declaration: Arc::clone(&self.constant),
            },
            SymbolKind::Static => GraphNodeKind::Value {
                declaration: Arc::clone(&self.static_declaration),
            },
        }
    }
}

/// What one Rust reference denotes at the graph layer.
///
/// A module declaration and a type mention are both general source relations
/// here, so five consumed kinds become four graph kinds.
pub(crate) fn reference_kind(kind: ReferenceKind) -> GraphReferenceKind {
    match kind {
        ReferenceKind::Call => GraphReferenceKind::Call,
        ReferenceKind::Import => GraphReferenceKind::Import,
        ReferenceKind::Implementation => GraphReferenceKind::Implementation,
        ReferenceKind::Module | ReferenceKind::Type => GraphReferenceKind::Reference,
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
