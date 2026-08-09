//! The module-instance graph one snapshot describes.
//!
//! A node is one module instance of one unit: the source that holds it, the
//! lexical scope of that source it occupies, the `mod` item that selected it,
//! and the conditional-compilation predicates inherited along the way. Nodes
//! are addressed globally so a candidate may cross units.

use crate::ir::FileIr;
use crate::ir::cfg::RustCfgCondition;
use crate::resolution::rust::identity::index_of;
use crate::resolution::rust::snapshot::{RustResolutionSnapshot, RustSource};

use super::error::RustResolutionError;

/// The `mod` item that selected one node.
#[derive(Clone, Copy)]
pub(super) struct NodeDeclaration {
    /// The node whose source declares the module.
    pub(super) node: usize,
    /// The declaring source's definition site for the module.
    pub(super) definition: usize,
}

/// One module instance of one unit.
pub(super) struct Node {
    pub(super) unit: usize,
    pub(super) file: usize,
    pub(super) scope: usize,
    pub(super) parent: Option<usize>,
    pub(super) declaration: Option<NodeDeclaration>,
    pub(super) condition: RustCfgCondition,
}

/// Every unit's module instances as one addressable graph.
pub(super) struct Graph {
    pub(super) nodes: Box<[Node]>,
    /// The crate-root node of each unit.
    pub(super) roots: Box<[usize]>,
}

impl Graph {
    /// The source one node's items live in.
    pub(super) fn source<'a>(
        &self,
        snapshot: &'a RustResolutionSnapshot,
        node: usize,
    ) -> Option<&'a RustSource> {
        let file = self.nodes.get(node)?.file;
        snapshot.sources().get(file)
    }

    /// The one-pass IR of the source one node's items live in.
    pub(super) fn file_ir<'a>(
        &self,
        snapshot: &'a RustResolutionSnapshot,
        node: usize,
    ) -> Option<&'a FileIr> {
        self.source(snapshot, node).map(RustSource::ir)
    }

    /// The node holding `scope` of `file`, starting from `node` and walking
    /// outward through the module instances that contain it.
    pub(super) fn node_for_scope(&self, node: usize, file: usize, scope: usize) -> Option<usize> {
        let mut current = Some(node);
        while let Some(index) = current {
            let found = self.nodes.get(index)?;
            if found.file == file && found.scope == scope {
                return Some(index);
            }
            current = found.parent;
        }
        None
    }
}

/// Resolve every unit's module instances into nodes.
pub(super) fn build(snapshot: &RustResolutionSnapshot) -> Result<Graph, RustResolutionError> {
    let mut nodes: Vec<Node> = Vec::new();
    let mut roots: Vec<usize> = Vec::new();
    for (unit, instances) in snapshot.units().iter().enumerate() {
        let offset = nodes.len();
        roots.push(offset);
        for instance in instances.modules() {
            let parent = instance
                .parent()
                .map(|id| offset.saturating_add(index_of(id.index())));
            let declaration = declaration_of(snapshot, &nodes, parent, instance.declaration);
            nodes.push(Node {
                unit,
                file: file_index(snapshot, instance.path())?,
                scope: index_of(instance.scope),
                parent,
                declaration,
                condition: inherited(snapshot, &nodes, parent, declaration),
            });
        }
    }
    Ok(Graph {
        nodes: nodes.into_boxed_slice(),
        roots: roots.into_boxed_slice(),
    })
}

fn declaration_of(
    snapshot: &RustResolutionSnapshot,
    nodes: &[Node],
    parent: Option<usize>,
    declaration: Option<u32>,
) -> Option<NodeDeclaration> {
    let node = parent?;
    let site = declaration_site(snapshot, nodes, node, declaration?)?;
    Some(NodeDeclaration {
        node,
        definition: site.definition,
    })
}

fn inherited(
    snapshot: &RustResolutionSnapshot,
    nodes: &[Node],
    parent: Option<usize>,
    declaration: Option<NodeDeclaration>,
) -> RustCfgCondition {
    let above = parent
        .and_then(|node| nodes.get(node))
        .map(|node| node.condition.clone())
        .unwrap_or_default();
    let stated = declaration
        .and_then(|found| declared_condition(snapshot, nodes, found))
        .unwrap_or_default();
    above.and(&stated)
}

fn declared_condition(
    snapshot: &RustResolutionSnapshot,
    nodes: &[Node],
    declaration: NodeDeclaration,
) -> Option<RustCfgCondition> {
    let ir = file_ir_of(snapshot, nodes, declaration.node)?;
    ir.module_declarations
        .iter()
        .find(|site| site.definition == declaration.definition)
        .map(|site| site.condition().clone())
}

fn declaration_site<'a>(
    snapshot: &'a RustResolutionSnapshot,
    nodes: &[Node],
    node: usize,
    declaration: u32,
) -> Option<&'a crate::ir::sites::ModuleDeclarationSite> {
    file_ir_of(snapshot, nodes, node)?
        .module_declarations
        .get(index_of(declaration))
}

fn file_ir_of<'a>(
    snapshot: &'a RustResolutionSnapshot,
    nodes: &[Node],
    node: usize,
) -> Option<&'a FileIr> {
    let file = nodes.get(node)?.file;
    snapshot.sources().get(file).map(RustSource::ir)
}

/// The position of one normalized path in the snapshot's sorted source store.
///
/// A module instance names a source the closure interned, so a miss is a
/// broken snapshot rather than an absent file. It is reported instead of
/// standing in for one: an unreachable index would make every later reader
/// take its absent-source arm, and the whole module instance would drop out
/// of the report with no gap and no evidence.
fn file_index(snapshot: &RustResolutionSnapshot, path: &str) -> Result<usize, RustResolutionError> {
    snapshot
        .sources()
        .binary_search_by(|source| source.path().cmp(path))
        .map_err(|_| RustResolutionError::UnknownFile {
            file: Box::from(path),
        })
}
