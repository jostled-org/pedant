//! One bounded declaration walk over a parsed tree.
//!
//! The four tree-sitter languages that own structures here — JavaScript,
//! TypeScript, Python, and Bash — share this one walk. It descends the grammar
//! once, keeps the nearest recognized ancestor as each structure's owner, and
//! checks both ceilings before it pays for the state they bound.

use std::ops::Range;

use ::tree_sitter::TreeCursor;
use pedant_types::StructureKind;

use crate::language::SyntaxLanguage;
use crate::structure::builder::{InventoryBuilder, lines_of};
use crate::structure::error::StructureError;
use crate::structure::inventory::StructureInventory;
use crate::structure::limits::StructureInventoryLimits;
use crate::structure::recognize::{recognize, source_is_a_module};
use crate::tree_sitter::{Node, advance, node_text};

/// One open owner: the tree level it was recognized at, and its position.
struct OpenOwner {
    depth: usize,
    structure: u32,
}

/// The module a source states and its grammar declares no node for, and where
/// this walk stands on it.
///
/// A Python or ECMAScript file is a module, so the inventory states one from the
/// file itself. It is settled at the first structure the walk recognizes rather
/// than before the walk, because that structure is the only one whose extent can
/// be the whole source: `def f(): pass` and `export class A {}`, each with no
/// closing newline, cover every byte the file holds. Two structures at one extent
/// state no ownership between them — `StructureSpan::strictly_contains` rejects
/// the link, and the nearest owner of anything inside them stops being decidable
/// — so the module stands down there rather than publishing a link every reader
/// of the owner forest asserts against.
///
/// A source that declares nothing still states its module: an empty file is a
/// module holding no structure, which is what [`close`](Self::close) retains.
enum FileModule {
    /// Stated by the language, and not yet settled against a structure.
    Pending,
    /// Settled: the position the module holds, or its absence.
    Settled(Option<u32>),
}

impl FileModule {
    /// The module `language` states, before the walk reads a node.
    fn opened(language: SyntaxLanguage) -> Self {
        match source_is_a_module(language) {
            true => Self::Pending,
            false => Self::Settled(None),
        }
    }

    /// The owner one recognized structure covering `bytes` takes.
    ///
    /// The nearest owner still open, or the file module when none is. Both
    /// readings sit here because the second settles the module: it is retained
    /// at the first structure the walk recognizes outside every open owner, and
    /// nothing asks a second time whether it exists.
    fn owner(
        &mut self,
        open: &[OpenOwner],
        bytes: &Range<usize>,
        builder: &mut InventoryBuilder<'_>,
    ) -> Result<Option<u32>, StructureError> {
        match open.last() {
            Some(owner) => Ok(Some(owner.structure)),
            None => self.settled(bytes, builder),
        }
    }

    /// The module's position, retaining it on the first call.
    ///
    /// It is retained ahead of the structure that asked, so it keeps the
    /// position source order gives it — unless that structure covers the whole
    /// file, which leaves the module nothing to own.
    fn settled(
        &mut self,
        bytes: &Range<usize>,
        builder: &mut InventoryBuilder<'_>,
    ) -> Result<Option<u32>, StructureError> {
        let settled = match (&*self, covers_the_file(bytes, builder.source())) {
            (Self::Settled(position), _) => *position,
            (Self::Pending, true) => None,
            (Self::Pending, false) => Some(retain_module(builder)?),
        };
        *self = Self::Settled(settled);
        Ok(settled)
    }

    /// Retain the module when the walk recognized nothing to settle it against.
    ///
    /// Nothing was retained ahead of it, so it takes the position it would have
    /// taken anyway.
    fn close(self, builder: &mut InventoryBuilder<'_>) -> Result<(), StructureError> {
        match self {
            Self::Pending => retain_module(builder).map(drop),
            Self::Settled(_) => Ok(()),
        }
    }
}

/// Whether one structure's extent is the file's own.
fn covers_the_file(bytes: &Range<usize>, source: &str) -> bool {
    *bytes == (0..source.len())
}

/// Retain the whole source as one module structure, owned by nothing.
fn retain_module(builder: &mut InventoryBuilder<'_>) -> Result<u32, StructureError> {
    let source = builder.source();
    builder.retain(
        StructureKind::Module,
        None,
        0..source.len(),
        lines_of(source),
        None,
    )
}

/// Walk `root` once and seal every structure it states.
///
/// `source` must be the exact string `root`'s tree was parsed from, because a
/// node's byte range indexes it.
pub(super) fn inventory<'source>(
    root: Node<'_>,
    source: &'source str,
    language: SyntaxLanguage,
    limits: StructureInventoryLimits,
) -> Result<StructureInventory<'source>, StructureError> {
    let mut builder = InventoryBuilder::new(source, limits);
    let mut module = FileModule::opened(language);
    walk(root, language, &mut module, &mut builder)?;
    module.close(&mut builder)?;
    Ok(builder.seal(language))
}

/// Descend the whole tree, retaining what the recognizer names.
///
/// Iterative rather than recursive: the depth ceiling is a caller's value, so a
/// permissive one would otherwise turn a deep source into a stack overflow
/// instead of a refusal.
fn walk<'source>(
    root: Node<'_>,
    language: SyntaxLanguage,
    module: &mut FileModule,
    builder: &mut InventoryBuilder<'source>,
) -> Result<(), StructureError> {
    let bytes = builder.source().as_bytes();
    let mut cursor = root.walk();
    let mut open: Vec<OpenOwner> = Vec::new();
    let mut depth = 0_usize;
    let mut at_root = true;
    loop {
        let node = cursor.node();
        // An owner recognized at this level or below is a sibling of the node
        // under visit rather than an ancestor of it.
        while open.last().is_some_and(|owner| owner.depth >= depth) {
            open.pop();
        }
        let found = match at_root {
            true => None,
            false => recognize(node, language),
        };
        at_root = false;
        if let Some(structure) = found {
            let name = structure.name.map(|named| node_text(named, bytes));
            let owner = module.owner(&open, &structure.bytes, builder)?;
            let position = builder.retain(
                structure.kind,
                name,
                structure.bytes,
                structure.lines,
                owner,
            )?;
            open.push(OpenOwner {
                depth,
                structure: position,
            });
        }
        match descend(&mut cursor, depth, builder)? {
            Some(child) => depth = child,
            // This walk closes an owner by comparing the level it was
            // recognized at against the level under visit, so the ascent leaves
            // it nothing to do.
            None if advance(&mut cursor, &mut depth, |_| {}) => {}
            None => return Ok(()),
        }
    }
}

/// Enter the node's first child once the ceiling admits its level.
///
/// Absent when the node has no children, so a leaf costs no ceiling check and
/// no refusal it could not have paid for.
fn descend(
    cursor: &mut TreeCursor<'_>,
    depth: usize,
    builder: &InventoryBuilder<'_>,
) -> Result<Option<usize>, StructureError> {
    if cursor.node().child_count() == 0 {
        return Ok(None);
    }
    let child = depth.saturating_add(1);
    builder.admit_depth(child)?;
    Ok(cursor.goto_first_child().then_some(child))
}
