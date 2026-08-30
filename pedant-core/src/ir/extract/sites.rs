//! Collection of the authoritative definition and reference site inventory.
//!
//! The collector owns the site tables and the traversal position they are
//! stamped with: the module scope, the lexically enclosing definition, the
//! active `#[cfg(…)]` condition, and the local receiver types a method call may
//! be inferred from. The `syn` dispatch that drives it lives in
//! [`super::visitor`].

use std::sync::Arc;

use pedant_types::{ReferenceKind, StructureKind, SymbolKind};

use crate::ir::cfg::RustCfgCondition;
use crate::ir::sites::{
    DefinitionSite, DefinitionSiteId, IrRange, ModuleDeclarationSite, ModuleScope, ReferenceOrigin,
    ReferenceSite, StructureSite, StructureSiteId,
};

/// The finished tables one source's traversal produced.
pub(super) struct FileSites {
    pub(super) scopes: Box<[ModuleScope]>,
    pub(super) declarations: Box<[ModuleDeclarationSite]>,
    pub(super) definitions: Box<[DefinitionSite]>,
    pub(super) references: Box<[ReferenceSite]>,
    pub(super) structures: Box<[StructureSite]>,
}

/// The traversal position a nested item must restore on the way out.
#[derive(Clone, Copy)]
pub(super) struct SavedPosition {
    scope: usize,
    owner: Option<DefinitionSiteId>,
    structure: Option<StructureSiteId>,
}

/// One named declaration under collection: the definition it states and the
/// physical extent that states it.
///
/// The structure kind is not a field: it is what the symbol kind already says,
/// and a second settable spelling of one fact is a second chance for the two
/// tables this entry fills to disagree about what was declared.
pub(super) struct DeclarationEntry {
    pub(super) kind: SymbolKind,
    pub(super) name: Box<str>,
    /// Where the declared name sits, which a resolution report points at.
    pub(super) name_range: IrRange,
    /// The whole declaration, which an outline shows.
    pub(super) declaration_range: IrRange,
    pub(super) associated_with: Option<Arc<str>>,
}

/// One `mod` item under collection.
///
/// A `mod` declares a name like every other named item, so it carries the same
/// entry they do rather than a hand-built copy of one; only the source it
/// selects and whether its body is inline are its own.
pub(super) struct ModuleEntry {
    pub(super) declared: DeclarationEntry,
    pub(super) declared_paths: Box<[Box<str>]>,
    pub(super) inline: bool,
}

/// One reference site under collection.
pub(super) struct ReferenceEntry {
    pub(super) kind: ReferenceKind,
    pub(super) origin: ReferenceOrigin,
    pub(super) text: Box<str>,
    pub(super) range: IrRange,
    pub(super) segments: Box<[Box<str>]>,
    pub(super) alias: Option<Box<str>>,
    pub(super) glob: bool,
    pub(super) receiver: Option<Arc<str>>,
}

impl ReferenceEntry {
    /// A reference whose whole identity is its path.
    pub(super) fn path(
        kind: ReferenceKind,
        origin: ReferenceOrigin,
        text: Box<str>,
        range: IrRange,
        segments: Box<[Box<str>]>,
    ) -> Self {
        Self {
            kind,
            origin,
            text,
            range,
            segments,
            alias: None,
            glob: false,
            receiver: None,
        }
    }
}

/// Accumulates the site inventory for one source.
pub(super) struct SiteCollector {
    scopes: Vec<ModuleScope>,
    declarations: Vec<ModuleDeclarationSite>,
    definitions: Vec<DefinitionSite>,
    references: Vec<ReferenceSite>,
    structures: Vec<StructureSite>,
    scope: usize,
    owner: Option<DefinitionSiteId>,
    structure: Option<StructureSiteId>,
    condition: RustCfgCondition,
}

impl SiteCollector {
    pub(super) fn new() -> Self {
        Self {
            scopes: vec![ModuleScope {
                name: Box::from(""),
                parent: None,
            }],
            declarations: Vec::new(),
            definitions: Vec::new(),
            references: Vec::new(),
            structures: Vec::new(),
            scope: 0,
            owner: None,
            structure: None,
            condition: RustCfgCondition::default(),
        }
    }

    /// The condition guarding the position under traversal.
    pub(super) fn condition(&self) -> &RustCfgCondition {
        &self.condition
    }

    /// Conjoin the condition `attrs` states, returning the one to restore.
    pub(super) fn enter_condition(&mut self, attrs: &[syn::Attribute]) -> RustCfgCondition {
        let restored = self.condition.clone();
        self.condition = restored.with(attrs);
        restored
    }

    /// Restore a condition [`Self::enter_condition`] replaced.
    pub(super) fn leave_condition(&mut self, restored: RustCfgCondition) {
        self.condition = restored;
    }

    /// Record one definition, stamping it with the current position.
    fn push_definition(
        &mut self,
        kind: SymbolKind,
        name: Box<str>,
        range: IrRange,
        associated_with: Option<Arc<str>>,
    ) -> DefinitionSiteId {
        let index = self.definitions.len();
        self.definitions.push(DefinitionSite {
            kind,
            name,
            range,
            scope: self.scope,
            parent: self.owner.map(DefinitionSiteId::index),
            associated_with,
            condition: self.condition.clone(),
        });
        DefinitionSiteId::new(index)
    }

    /// Record one named declaration: the definition it states, and the
    /// physical extent that states it.
    ///
    /// One call rather than two, so a declaration cannot reach the definition
    /// table without also reaching the structure table. The ordinal linking
    /// them is minted here, where the visitor has just recognized the
    /// declaration, rather than re-derived later from a name or a span.
    ///
    /// Answers both identities — the definition first, then the structure — so a
    /// caller entering the body takes the positions this call recorded rather
    /// than a table length read beside it, which the order of the two pushes
    /// here would silently decide. Two ordinals into two tables, so each comes
    /// back as its own type and a caller cannot hand one where the other belongs.
    ///
    /// The structure kind is derived from the symbol kind here, at the one point
    /// where both rows are written, rather than stated a second time by the
    /// caller.
    fn record_declaration(
        &mut self,
        entry: DeclarationEntry,
    ) -> (DefinitionSiteId, StructureSiteId) {
        let structure_kind = StructureKind::from(entry.kind);
        let definition = self.push_definition(
            entry.kind,
            entry.name,
            entry.name_range,
            entry.associated_with,
        );
        let structure =
            self.push_structure(structure_kind, entry.declaration_range, Some(definition));
        (definition, structure)
    }

    /// Record one physical declaration, stamping it with the declaration that
    /// lexically owns it.
    fn push_structure(
        &mut self,
        kind: StructureKind,
        range: IrRange,
        definition: Option<DefinitionSiteId>,
    ) -> StructureSiteId {
        let index = self.structures.len();
        self.structures.push(StructureSite {
            kind,
            range,
            parent: self.structure,
            definition,
        });
        StructureSiteId::new(index)
    }

    /// Record one named declaration and enter the body it owns.
    pub(super) fn push_declaration(&mut self, entry: DeclarationEntry) -> SavedPosition {
        let (definition, structure) = self.record_declaration(entry);
        let saved = self.position();
        self.owner = Some(definition);
        self.structure = Some(structure);
        saved
    }

    /// Record one unnamed declaration and enter the body it owns.
    ///
    /// The Rust `impl` block is the whole of this route: it states a physical
    /// declaration that owns every associated item inside it, and no definition
    /// a reference could denote.
    pub(super) fn push_unnamed_structure(
        &mut self,
        kind: StructureKind,
        range: IrRange,
    ) -> SavedPosition {
        let structure = self.push_structure(kind, range, None);
        let saved = self.position();
        self.structure = Some(structure);
        saved
    }

    /// Record one reference, stamping it with the current position.
    pub(super) fn push_reference(&mut self, entry: ReferenceEntry, containing_fn: Option<usize>) {
        let condition = self.condition.clone();
        self.push_conditional_reference(entry, condition, containing_fn);
    }

    /// Record one reference whose own attributes widen the active condition.
    pub(super) fn push_conditional_reference(
        &mut self,
        entry: ReferenceEntry,
        condition: RustCfgCondition,
        containing_fn: Option<usize>,
    ) {
        self.references.push(ReferenceSite {
            kind: entry.kind,
            text: entry.text,
            range: entry.range,
            scope: self.scope,
            enclosing: self.owner.map(DefinitionSiteId::index),
            origin: entry.origin,
            segments: entry.segments,
            alias: entry.alias,
            glob: entry.glob,
            receiver: entry.receiver,
            condition,
            containing_fn,
        });
    }

    /// Record one `mod` item and enter the body it owns.
    ///
    /// The item's own `#[cfg(…)]` attributes already sit on the active
    /// condition, conjoined by the gate scaffolding the visitor entered under,
    /// so nothing here re-applies them.
    pub(super) fn push_module(&mut self, entry: ModuleEntry) -> SavedPosition {
        let name = entry.declared.name.clone();
        let (definition, structure) = self.record_declaration(entry.declared);
        let inline_scope = entry.inline.then(|| self.open_scope(&name));
        self.declarations.push(ModuleDeclarationSite {
            name,
            declared_paths: entry.declared_paths,
            definition: definition.index(),
            inline_scope,
            scope: self.scope,
            condition: self.condition.clone(),
        });
        let saved = self.position();
        self.owner = Some(definition);
        self.structure = Some(structure);
        self.scope = inline_scope.unwrap_or(self.scope);
        saved
    }

    /// Restore a position an entered item replaced.
    pub(super) fn restore(&mut self, saved: SavedPosition) {
        self.scope = saved.scope;
        self.owner = saved.owner;
        self.structure = saved.structure;
    }

    pub(super) fn finish(self) -> FileSites {
        FileSites {
            scopes: self.scopes.into_boxed_slice(),
            declarations: self.declarations.into_boxed_slice(),
            definitions: self.definitions.into_boxed_slice(),
            references: self.references.into_boxed_slice(),
            structures: self.structures.into_boxed_slice(),
        }
    }

    fn open_scope(&mut self, name: &str) -> usize {
        let index = self.scopes.len();
        self.scopes.push(ModuleScope {
            name: Box::from(name),
            parent: Some(self.scope),
        });
        index
    }

    fn position(&self) -> SavedPosition {
        SavedPosition {
            scope: self.scope,
            owner: self.owner,
            structure: self.structure,
        }
    }
}
