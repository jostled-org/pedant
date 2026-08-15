//! Collection of the authoritative definition and reference site inventory.
//!
//! The collector owns the site tables and the traversal position they are
//! stamped with: the module scope, the lexically enclosing definition, the
//! active `#[cfg(…)]` condition, and the local receiver types a method call may
//! be inferred from. The `syn` dispatch that drives it lives in
//! [`super::visitor`].

use std::collections::BTreeMap;
use std::rc::Rc;

use pedant_types::{ReferenceKind, SymbolKind};

use crate::ir::cfg::RustCfgCondition;
use crate::ir::sites::{
    DefinitionSite, IrRange, ModuleDeclarationSite, ModuleScope, ReferenceOrigin, ReferenceSite,
};

/// The local binding types one function body established.
///
/// One binding's type is read once per method call on it, so the type name is
/// shared rather than copied out on every lookup.
pub(super) type LocalReceivers = BTreeMap<Box<str>, Rc<str>>;

/// The finished tables one source's traversal produced.
pub(super) struct FileSites {
    pub(super) scopes: Box<[ModuleScope]>,
    pub(super) declarations: Box<[ModuleDeclarationSite]>,
    pub(super) definitions: Box<[DefinitionSite]>,
    pub(super) references: Box<[ReferenceSite]>,
}

/// The traversal position a nested item must restore on the way out.
#[derive(Clone, Copy)]
pub(super) struct SavedPosition {
    scope: usize,
    owner: Option<usize>,
}

/// One `mod` item under collection.
pub(super) struct ModuleEntry {
    pub(super) name: Box<str>,
    pub(super) range: IrRange,
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
    pub(super) receiver: Option<Rc<str>>,
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
    scope: usize,
    owner: Option<usize>,
    condition: RustCfgCondition,
    receivers: LocalReceivers,
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
            scope: 0,
            owner: None,
            condition: RustCfgCondition::default(),
            receivers: LocalReceivers::new(),
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
    pub(super) fn push_definition(
        &mut self,
        kind: SymbolKind,
        name: Box<str>,
        range: IrRange,
        associated_with: Option<Box<str>>,
    ) -> usize {
        let index = self.definitions.len();
        self.definitions.push(DefinitionSite {
            kind,
            name,
            range,
            scope: self.scope,
            parent: self.owner,
            associated_with,
            condition: self.condition.clone(),
        });
        index
    }

    /// Record one reference, stamping it with the current position.
    pub(super) fn push_reference(&mut self, entry: ReferenceEntry, containing_fn: Option<usize>) {
        let condition = self.condition.clone();
        self.push_conditional_reference(entry, &condition, containing_fn);
    }

    /// Record one reference whose own attributes widen the active condition.
    pub(super) fn push_conditional_reference(
        &mut self,
        entry: ReferenceEntry,
        condition: &RustCfgCondition,
        containing_fn: Option<usize>,
    ) {
        self.references.push(ReferenceSite {
            kind: entry.kind,
            text: entry.text,
            range: entry.range,
            scope: self.scope,
            enclosing: self.owner,
            origin: entry.origin,
            segments: entry.segments,
            alias: entry.alias,
            glob: entry.glob,
            receiver: entry.receiver,
            condition: condition.clone(),
            containing_fn,
        });
    }

    /// Record one `mod` item and enter the body it owns.
    ///
    /// The item's own `#[cfg(…)]` attributes already sit on the active
    /// condition, conjoined by the gate scaffolding the visitor entered under,
    /// so nothing here re-applies them.
    pub(super) fn push_module(&mut self, entry: ModuleEntry) -> SavedPosition {
        let definition =
            self.push_definition(SymbolKind::Module, entry.name.clone(), entry.range, None);
        let inline_scope = entry.inline.then(|| self.open_scope(&entry.name));
        self.declarations.push(ModuleDeclarationSite {
            name: entry.name,
            declared_paths: entry.declared_paths,
            definition,
            inline_scope,
            scope: self.scope,
            condition: self.condition.clone(),
        });
        let saved = self.position();
        self.owner = Some(definition);
        self.scope = inline_scope.unwrap_or(self.scope);
        saved
    }

    /// Enter a definition's body, so nested sites name it as their owner.
    pub(super) fn enter_owner(&mut self, definition: usize) -> SavedPosition {
        let saved = self.position();
        self.owner = Some(definition);
        saved
    }

    /// Restore a position an entered item replaced.
    pub(super) fn restore(&mut self, saved: SavedPosition) {
        self.scope = saved.scope;
        self.owner = saved.owner;
    }

    /// Start a fresh local receiver-type environment for one function body,
    /// returning the enclosing one to restore.
    pub(super) fn enter_receivers(&mut self) -> LocalReceivers {
        std::mem::take(&mut self.receivers)
    }

    /// Restore a receiver environment [`Self::enter_receivers`] replaced.
    pub(super) fn leave_receivers(&mut self, restored: LocalReceivers) {
        self.receivers = restored;
    }

    /// Record that the local binding `name` holds a value of type `type_name`.
    pub(super) fn record_receiver(&mut self, name: Box<str>, type_name: Rc<str>) {
        self.receivers.insert(name, type_name);
    }

    /// The type a local binding is known to hold, when an annotation, a struct
    /// literal, or an obvious constructor established one.
    pub(super) fn receiver_type(&self, receiver: &str) -> Option<Rc<str>> {
        self.receivers.get(receiver).cloned()
    }

    pub(super) fn finish(self) -> FileSites {
        FileSites {
            scopes: self.scopes.into_boxed_slice(),
            declarations: self.declarations.into_boxed_slice(),
            definitions: self.definitions.into_boxed_slice(),
            references: self.references.into_boxed_slice(),
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
        }
    }
}
