//! What the traversal knows about the item it is currently visiting.
//!
//! A value shape rather than a parameter list: it travels whole from a `syn`
//! arm to the recorder that consumes it, and only the arm's spelling of its
//! fields differs.

use std::sync::Arc;

use pedant_types::SymbolKind;

use crate::ir::facts::TypeDefKind;
use crate::ir::sites::IrRange;

/// One type definition under visit, as its source writes it.
pub(in crate::ir::extract) struct TypeDefinition<'ast> {
    /// The identifier naming the type.
    pub(in crate::ir::extract) ident: &'ast syn::Ident,
    /// That identifier rendered once, shared by every reader of the name.
    ///
    /// Carried beside the identifier rather than derived from it inside the
    /// recorder, because a trait arm establishes the same handle as the scope
    /// its items name before the recorder runs.
    pub(in crate::ir::extract) name: Arc<str>,
    /// Which kind of type the source declares.
    pub(in crate::ir::extract) kind: TypeDefKind,
    /// The declared visibility.
    pub(in crate::ir::extract) visibility: &'ast syn::Visibility,
    /// The item's own attributes, gates included.
    pub(in crate::ir::extract) attrs: &'ast [syn::Attribute],
    /// The extent of the whole declaration.
    pub(in crate::ir::extract) declaration: IrRange,
}

impl<'ast> TypeDefinition<'ast> {
    /// The named declaration this type definition states.
    ///
    /// A type declares a name the way a constant does, so both routes reach the
    /// site tables through one shape. A type definition names no owner: it is
    /// written where the source writes it, never inside an `impl` or a trait.
    pub(in crate::ir::extract) fn declared_item(&self) -> ValueItem<'ast> {
        ValueItem {
            ident: self.ident,
            kind: symbol_kind(self.kind),
            attrs: self.attrs,
            associated_with: None,
            declaration: self.declaration,
        }
    }
}

/// One named declaration under visit, as its source writes it: a constant, a
/// static, a type alias, or the declaration a type definition states.
pub(in crate::ir::extract) struct ValueItem<'ast> {
    /// The identifier naming the item.
    pub(in crate::ir::extract) ident: &'ast syn::Ident,
    /// Which symbol the source declares.
    pub(in crate::ir::extract) kind: SymbolKind,
    /// The item's own attributes, gates included.
    pub(in crate::ir::extract) attrs: &'ast [syn::Attribute],
    /// The owner the syntax states: an `impl` self type, a trait, or nothing at
    /// all for a free item.
    pub(in crate::ir::extract) associated_with: Option<Arc<str>>,
    /// The extent of the whole declaration.
    pub(in crate::ir::extract) declaration: IrRange,
}

/// The symbol one kind of type definition declares.
fn symbol_kind(kind: TypeDefKind) -> SymbolKind {
    match kind {
        TypeDefKind::Struct => SymbolKind::Struct,
        TypeDefKind::Enum => SymbolKind::Enum,
        TypeDefKind::Trait => SymbolKind::Trait,
        TypeDefKind::Union => SymbolKind::Union,
    }
}
