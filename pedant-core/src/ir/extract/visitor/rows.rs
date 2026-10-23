//! The row macros that expand into `Visit` overrides.
//!
//! Each macro states one visit body shape once and expands it per row inside
//! the `impl Visit` block. Paths in a body resolve where the row expands, so
//! the importing stays with that block.

/// Define one type-definition visit per row.
///
/// Every row is `visit_fn(SynType) => Kind via edges`, and every body is the
/// same: state the identifier, its rendered name, the kind, visibility,
/// attributes, and whole extent the source writes, compute that type's
/// relationship edges, then walk what it holds. The trait row is written out
/// below, because a trait also carries its own name into the items it declares.
macro_rules! type_definitions {
    ($($visit:ident($item:ty) => $kind:ident via $edges:ident;)*) => {
        $(
            fn $visit(&mut self, node: &'ast $item) {
                self.visit_type_def(
                    TypeDefinition {
                        ident: &node.ident,
                        name: type_scope(&node.ident),
                        kind: TypeDefKind::$kind,
                        visibility: &node.vis,
                        attrs: &node.attrs,
                        declaration: node.extent(),
                    },
                    |name| $edges(node, name),
                    |s| syn::visit::$visit(s, node),
                );
            }
        )*
    };
}

/// Define one value-item visit per row.
///
/// Two groups, because the owner is the only difference. A `free` row expands
/// with a literal `None`: a method body sitting in an `impl` does not make a
/// `const` declared beside it an associated one. An `owned` row names a reader
/// of the traversal state — the enclosing `impl` self type or trait — as a
/// function rather than an expression, because a row cannot name `self`: macro
/// hygiene binds that to the call site, not to the body it expands into.
///
/// Only the free type alias is written out below, because it states
/// relationship edges as well as a site.
macro_rules! value_items {
    (free { $($free:ident($free_item:ty) => $free_kind:ident;)* }
     owned { $($owned:ident($owned_item:ty) => $owned_kind:ident owned_by $owner:path;)* }) => {
        $(value_items!(@row $free($free_item) => $free_kind,);)*
        $(value_items!(@row $owned($owned_item) => $owned_kind, $owner);)*
    };
    (@row $visit:ident($item:ty) => $kind:ident, $($owner:path)?) => {
        fn $visit(&mut self, node: &'ast $item) {
            let associated_with = value_items!(@owner $($owner(self))?);
            self.visit_value_item(
                ValueItem {
                    ident: &node.ident,
                    kind: SymbolKind::$kind,
                    attrs: &node.attrs,
                    associated_with,
                    declaration: node.extent(),
                },
                |this| syn::visit::$visit(this, node),
            );
        }
    };
    (@owner) => { None };
    (@owner $stated:expr) => { $stated };
}
