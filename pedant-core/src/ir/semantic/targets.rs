//! The definition edges one parsed file states, taken once while the file is
//! analyzed.
//!
//! An edge is stated in database terms — the crate a name was resolved in, the
//! file the definition sits in, and the byte offset its name starts at — and is
//! turned into repository coordinates only when a verified snapshot asks for
//! it. The crate is part of the edge, so one physical source instantiated under
//! two Cargo targets can never answer for the wrong one.
//!
//! Only the outermost path of a path expression or type, and the name of a
//! method call, are resolved. A path inside a `use` tree is left alone: a `use`
//! item states one site per leaf at one shared range, so its leaves are not
//! separable by coordinate and stay with the tier that produced them.

use ra_ap_hir::{
    AsAssocItem, AssocItem, AssocItemContainer, Crate, Function, HasSource, Impl, InFile,
    ModuleDef, Name, PathResolution, Trait,
};
use ra_ap_ide::{FileId, RootDatabase};
use ra_ap_syntax::ast::HasName;
use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, TextSize, ast};

use super::common::ParsedFile;

/// Where one end of an edge sits, in database terms.
#[derive(Clone, Copy)]
pub(super) struct EdgeSite {
    /// The crate the name was resolved in, or the definition belongs to.
    pub(super) krate: Crate,
    /// The file the site sits in.
    pub(super) file: FileId,
    /// The byte offset the site starts at.
    pub(super) offset: TextSize,
}

/// One reference and the definition the database says it denotes.
pub(super) struct SemanticEdge {
    pub(super) source: EdgeSite,
    pub(super) target: EdgeSite,
    /// Whether the target is one member of a dispatch set rather than the one
    /// concrete definition the call reaches.
    pub(super) enumerated: bool,
}

/// Every definition edge one parsed file states.
pub(super) fn collect(pf: &ParsedFile<'_>) -> Box<[SemanticEdge]> {
    let mut edges: Vec<SemanticEdge> = Vec::new();
    for node in pf.tree.syntax().descendants() {
        match node.kind() {
            SyntaxKind::PATH => add_path(pf, &node, &mut edges),
            SyntaxKind::METHOD_CALL_EXPR => add_method_call(pf, &node, &mut edges),
            _ => {}
        }
    }
    edges.into_boxed_slice()
}

fn add_path(pf: &ParsedFile<'_>, node: &SyntaxNode, edges: &mut Vec<SemanticEdge>) {
    let Some(path) = ast::Path::cast(node.clone()).filter(|_| is_resolvable_path(node)) else {
        return;
    };
    let (Some(source), Some(PathResolution::Def(def))) =
        (source_site(pf, node), pf.sema.resolve_path(&path))
    else {
        return;
    };
    if let Some(target) = definition_site(pf.db, def) {
        edges.push(SemanticEdge {
            source,
            target,
            enumerated: false,
        });
    }
}

/// The outermost path of an expression or type, excluding `use` trees.
fn is_resolvable_path(node: &SyntaxNode) -> bool {
    let outermost = node
        .parent()
        .is_none_or(|parent| parent.kind() != SyntaxKind::PATH);
    outermost && node.ancestors().all(|it| it.kind() != SyntaxKind::USE_TREE)
}

fn add_method_call(pf: &ParsedFile<'_>, node: &SyntaxNode, edges: &mut Vec<SemanticEdge>) {
    let Some(call) = ast::MethodCallExpr::cast(node.clone()) else {
        return;
    };
    let (Some(name), Some(function)) = (call.name_ref(), pf.sema.resolve_method_call(&call)) else {
        return;
    };
    let Some(krate) = resolved_crate(pf, node) else {
        return;
    };
    let source = EdgeSite {
        krate,
        file: pf.file_id,
        offset: name.syntax().text_range().start(),
    };
    let (targets, enumerated) = method_targets(pf.db, function);
    edges.extend(targets.into_iter().map(|target| SemanticEdge {
        source,
        target,
        enumerated,
    }));
}

/// Where one reference sits, and which crate the database resolved it in.
fn source_site(pf: &ParsedFile<'_>, node: &SyntaxNode) -> Option<EdgeSite> {
    Some(EdgeSite {
        krate: resolved_crate(pf, node)?,
        file: pf.file_id,
        offset: node.text_range().start(),
    })
}

fn resolved_crate(pf: &ParsedFile<'_>, node: &SyntaxNode) -> Option<Crate> {
    pf.sema.scope(node).map(|scope| scope.krate())
}

/// Every definition a method call may reach, and whether they are a dispatch
/// set rather than one concrete target.
///
/// A call that lands on a trait's own declaration is dispatched at run time, so
/// the set of implementations the database holds is enumerated and none of them
/// is proved. A call that lands on an inherent or implemented function is that
/// one definition.
fn method_targets(db: &RootDatabase, function: Function) -> (Vec<EdgeSite>, bool) {
    let container = function.as_assoc_item(db).map(|item| item.container(db));
    match container {
        Some(AssocItemContainer::Trait(declared)) => (trait_targets(db, declared, function), true),
        _ => (
            definition_site(db, ModuleDef::Function(function))
                .into_iter()
                .collect(),
            false,
        ),
    }
}

/// Every implementation of one trait method this repository holds, or the
/// trait's own declaration when it holds none.
///
/// A trait declared outside the repository — `Clone`, `From`, any `core` trait
/// — is implemented across the whole crate graph, and asking each of those
/// implementations for its source forces a parse of the file that holds it.
/// None of them can ever be a snapshot target, so the crate origin decides
/// before any source is read.
fn trait_targets(db: &RootDatabase, declared: Trait, function: Function) -> Vec<EdgeSite> {
    let name = function.name(db);
    let sites: Vec<EdgeSite> = Impl::all_for_trait(db, declared)
        .into_iter()
        .filter(|found| is_repository_impl(db, *found))
        .flat_map(|found| found.items(db))
        .filter_map(|item| implemented_function(item, db, &name))
        .filter_map(|found| definition_site(db, ModuleDef::Function(found)))
        .collect();
    match sites.is_empty() {
        true => definition_site(db, ModuleDef::Function(function))
            .into_iter()
            .collect(),
        false => sites,
    }
}

/// Whether one implementation sits in a crate this workspace builds, which is
/// the only kind a verified snapshot can hold.
fn is_repository_impl(db: &RootDatabase, found: Impl) -> bool {
    found.module(db).krate(db).origin(db).is_local()
}

fn implemented_function(item: AssocItem, db: &RootDatabase, name: &Name) -> Option<Function> {
    match item {
        AssocItem::Function(found) if found.name(db) == *name => Some(found),
        _ => None,
    }
}

/// Where one definition's name sits, and which crate holds it.
///
/// Modules, macros, and builtin types are absent by design: a module's site is
/// its `mod` item, whose range the syntactic tier states from the `mod` token,
/// and a macro's definition is not the target of an expansion this tier
/// performs. A reference to one of those keeps the answer Tier 1 gave it.
fn definition_site(db: &RootDatabase, def: ModuleDef) -> Option<EdgeSite> {
    let krate = def.module(db)?.krate(db);
    let (file, offset) = match def {
        ModuleDef::Function(it) => named_range(db, it.source(db)?),
        ModuleDef::Adt(it) => named_range(db, it.source(db)?),
        ModuleDef::EnumVariant(it) => named_range(db, it.source(db)?),
        ModuleDef::Const(it) => named_range(db, it.source(db)?),
        ModuleDef::Static(it) => named_range(db, it.source(db)?),
        ModuleDef::Trait(it) => named_range(db, it.source(db)?),
        ModuleDef::TypeAlias(it) => named_range(db, it.source(db)?),
        ModuleDef::Module(_) | ModuleDef::Macro(_) | ModuleDef::BuiltinType(_) => None,
    }?;
    Some(EdgeSite {
        krate,
        file,
        offset,
    })
}

/// The file and offset one named item's declared name starts at.
fn named_range<N: AstNode + HasName>(
    db: &RootDatabase,
    source: InFile<N>,
) -> Option<(FileId, TextSize)> {
    let file = source.file_id.file_id()?.file_id(db);
    let name = source.value.name()?;
    Some((file, name.syntax().text_range().start()))
}
