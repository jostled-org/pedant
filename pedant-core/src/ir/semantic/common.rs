//! Shared helpers for semantic analysis submodules.
//!
//! Contains the file parsing preamble (`with_parsed_file`, `with_fn_body`)
//! and utility functions used across multiple detection domains.

use line_index::LineIndex;
use ra_ap_hir::{DisplayTarget, EditionedFileId, HirDisplay, Semantics};
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::ast::HasName;
use ra_ap_syntax::{AstNode, SyntaxNode, ast};
use ra_ap_vfs::{AbsPathBuf, VfsPath};

use ra_ap_syntax::SyntaxKind;

use super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
use super::SemanticContext;

/// Parsed file context passed to semantic analysis closures.
///
/// Created once per file by [`with_parsed_file`], then shared across
/// all detection passes to avoid redundant parsing.
pub(super) struct ParsedFile<'a> {
    pub(super) sema: Semantics<'a, RootDatabase>,
    pub(super) tree: ast::SourceFile,
    pub(super) line_index: &'a LineIndex,
    pub(super) db: &'a RootDatabase,
    pub(super) file_id: ra_ap_ide::FileId,
}

/// Parse a file and run a closure with the parsed context.
///
/// Handles file lookup, database attachment, semantic construction,
/// and line index retrieval. Returns `None` when the file is not in
/// the VFS or the line index cannot be computed.
pub(super) fn with_parsed_file<T>(
    ctx: &SemanticContext,
    file: &str,
    f: impl FnOnce(&ParsedFile<'_>) -> T,
) -> Option<T> {
    let (file_id, db) = file_setup(ctx, file)?;
    let line_index_arc = ctx.host.analysis().file_line_index(file_id).ok()?;
    ra_ap_hir::attach_db(db, || {
        let sema = Semantics::new(db);
        let editioned = EditionedFileId::current_edition(db, file_id);
        let tree = sema.parse(editioned);
        Some(f(&ParsedFile {
            sema,
            tree,
            line_index: &line_index_arc,
            db,
            file_id,
        }))
    })
}

/// Parse a file, locate a named function, and run a closure with the function context.
///
/// Combines [`with_parsed_file`] and [`find_fn_body`]. Returns `None` when
/// the file cannot be parsed or the function is not found.
pub(super) fn with_fn_body<T>(
    ctx: &SemanticContext,
    file: &str,
    fn_name: &str,
    f: impl FnOnce(&ParsedFile<'_>, &ast::Fn, &ast::BlockExpr, &ast::StmtList) -> T,
) -> Option<T> {
    with_parsed_file(ctx, file, |pf| {
        let (fn_node, body, stmt_list) = find_fn_body(&pf.tree, fn_name)?;
        Some(f(pf, &fn_node, &body, &stmt_list))
    })
    .flatten()
}

/// Map an absolute file path to a VFS `FileId` and database reference.
fn file_setup<'a>(
    ctx: &'a SemanticContext,
    file: &str,
) -> Option<(ra_ap_ide::FileId, &'a RootDatabase)> {
    let file_id = file_id_for_path(ctx, file)?;
    let db = ctx.host.raw_database();
    Some((file_id, db))
}

/// Map an absolute file path to a VFS `FileId`.
fn file_id_for_path(ctx: &SemanticContext, path: &str) -> Option<ra_ap_ide::FileId> {
    let abs = AbsPathBuf::try_from(path).ok()?;
    let vfs_path = VfsPath::from(abs);
    let (file_id, _) = ctx.vfs.file_id(&vfs_path)?;
    Some(file_id)
}

/// Convert a `SyntaxNode` position to an `IrSpan` using the file's line index.
pub(super) fn span_from_node(node: &SyntaxNode, line_index: &LineIndex) -> IrSpan {
    let offset = node.text_range().start();
    let lc = line_index.line_col(offset);
    IrSpan {
        line: (lc.line + 1) as usize,
        column: lc.col as usize,
    }
}

/// Construct a quality/perf/concurrency `DataFlowFact` (no capability source/sink).
pub(super) fn quality_fact(
    kind: DataFlowKind,
    source_span: IrSpan,
    sink_span: IrSpan,
    message: Box<str>,
) -> DataFlowFact {
    DataFlowFact {
        kind,
        source_capability: None,
        source_span,
        sink_capability: None,
        sink_span,
        call_chain: Box::new([]),
        message,
    }
}

/// Format a resolved `Type` as a canonical string.
pub(super) fn format_type(
    ty: &ra_ap_hir::Type<'_>,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Box<str> {
    ty.display(db, display_target).to_string().into_boxed_str()
}

/// Find a named function in a parsed source file and return its body components.
fn find_fn_body(
    tree: &ast::SourceFile,
    fn_name: &str,
) -> Option<(ast::Fn, ast::BlockExpr, ast::StmtList)> {
    let fn_node = find_fn_node(tree, fn_name)?;
    let body = fn_node.body()?;
    let stmt_list = body.stmt_list()?;
    Some((fn_node, body, stmt_list))
}

/// Find a named function in a parsed source file.
fn find_fn_node(tree: &ast::SourceFile, fn_name: &str) -> Option<ast::Fn> {
    tree.syntax()
        .descendants()
        .filter_map(ast::Fn::cast)
        .find(|f| f.name().is_some_and(|n| n.text() == fn_name))
}

/// Build a `DisplayTarget` for rendering types from a given file.
///
/// Returns `None` if the file does not belong to any crate.
pub(super) fn display_target_for_file(
    sema: &Semantics<'_, RootDatabase>,
    file_id: ra_ap_ide::FileId,
    db: &RootDatabase,
) -> Option<DisplayTarget> {
    let krate = sema.first_crate(file_id)?;
    Some(DisplayTarget::from_crate(db, krate.into()))
}

/// Extract the simple binding name from a pattern (e.g., `let key = ...` → `"key"`).
pub(super) fn extract_binding_name(pat: &ast::Pat) -> Option<Box<str>> {
    match pat {
        ast::Pat::IdentPat(ident) => ident.name().map(|n| Box::from(n.text().as_str())),
        _ => None,
    }
}

/// Check whether a syntax subtree contains a `NameRef` matching `binding_name`.
pub(super) fn expr_references_binding(expr: &SyntaxNode, binding_name: &str) -> bool {
    expr.descendants()
        .filter(|n| n.kind() == SyntaxKind::NAME_REF)
        .any(|n| n.text() == binding_name)
}

/// Resolve a path-based call expression to its `ra_ap_hir::Function`.
pub(super) fn resolve_call_to_function(
    sema: &Semantics<'_, RootDatabase>,
    call: &ast::CallExpr,
) -> Option<ra_ap_hir::Function> {
    let expr = call.expr()?;
    let path_expr = ast::PathExpr::cast(expr.syntax().clone())?;
    let path = path_expr.path()?;
    let resolution = sema.resolve_path(&path)?;
    match resolution {
        ra_ap_hir::PathResolution::Def(ra_ap_hir::ModuleDef::Function(f)) => Some(f),
        _ => None,
    }
}
