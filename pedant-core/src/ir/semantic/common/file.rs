//! File parsing and shared semantic helpers.

use super::prelude::*;

/// Parsed file context passed to semantic analysis closures.
///
/// Created once per file by [`with_parsed_file`], then shared across
/// all detection passes to avoid redundant parsing.
pub(in crate::ir::semantic) struct ParsedFile<'a> {
    pub(in crate::ir::semantic) sema: Semantics<'a, RootDatabase>,
    pub(in crate::ir::semantic) tree: ast::SourceFile,
    pub(in crate::ir::semantic) line_index: &'a LineIndex,
    pub(in crate::ir::semantic) db: &'a RootDatabase,
    pub(in crate::ir::semantic) file_id: ra_ap_ide::FileId,
    pub(in crate::ir::semantic) display_target: DisplayTarget,
}

/// Parse a file and run a closure with the parsed context.
///
/// Handles file lookup, database attachment, semantic construction,
/// and line index retrieval. Returns `None` when the file is not in
/// the VFS or the line index cannot be computed.
pub(in crate::ir::semantic) fn with_parsed_file<T>(
    ctx: &SemanticContext,
    file: &str,
    f: impl FnOnce(&ParsedFile<'_>) -> T,
) -> Option<T> {
    ctx.file_setup_count.set(ctx.file_setup_count.get() + 1);
    let (file_id, db) = file_setup(ctx, file)?;
    let analysis = ctx.host.analysis();
    let krate = analysis
        .relevant_crates_for(file_id)
        .ok()?
        .into_iter()
        .next()?;
    let edition = analysis.crate_edition(krate).ok()?;
    let line_index_arc = analysis.file_line_index(file_id).ok()?;
    ra_ap_hir::attach_db(db, || {
        let sema = Semantics::new(db);
        // The crate's own edition, not the newest one: an editioned file id
        // that disagrees with the crate's edition keys into no body source map,
        // which silently costs every inference-backed query its answer. A file
        // no crate holds has no edition of its own, so it is not analyzed at
        // all rather than analyzed under the current edition as a guess.
        let editioned = ra_ap_hir::EditionedFileId::new(db, file_id, edition);
        let tree = sema.parse(editioned);
        Some(f(&ParsedFile {
            sema,
            tree,
            line_index: &line_index_arc,
            db,
            file_id,
            display_target: DisplayTarget::from_crate(db, krate),
        }))
    })
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
pub(in crate::ir::semantic) fn span_from_node(node: &SyntaxNode, line_index: &LineIndex) -> IrSpan {
    let offset = node.text_range().start();
    let lc = line_index.line_col(offset);
    IrSpan {
        line: (lc.line + 1) as usize,
        column: lc.col as usize,
    }
}

/// Construct a quality/perf/concurrency `DataFlowFact` (no capability source/sink).
pub(in crate::ir::semantic) fn quality_fact(
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
pub(in crate::ir::semantic) fn format_type(
    ty: &ra_ap_hir::Type<'_>,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Box<str> {
    ty.display(db, display_target).to_string().into_boxed_str()
}

/// Extract the simple binding name from a pattern (e.g., `let key = ...` → `"key"`).
pub(in crate::ir::semantic) fn extract_binding_name(pat: &ast::Pat) -> Option<Box<str>> {
    match pat {
        ast::Pat::IdentPat(ident) => ident.name().map(|n| Box::from(n.text().as_str())),
        _ => None,
    }
}

/// Check whether a syntax subtree contains a `NameRef` matching `binding_name`.
pub(in crate::ir::semantic) fn expr_references_binding(
    expr: &SyntaxNode,
    binding_name: &str,
) -> bool {
    expr.descendants()
        .filter(|n| n.kind() == SyntaxKind::NAME_REF)
        .any(|n| n.text() == binding_name)
}

/// Resolve a path-based call expression to its `ra_ap_hir::Function`.
pub(in crate::ir::semantic) fn resolve_call_to_function(
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

/// Extract a simple name from a direct path expression (e.g., `x` → `"x"`).
///
/// Returns `None` for qualified paths (`a::b`) or non-path expressions.
pub(in crate::ir::semantic) fn direct_path_name(expr: &ast::Expr) -> Option<Box<str>> {
    let ast::Expr::PathExpr(pe) = expr else {
        return None;
    };
    let path = pe.path()?;
    path.qualifier().is_none().then_some(())?;
    path.segment()?
        .name_ref()
        .map(|n| Box::from(n.text().as_str()))
}

// ---------------------------------------------------------------------------
// Mutation method classification
// ---------------------------------------------------------------------------

/// Methods that mutate `Vec<T>`.
pub(in crate::ir::semantic) const VEC_MUTATION_METHODS: &[&str] = &[
    "push",
    "pop",
    "insert",
    "remove",
    "swap_remove",
    "truncate",
    "clear",
    "retain",
    "reserve",
    "resize",
    "extend",
    "append",
    "splice",
    "drain",
    "dedup",
    "dedup_by",
    "dedup_by_key",
    "sort",
    "sort_by",
    "sort_by_key",
    "sort_unstable",
    "sort_unstable_by",
    "sort_unstable_by_key",
    "reverse",
    "rotate_left",
    "rotate_right",
    "fill",
    "fill_with",
];

/// Methods that mutate `String` (in addition to shared Vec-like methods).
pub(in crate::ir::semantic) const STRING_MUTATION_METHODS: &[&str] =
    &["push_str", "insert_str", "replace_range"];

/// Check whether a method name is a known mutation method on `Vec` or `String`.
pub(in crate::ir::semantic) fn is_mutation_method(method: &str) -> bool {
    VEC_MUTATION_METHODS
        .iter()
        .chain(STRING_MUTATION_METHODS.iter())
        .any(|m| *m == method)
}
