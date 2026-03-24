//! Adapter module for `ra_ap_ide` semantic analysis.
//!
//! All `ra_ap_*` types are contained within this module. Nothing leaks to the
//! rest of pedant-core. The `SemanticContext` struct exposes a stable internal
//! API that absorbs upstream API churn from rust-analyzer's weekly releases.
//!
//! When the `semantic` feature is disabled, `SemanticContext` exists as an
//! unconstructable type so that `analyze()` can always accept
//! `Option<&SemanticContext>` without feature gates on the signature.

#[cfg(feature = "semantic")]
use std::path::Path;

#[cfg(feature = "semantic")]
use pedant_types::Capability;
#[cfg(feature = "semantic")]
use ra_ap_hir::{DisplayTarget, EditionedFileId, HirDisplay, Semantics};
#[cfg(feature = "semantic")]
use ra_ap_ide::{AnalysisHost, LineCol, RootDatabase};
#[cfg(feature = "semantic")]
use ra_ap_load_cargo::{LoadCargoConfig, ProcMacroServerChoice, load_workspace_at};
#[cfg(feature = "semantic")]
use ra_ap_project_model::{CargoConfig, RustLibSource};
#[cfg(feature = "semantic")]
use ra_ap_syntax::ast::HasName;
#[cfg(feature = "semantic")]
use ra_ap_syntax::ast::{HasAttrs, HasVisibility};
#[cfg(feature = "semantic")]
use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, ast};

#[cfg(feature = "semantic")]
use line_index::LineIndex;

#[cfg(feature = "semantic")]
use super::facts::{DataFlowFact, IrSpan};
#[cfg(feature = "semantic")]
use ra_ap_vfs::{AbsPathBuf, Vfs, VfsPath};

/// Opaque handle to a loaded rust-analyzer database and VFS.
///
/// All `ra_ap_*` types stay behind this boundary. When the `semantic`
/// feature is disabled, this type exists but cannot be constructed,
/// allowing `analyze()` to accept `Option<&SemanticContext>` unconditionally.
#[cfg(feature = "semantic")]
pub struct SemanticContext {
    host: AnalysisHost,
    vfs: Vfs,
}

/// Unconstructable stub — enables `Option<&SemanticContext>` in API signatures
/// without feature gates. Cannot be instantiated when the `semantic` feature
/// is disabled.
#[cfg(not(feature = "semantic"))]
pub struct SemanticContext(());

/// Known primitive types that implement `Copy`.
#[cfg(feature = "semantic")]
const COPY_PRIMITIVES: &[&str] = &[
    "bool", "char", "f32", "f64", "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32",
    "u64", "u128", "usize",
];

#[cfg(feature = "semantic")]
impl SemanticContext {
    /// Attempt to load a rust-analyzer database from the Cargo workspace at `workspace_root`.
    ///
    /// Returns `None` on any loading failure (missing manifest, build errors, etc.).
    pub fn load(workspace_root: &Path) -> Option<Self> {
        let cargo_config = cargo_config_minimal();
        let load_config = load_config_minimal();
        let (db, vfs, _proc_macro) =
            load_workspace_at(workspace_root, &cargo_config, &load_config, &|_| {}).ok()?;
        let host = AnalysisHost::with_database(db);
        Some(Self { host, vfs })
    }

    /// Resolve the type at a source position to its canonical name, following aliases.
    ///
    /// Returns `None` when no type can be determined (e.g., macro-generated code).
    pub fn resolve_type(&self, file: &str, line: usize, col: usize) -> Option<Box<str>> {
        let file_id = self.file_id_for_path(file)?;
        let db = self.host.raw_database();
        let analysis = self.host.analysis();
        let line_index = analysis.file_line_index(file_id).ok()?;
        let offset = line_index.offset(LineCol {
            line: (line.checked_sub(1)?) as u32,
            col: col as u32,
        })?;

        // attach_db makes the database available to the trait solver.
        ra_ap_hir::attach_db(db, || {
            let sema = Semantics::new(db);
            let editioned = EditionedFileId::current_edition(db, file_id);
            let tree = sema.parse(editioned);
            let display_target = display_target_for_file(&sema, file_id, db)?;

            let token = tree.syntax().token_at_offset(offset).right_biased()?;
            token
                .parent_ancestors()
                .find_map(|node| try_resolve_node_type(&sema, &node, db, display_target))
        })
    }

    /// Static lookup: `true` when `type_name` is a known `Copy` primitive.
    ///
    /// Does not query the database. For resolved types, use enriched IR fields.
    pub fn is_copy(type_name: &str) -> bool {
        COPY_PRIMITIVES.contains(&type_name)
    }

    /// Build a call graph for all functions in `file`.
    ///
    /// Returns deduplicated `(caller, callee)` pairs where both names are the
    /// simple function name (not fully qualified). Only resolves calls to known
    /// functions — unresolved calls are silently skipped.
    pub fn call_graph(&self, file: &str) -> Box<[(Box<str>, Box<str>)]> {
        let file_id = match self.file_id_for_path(file) {
            Some(id) => id,
            None => return Box::new([]),
        };
        let db = self.host.raw_database();

        ra_ap_hir::attach_db(db, || {
            let sema = Semantics::new(db);
            let editioned = EditionedFileId::current_edition(db, file_id);
            let tree = sema.parse(editioned);
            let mut edges = Vec::new();

            for fn_node in tree.syntax().descendants().filter_map(ast::Fn::cast) {
                collect_fn_call_edges(&sema, &fn_node, db, &mut edges);
            }

            edges.sort();
            edges.dedup();
            edges.into_boxed_slice()
        })
    }

    /// Trace taint propagation within a single function body.
    ///
    /// Identifies bindings that originate from capability sources (env var reads,
    /// filesystem reads) and detects when tainted values reach capability sinks
    /// (network calls, process exec). Returns one `DataFlowFact` per source→sink
    /// flow detected.
    pub fn trace_taints(&self, file: &str, fn_name: &str) -> Box<[DataFlowFact]> {
        let empty: Box<[DataFlowFact]> = Box::new([]);
        let file_id = match self.file_id_for_path(file) {
            Some(id) => id,
            None => return empty,
        };
        let db = self.host.raw_database();
        let analysis = self.host.analysis();
        let line_index = match analysis.file_line_index(file_id).ok() {
            Some(li) => li,
            None => return empty,
        };

        ra_ap_hir::attach_db(db, || {
            let sema = Semantics::new(db);
            let editioned = EditionedFileId::current_edition(db, file_id);
            let tree = sema.parse(editioned);

            let fn_node = tree
                .syntax()
                .descendants()
                .filter_map(ast::Fn::cast)
                .find(|f| f.name().map(|n| n.text() == fn_name).unwrap_or(false));

            let fn_node = match fn_node {
                Some(f) => f,
                None => return Box::<[DataFlowFact]>::default(),
            };
            let body = match fn_node.body() {
                Some(b) => b,
                None => return Box::<[DataFlowFact]>::default(),
            };
            let stmt_list = match body.stmt_list() {
                Some(sl) => sl,
                None => return Box::<[DataFlowFact]>::default(),
            };

            // Phase 1: identify tainted bindings from capability sources.
            let tainted: Box<[Taint]> =
                collect_tainted_bindings(&sema, &stmt_list, db, &line_index);

            // Phase 2: detect when tainted bindings flow to capability sinks.
            collect_taint_flows(&sema, &body, db, &line_index, &tainted)
        })
    }

    /// Determine whether the function containing `line` is reachable from any
    /// public entry point (`pub fn`, `main`, `#[test]`).
    ///
    /// Uses the call graph to compute transitive reachability. Returns `false`
    /// when the line does not fall within any function or the file cannot be loaded.
    pub fn is_reachable(&self, file: &str, line: usize) -> bool {
        self.check_reachability_batch(file, &[line])
            .first()
            .copied()
            .unwrap_or(false)
    }

    /// Batch reachability check: builds the call graph once for `file`, then
    /// checks each line in `lines`. Returns one `bool` per input line.
    pub fn check_reachability_batch(&self, file: &str, lines: &[usize]) -> Box<[bool]> {
        let file_id = match self.file_id_for_path(file) {
            Some(id) => id,
            None => return vec![false; lines.len()].into_boxed_slice(),
        };
        let db = self.host.raw_database();

        ra_ap_hir::attach_db(db, || {
            let sema = Semantics::new(db);
            let editioned = EditionedFileId::current_edition(db, file_id);
            let tree = sema.parse(editioned);
            let analysis = self.host.analysis();
            let line_index = match analysis.file_line_index(file_id).ok() {
                Some(li) => li,
                None => return vec![false; lines.len()].into_boxed_slice(),
            };

            let fns: Box<[FnEntry]> = tree
                .syntax()
                .descendants()
                .filter_map(ast::Fn::cast)
                .filter_map(|f| fn_entry(&f, &line_index))
                .collect::<Vec<_>>()
                .into_boxed_slice();

            let edges = self.call_graph(file);

            lines
                .iter()
                .map(|&line| is_line_reachable(&fns, &edges, line))
                .collect::<Vec<_>>()
                .into_boxed_slice()
        })
    }

    /// Map an absolute file path to a VFS `FileId`.
    fn file_id_for_path(&self, path: &str) -> Option<ra_ap_ide::FileId> {
        let abs = AbsPathBuf::try_from(path).ok()?;
        let vfs_path = VfsPath::from(abs);
        let (file_id, _) = self.vfs.file_id(&vfs_path)?;
        Some(file_id)
    }
}

/// Try to resolve a syntax node to a type string.
///
/// Attempts casts in order: expression, pattern, type annotation.
/// Returns `None` if the node does not have a resolvable type.
#[cfg(feature = "semantic")]
fn try_resolve_node_type(
    sema: &Semantics<'_, RootDatabase>,
    node: &SyntaxNode,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Option<Box<str>> {
    // SyntaxNode::clone is cheap (Rc-based tree).
    // Try as expression first.
    if let Some(r) = ast::Expr::cast(node.clone())
        .and_then(|expr| sema.type_of_expr(&expr))
        .map(|info| format_type(&info.original, db, display_target))
    {
        return Some(r);
    }

    // Try as pattern.
    if let Some(r) = ast::Pat::cast(node.clone())
        .and_then(|pat| sema.type_of_pat(&pat))
        .map(|info| format_type(&info.original, db, display_target))
    {
        return Some(r);
    }

    // Try as type annotation — resolve through aliases via sema.resolve_type.
    // Falls back to path resolution for types in function signatures.
    ast::Type::cast(node.clone()).and_then(|ty_node| {
        sema.resolve_type(&ty_node)
            .map(|ty| format_type(&ty, db, display_target))
            .or_else(|| resolve_path_type(sema, &ty_node, db, display_target))
    })
}

/// Resolve a path type by looking up the path to find what it refers to.
///
/// Handles type aliases in function signatures where `sema.resolve_type()`
/// cannot resolve because the source map doesn't cover signature positions.
#[cfg(feature = "semantic")]
fn resolve_path_type(
    sema: &Semantics<'_, RootDatabase>,
    ty: &ast::Type,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Option<Box<str>> {
    let path_type = match ty {
        ast::Type::PathType(p) => p.path()?,
        _ => return None,
    };
    let resolution = sema.resolve_path(&path_type)?;
    match resolution {
        ra_ap_hir::PathResolution::Def(module_def) => {
            resolve_module_def_type(module_def, db, display_target)
        }
        _ => None,
    }
}

/// Get the type representation for a module-level definition.
#[cfg(feature = "semantic")]
fn resolve_module_def_type(
    def: ra_ap_hir::ModuleDef,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Option<Box<str>> {
    match def {
        ra_ap_hir::ModuleDef::TypeAlias(alias) => {
            let ty = alias.ty(db);
            Some(format_type(&ty, db, display_target))
        }
        ra_ap_hir::ModuleDef::Adt(adt) => {
            let ty = adt.ty(db);
            Some(format_type(&ty, db, display_target))
        }
        ra_ap_hir::ModuleDef::BuiltinType(builtin) => Some(builtin.name().as_str().into()),
        _ => None,
    }
}

/// Collect call edges from a single function's body into `edges`.
#[cfg(feature = "semantic")]
fn collect_fn_call_edges(
    sema: &Semantics<'_, RootDatabase>,
    fn_node: &ast::Fn,
    db: &RootDatabase,
    edges: &mut Vec<(Box<str>, Box<str>)>,
) {
    let name = match fn_node.name() {
        Some(n) => n,
        None => return,
    };
    let Some(body) = fn_node.body() else {
        return;
    };

    for node in body.syntax().descendants() {
        if let Some(callee_name) = resolve_node_callee(sema, node, db) {
            edges.push((name.text().to_string().into_boxed_str(), callee_name));
        }
    }
}

/// Try to resolve a syntax node as a call target using kind-based dispatch.
///
/// Checks `SyntaxKind` first to avoid cloning the node for multiple cast attempts.
#[cfg(feature = "semantic")]
fn resolve_node_callee(
    sema: &Semantics<'_, RootDatabase>,
    node: SyntaxNode,
    db: &RootDatabase,
) -> Option<Box<str>> {
    match node.kind() {
        SyntaxKind::CALL_EXPR => {
            ast::CallExpr::cast(node).and_then(|call| resolve_call_callee(sema, &call, db))
        }
        SyntaxKind::METHOD_CALL_EXPR => {
            ast::MethodCallExpr::cast(node).and_then(|mc| resolve_method_callee(sema, &mc, db))
        }
        _ => None,
    }
}

/// Resolve the callee of a path-based call expression (e.g., `fetch()`, `TcpStream::connect(...)`).
#[cfg(feature = "semantic")]
fn resolve_call_callee(
    sema: &Semantics<'_, RootDatabase>,
    call: &ast::CallExpr,
    db: &RootDatabase,
) -> Option<Box<str>> {
    let func = resolve_call_to_function(sema, call)?;
    Some(Box::from(func.name(db).as_str()))
}

/// Resolve the callee of a method call expression (e.g., `x.clone()`).
#[cfg(feature = "semantic")]
fn resolve_method_callee(
    sema: &Semantics<'_, RootDatabase>,
    method_call: &ast::MethodCallExpr,
    db: &RootDatabase,
) -> Option<Box<str>> {
    let func = sema.resolve_method_call(method_call)?;
    Some(Box::from(func.name(db).as_str()))
}

/// Build a `DisplayTarget` for rendering types from a given file.
///
/// Returns `None` if the file does not belong to any crate.
#[cfg(feature = "semantic")]
fn display_target_for_file(
    sema: &Semantics<'_, RootDatabase>,
    file_id: ra_ap_ide::FileId,
    db: &RootDatabase,
) -> Option<DisplayTarget> {
    let krate = sema.first_crate(file_id)?;
    Some(DisplayTarget::from_crate(db, krate.into()))
}

/// Format a resolved `Type` as a canonical string.
#[cfg(feature = "semantic")]
fn format_type(
    ty: &ra_ap_hir::Type<'_>,
    db: &RootDatabase,
    display_target: DisplayTarget,
) -> Box<str> {
    ty.display(db, display_target).to_string().into_boxed_str()
}

/// Minimal `CargoConfig` — no build scripts, no proc macros.
#[cfg(feature = "semantic")]
fn cargo_config_minimal() -> CargoConfig {
    CargoConfig {
        all_targets: false,
        features: Default::default(),
        target: None,
        sysroot: Some(RustLibSource::Discover),
        sysroot_src: None,
        rustc_source: None,
        extra_includes: Vec::new(),
        cfg_overrides: Default::default(),
        wrap_rustc_in_build_scripts: false,
        run_build_script_command: None,
        extra_args: Vec::new(),
        extra_env: Default::default(),
        invocation_strategy: Default::default(),
        target_dir_config: Default::default(),
        set_test: false,
        no_deps: false,
    }
}

/// Minimal `LoadCargoConfig` — no build scripts, no proc macros, no cache prefill.
#[cfg(feature = "semantic")]
fn load_config_minimal() -> LoadCargoConfig {
    LoadCargoConfig {
        load_out_dirs_from_check: false,
        with_proc_macro_server: ProcMacroServerChoice::None,
        prefill_caches: false,
        proc_macro_processes: 0,
    }
}

// --- Taint propagation helpers ---

/// Tainted binding: (name, source capability, source span).
#[cfg(feature = "semantic")]
type Taint = (Box<str>, Capability, IrSpan);

/// Known function patterns that produce tainted values.
#[cfg(feature = "semantic")]
const SOURCE_PATTERNS: &[(&str, &[&str], Capability)] = &[
    ("var", &["env"], Capability::EnvAccess),
    ("var_os", &["env"], Capability::EnvAccess),
    ("read", &["fs"], Capability::FileRead),
    ("read_to_string", &["fs"], Capability::FileRead),
    ("read_dir", &["fs"], Capability::FileRead),
    ("read_link", &["fs"], Capability::FileRead),
];

/// Known module segments that indicate a capability sink.
#[cfg(feature = "semantic")]
const SINK_MODULES: &[(&str, Capability)] = &[
    ("net", Capability::Network),
    ("process", Capability::ProcessExec),
];

/// Scan let-bindings in a statement list for capability source initializers.
#[cfg(feature = "semantic")]
fn collect_tainted_bindings(
    sema: &Semantics<'_, RootDatabase>,
    stmt_list: &ast::StmtList,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Box<[Taint]> {
    stmt_list
        .statements()
        .filter_map(|stmt| match stmt {
            ast::Stmt::LetStmt(let_stmt) => Some(let_stmt),
            _ => None,
        })
        .filter_map(|let_stmt| {
            let pat = let_stmt.pat()?;
            let init = let_stmt.initializer()?;
            let (cap, span) = find_source_in_expr(sema, init.syntax(), db, line_index)?;
            let name = extract_binding_name(&pat)?;
            Some((name, cap, span))
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Walk a function body for sink calls that consume tainted bindings.
#[cfg(feature = "semantic")]
fn collect_taint_flows(
    sema: &Semantics<'_, RootDatabase>,
    body: &ast::BlockExpr,
    db: &RootDatabase,
    line_index: &LineIndex,
    tainted: &[Taint],
) -> Box<[DataFlowFact]> {
    body.syntax()
        .descendants()
        .flat_map(|node| {
            let (sink_cap, sink_span) = classify_node_as_sink(sema, &node, db, line_index)?;
            Some(
                tainted
                    .iter()
                    .filter(move |(name, _, _)| expr_references_binding(&node, name))
                    .map(move |(_, cap, src_span)| DataFlowFact {
                        source_capability: *cap,
                        source_span: *src_span,
                        sink_capability: sink_cap,
                        sink_span,
                        call_chain: Box::new([]),
                    }),
            )
        })
        .flatten()
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Classify a syntax node as a capability sink (call or method call).
#[cfg(feature = "semantic")]
fn classify_node_as_sink(
    sema: &Semantics<'_, RootDatabase>,
    node: &SyntaxNode,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Option<(Capability, IrSpan)> {
    match node.kind() {
        SyntaxKind::CALL_EXPR => {
            let call = ast::CallExpr::cast(node.clone())?;
            classify_call_as_sink(sema, &call, db, line_index)
        }
        SyntaxKind::METHOD_CALL_EXPR => {
            let mc = ast::MethodCallExpr::cast(node.clone())?;
            classify_method_call_as_sink(sema, &mc, db, line_index)
        }
        _ => None,
    }
}

/// Walk an expression subtree to find a capability source call.
#[cfg(feature = "semantic")]
fn find_source_in_expr(
    sema: &Semantics<'_, RootDatabase>,
    expr: &SyntaxNode,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Option<(Capability, IrSpan)> {
    expr.descendants().find_map(|node| match node.kind() {
        SyntaxKind::CALL_EXPR => {
            let call = ast::CallExpr::cast(node)?;
            let func = resolve_call_to_function(sema, &call)?;
            let cap = classify_function_as_source(func, db)?;
            Some((cap, span_from_node(call.syntax(), line_index)))
        }
        _ => None,
    })
}

/// Resolve a path-based call expression to its `ra_ap_hir::Function`.
#[cfg(feature = "semantic")]
fn resolve_call_to_function(
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

/// Classify a resolved function as a capability source by checking its module path.
#[cfg(feature = "semantic")]
fn classify_function_as_source(func: ra_ap_hir::Function, db: &RootDatabase) -> Option<Capability> {
    let name = func.name(db);
    let name_str = name.as_str();
    let module_segments = build_module_path(func.module(db), db);

    SOURCE_PATTERNS
        .iter()
        .find_map(|(fn_name, required_segments, cap)| {
            let name_matches = name_str == *fn_name;
            let path_matches = required_segments
                .iter()
                .all(|seg| module_segments.iter().any(|m| m.as_ref() == *seg));
            (name_matches && path_matches).then_some(*cap)
        })
}

/// Classify a path-based call expression as a capability sink.
///
/// Tries semantic resolution first. Falls back to resolving the qualifier
/// type's module path for associated function calls (e.g., `TcpStream::connect`)
/// where `sema.resolve_path` on the full path returns `None`.
#[cfg(feature = "semantic")]
fn classify_call_as_sink(
    sema: &Semantics<'_, RootDatabase>,
    call: &ast::CallExpr,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Option<(Capability, IrSpan)> {
    // Try full path resolution first (works for module-level functions).
    if let Some(func) = resolve_call_to_function(sema, call) {
        let cap = classify_function_as_sink(func, db)?;
        return Some((cap, span_from_node(call.syntax(), line_index)));
    }
    // Fallback: resolve the qualifier type for associated function calls.
    let cap = classify_qualified_call_by_type(sema, call, db)?;
    Some((cap, span_from_node(call.syntax(), line_index)))
}

/// Classify an associated function call by resolving the qualifier type's module.
///
/// For `TcpStream::connect(...)`, resolves `TcpStream` to its defining module
/// and checks whether that module is a known capability sink.
#[cfg(feature = "semantic")]
fn classify_qualified_call_by_type(
    sema: &Semantics<'_, RootDatabase>,
    call: &ast::CallExpr,
    db: &RootDatabase,
) -> Option<Capability> {
    let expr = call.expr()?;
    let path_expr = ast::PathExpr::cast(expr.syntax().clone())?;
    let path = path_expr.path()?;
    let qualifier = path.qualifier()?;
    let resolution = sema.resolve_path(&qualifier)?;
    match resolution {
        ra_ap_hir::PathResolution::Def(module_def) => {
            let module = module_def_module(module_def, db)?;
            let segments = build_module_path(module, db);
            match_sink_module(&segments)
        }
        _ => None,
    }
}

/// Get the defining module for a `ModuleDef`.
#[cfg(feature = "semantic")]
fn module_def_module(def: ra_ap_hir::ModuleDef, db: &RootDatabase) -> Option<ra_ap_hir::Module> {
    match def {
        ra_ap_hir::ModuleDef::Adt(adt) => Some(adt.module(db)),
        ra_ap_hir::ModuleDef::Function(f) => Some(f.module(db)),
        ra_ap_hir::ModuleDef::Module(m) => Some(m),
        ra_ap_hir::ModuleDef::TypeAlias(ta) => Some(ta.module(db)),
        ra_ap_hir::ModuleDef::Trait(t) => Some(t.module(db)),
        _ => None,
    }
}

/// Classify a method call expression as a capability sink.
#[cfg(feature = "semantic")]
fn classify_method_call_as_sink(
    sema: &Semantics<'_, RootDatabase>,
    method_call: &ast::MethodCallExpr,
    db: &RootDatabase,
    line_index: &LineIndex,
) -> Option<(Capability, IrSpan)> {
    let func = sema.resolve_method_call(method_call)?;
    let cap = classify_function_as_sink(func, db)?;
    Some((cap, span_from_node(method_call.syntax(), line_index)))
}

/// Classify a resolved function as a capability sink by checking its module path.
#[cfg(feature = "semantic")]
fn classify_function_as_sink(func: ra_ap_hir::Function, db: &RootDatabase) -> Option<Capability> {
    let module_segments = build_module_path(func.module(db), db);
    match_sink_module(&module_segments)
}

/// Check whether any segment in a module path matches a known sink module.
#[cfg(feature = "semantic")]
fn match_sink_module(segments: &[Box<str>]) -> Option<Capability> {
    SINK_MODULES.iter().find_map(|(segment, cap)| {
        segments
            .iter()
            .any(|m| m.as_ref() == *segment)
            .then_some(*cap)
    })
}

/// Build the module path from a module to the crate root.
///
/// Returns segments in root-to-leaf order (e.g., `["std", "env"]`).
#[cfg(feature = "semantic")]
fn build_module_path(module: ra_ap_hir::Module, db: &RootDatabase) -> Box<[Box<str>]> {
    let mut segments = Vec::new();
    let mut current = Some(module);
    while let Some(m) = current {
        if let Some(name) = m.name(db) {
            segments.push(Box::from(name.as_str()));
        }
        current = m.parent(db);
    }
    segments.reverse();
    segments.into_boxed_slice()
}

/// Check whether a syntax subtree contains a `NameRef` matching `binding_name`.
#[cfg(feature = "semantic")]
fn expr_references_binding(expr: &SyntaxNode, binding_name: &str) -> bool {
    expr.descendants()
        .filter(|n| n.kind() == SyntaxKind::NAME_REF)
        .any(|n| n.text() == binding_name)
}

/// Extract the simple binding name from a pattern (e.g., `let key = ...` → `"key"`).
#[cfg(feature = "semantic")]
fn extract_binding_name(pat: &ast::Pat) -> Option<Box<str>> {
    match pat {
        ast::Pat::IdentPat(ident) => ident.name().map(|n| Box::from(n.text().as_str())),
        _ => None,
    }
}

/// Convert a `SyntaxNode` position to an `IrSpan` using the file's line index.
#[cfg(feature = "semantic")]
fn span_from_node(node: &SyntaxNode, line_index: &LineIndex) -> IrSpan {
    let offset = node.text_range().start();
    let lc = line_index.line_col(offset);
    IrSpan {
        line: (lc.line + 1) as usize,
        column: lc.col as usize,
    }
}

// --- Reachability helpers ---

/// Function entry: (name, start_line, end_line, is_entry_point).
#[cfg(feature = "semantic")]
type FnEntry = (Box<str>, usize, usize, bool);

/// Extract function metadata from an `ast::Fn` node.
#[cfg(feature = "semantic")]
fn fn_entry(f: &ast::Fn, line_index: &LineIndex) -> Option<FnEntry> {
    let name = Box::from(f.name()?.text().as_str());
    let range = f.syntax().text_range();
    let start = line_index.line_col(range.start());
    let end = line_index.line_col(range.end());
    let is_pub = f.visibility().is_some();
    let is_main = &*name == "main";
    let is_test = f.attrs().any(|attr: ast::Attr| {
        attr.path()
            .map(|p: ast::Path| p.syntax().text() == "test")
            .unwrap_or(false)
    });
    Some((
        name,
        (start.line + 1) as usize,
        (end.line + 1) as usize,
        is_pub || is_main || is_test,
    ))
}

/// Check whether a single line falls within a reachable function.
#[cfg(feature = "semantic")]
fn is_line_reachable(fns: &[FnEntry], edges: &[(Box<str>, Box<str>)], line: usize) -> bool {
    let target = match fns
        .iter()
        .find(|(_, start, end, _)| line >= *start && line <= *end)
    {
        Some((name, _, _, _)) => name,
        None => return false,
    };

    let is_entry = fns
        .iter()
        .any(|(name, _, _, entry)| name == target && *entry);
    match is_entry {
        true => true,
        false => reachable_from_entries(fns, edges, target),
    }
}

/// BFS from entry points through call graph edges to determine reachability.
#[cfg(feature = "semantic")]
fn reachable_from_entries(fns: &[FnEntry], edges: &[(Box<str>, Box<str>)], target: &str) -> bool {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    // Build adjacency list for O(V+E) BFS instead of O(V*E).
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (caller, callee) in edges {
        adj.entry(caller).or_default().push(callee);
    }

    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();

    for (name, _, _, is_entry) in fns {
        if *is_entry {
            visited.insert(&**name);
            queue.push_back(&**name);
        }
    }

    while let Some(current) = queue.pop_front() {
        if current == target {
            return true;
        }
        let callees = match adj.get(current) {
            Some(c) => c,
            None => continue,
        };
        for callee in callees {
            if visited.insert(*callee) {
                queue.push_back(callee);
            }
        }
    }

    false
}
