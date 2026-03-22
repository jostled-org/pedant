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
use ra_ap_hir::{DisplayTarget, EditionedFileId, HirDisplay, Semantics};
#[cfg(feature = "semantic")]
use ra_ap_ide::{AnalysisHost, LineCol, RootDatabase};
#[cfg(feature = "semantic")]
use ra_ap_load_cargo::{LoadCargoConfig, ProcMacroServerChoice, load_workspace_at};
#[cfg(feature = "semantic")]
use ra_ap_project_model::{CargoConfig, RustLibSource};
#[cfg(feature = "semantic")]
use ra_ap_syntax::{AstNode, SyntaxNode, ast};
#[cfg(feature = "semantic")]
use ra_ap_vfs::{AbsPathBuf, Vfs, VfsPath};

/// Opaque semantic analysis context backed by `ra_ap_ide`.
///
/// Holds the rust-analyzer database and VFS for a loaded Cargo workspace.
/// All queries go through this type — no `ra_ap_*` types are exposed.
///
/// When the `semantic` feature is disabled, this type exists but cannot be
/// constructed. This allows `analyze()` to accept `Option<&SemanticContext>`
/// unconditionally.
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
    /// Load semantic context from a Cargo workspace root.
    ///
    /// Returns `None` if loading fails (missing `Cargo.toml`, build errors, etc.).
    pub fn load(workspace_root: &Path) -> Option<Self> {
        let cargo_config = cargo_config_minimal();
        let load_config = load_config_minimal();
        let (db, vfs, _proc_macro) =
            load_workspace_at(workspace_root, &cargo_config, &load_config, &|_| {}).ok()?;
        let host = AnalysisHost::with_database(db);
        Some(Self { host, vfs })
    }

    /// Resolve a type at a given file position to its canonical name.
    ///
    /// Resolves through type aliases to the underlying type.
    /// Returns `None` if no type can be determined at the position.
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

    /// Check if a type name corresponds to a `Copy` type.
    ///
    /// Uses a known set of primitive types. For resolved types from the
    /// semantic database, use the enriched IR fields (added in Step 2).
    /// Does not access instance state — operates on a static lookup table.
    pub fn is_copy(type_name: &str) -> bool {
        COPY_PRIMITIVES.contains(&type_name)
    }

    /// Map an absolute file path to a VFS `FileId`.
    fn file_id_for_path(&self, path: &str) -> Option<ra_ap_ide::FileId> {
        let abs = AbsPathBuf::try_from(path).ok()?;
        let vfs_path = VfsPath::from(abs);
        let (file_id, _excluded) = self.vfs.file_id(&vfs_path)?;
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
