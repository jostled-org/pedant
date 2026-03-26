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
mod common;
#[cfg(feature = "semantic")]
mod concurrency;
#[cfg(feature = "semantic")]
mod perf;
#[cfg(feature = "semantic")]
mod quality;
#[cfg(feature = "semantic")]
mod reachability;
#[cfg(feature = "semantic")]
mod taint;

#[cfg(feature = "semantic")]
use std::path::Path;

#[cfg(feature = "semantic")]
use ra_ap_hir::{DisplayTarget, Semantics};
#[cfg(feature = "semantic")]
use ra_ap_ide::{AnalysisHost, LineCol, RootDatabase};
#[cfg(feature = "semantic")]
use ra_ap_load_cargo::{LoadCargoConfig, ProcMacroServerChoice, load_workspace_at};
#[cfg(feature = "semantic")]
use ra_ap_project_model::{CargoConfig, RustLibSource};
#[cfg(feature = "semantic")]
use ra_ap_syntax::{AstNode, SyntaxNode, ast};

#[cfg(feature = "semantic")]
use super::facts::DataFlowFact;
#[cfg(feature = "semantic")]
use ra_ap_vfs::Vfs;

#[cfg(feature = "semantic")]
use common::{display_target_for_file, format_type, with_fn_body, with_parsed_file};

/// Opaque handle to a loaded rust-analyzer database and VFS.
///
/// All `ra_ap_*` types stay behind this boundary. When the `semantic`
/// feature is disabled, this type exists but cannot be constructed,
/// allowing `analyze()` to accept `Option<&SemanticContext>` unconditionally.
#[cfg(feature = "semantic")]
pub struct SemanticContext {
    pub(super) host: AnalysisHost,
    pub(super) vfs: Vfs,
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
        let checked_line = line.checked_sub(1)?;
        with_parsed_file(self, file, |pf| {
            let offset = pf.line_index.offset(LineCol {
                line: checked_line as u32,
                col: col as u32,
            })?;
            let display_target = display_target_for_file(&pf.sema, pf.file_id, pf.db)?;

            let token = pf.tree.syntax().token_at_offset(offset).right_biased()?;
            token
                .parent_ancestors()
                .find_map(|node| try_resolve_node_type(&pf.sema, &node, pf.db, display_target))
        })
        .flatten()
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
        with_parsed_file(self, file, reachability::build_call_graph).unwrap_or_default()
    }

    /// Trace taint propagation within a single function body.
    ///
    /// Identifies bindings that originate from capability sources (env var reads,
    /// filesystem reads) and detects when tainted values reach capability sinks
    /// (network calls, process exec). Returns one `DataFlowFact` per source→sink
    /// flow detected.
    pub fn trace_taints(&self, file: &str, fn_name: &str) -> Box<[DataFlowFact]> {
        with_fn_body(self, file, fn_name, |pf, _, body, stmt_list| {
            taint::trace_taints_in_fn(pf, body, stmt_list)
        })
        .unwrap_or_default()
    }

    /// Detect quality issues within a single function body.
    ///
    /// Identifies dead stores (value overwritten before read), discarded results
    /// (Result-returning calls without binding), and partial error handling
    /// (Result handled on some paths, dropped on others).
    pub fn detect_quality_issues(&self, file: &str, fn_name: &str) -> Box<[DataFlowFact]> {
        with_fn_body(self, file, fn_name, |pf, _, _, stmt_list| {
            quality::detect_quality_in_fn(pf, stmt_list)
        })
        .unwrap_or_default()
    }

    /// Detect performance issues within a single function body.
    ///
    /// Identifies repeated calls (same function, same arguments), unnecessary
    /// clones (original not used after clone), allocations in loops
    /// (`Vec::new()`, `String::new()`, `format!()` inside loop bodies), and
    /// redundant collects (`.collect()` followed by `.iter()`/`.into_iter()`).
    pub fn detect_performance_issues(&self, file: &str, fn_name: &str) -> Box<[DataFlowFact]> {
        with_fn_body(self, file, fn_name, |pf, _, body, stmt_list| {
            perf::detect_perf_in_fn(pf, body, stmt_list)
        })
        .unwrap_or_default()
    }

    /// Detect lock guards held across `.await` points within a single async function.
    ///
    /// Identifies bindings from `.lock()`, `.read()`, or `.write()` calls that
    /// remain live when an `.await` expression is reached. Returns one
    /// `DataFlowFact` per guard-across-await occurrence.
    pub fn detect_lock_across_await(&self, file: &str, fn_name: &str) -> Box<[DataFlowFact]> {
        with_fn_body(self, file, fn_name, |pf, fn_node, _, stmt_list| {
            concurrency::detect_lock_await_in_fn(pf, fn_node, stmt_list)
        })
        .unwrap_or_default()
    }

    /// Detect inconsistent lock ordering across all functions in a file.
    ///
    /// For each function, records the sequence of `.lock()` acquisitions by
    /// receiver name. When two functions lock the same pair of receivers in
    /// different orders, emits an `InconsistentLockOrder` finding.
    pub fn detect_inconsistent_lock_ordering(&self, file: &str) -> Box<[DataFlowFact]> {
        with_parsed_file(self, file, concurrency::detect_lock_ordering).unwrap_or_default()
    }

    /// Run all data-flow detection passes for every function in `file` using a
    /// single parse. Returns the combined results of taint, quality, performance,
    /// lock-across-await (per-function), and inconsistent lock ordering (file-wide).
    ///
    /// This eliminates the redundant file setup that occurs when each detection
    /// pass is called individually.
    pub(crate) fn enrich_all_data_flows(&self, file: &str) -> Box<[DataFlowFact]> {
        with_parsed_file(self, file, |pf| {
            let mut flows = Vec::new();
            for fn_node in pf.tree.syntax().descendants().filter_map(ast::Fn::cast) {
                let Some(body) = fn_node.body() else {
                    continue;
                };
                let Some(stmt_list) = body.stmt_list() else {
                    continue;
                };
                flows.extend(taint::trace_taints_in_fn(pf, &body, &stmt_list).into_vec());
                flows.extend(quality::detect_quality_in_fn(pf, &stmt_list).into_vec());
                flows.extend(perf::detect_perf_in_fn(pf, &body, &stmt_list).into_vec());
                flows.extend(
                    concurrency::detect_lock_await_in_fn(pf, &fn_node, &stmt_list).into_vec(),
                );
            }
            flows.extend(concurrency::detect_lock_ordering(pf).into_vec());
            flows.into_boxed_slice()
        })
        .unwrap_or_default()
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
        with_parsed_file(self, file, |pf| reachability::check_reachability(pf, lines))
            .unwrap_or_else(|| vec![false; lines.len()].into_boxed_slice())
    }
}

// --- Type resolution helpers (remain in mod.rs — not domain-specific) ---

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
    if let Some(r) = ast::Expr::cast(node.clone())
        .and_then(|expr| sema.type_of_expr(&expr))
        .map(|info| format_type(&info.original, db, display_target))
    {
        return Some(r);
    }

    if let Some(r) = ast::Pat::cast(node.clone())
        .and_then(|pat| sema.type_of_pat(&pat))
        .map(|info| format_type(&info.original, db, display_target))
    {
        return Some(r);
    }

    ast::Type::cast(node.clone()).and_then(|ty_node| {
        sema.resolve_type(&ty_node)
            .map(|ty| format_type(&ty, db, display_target))
            .or_else(|| resolve_path_type(sema, &ty_node, db, display_target))
    })
}

/// Resolve a path type by looking up the path to find what it refers to.
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

// --- Config helpers ---

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
        num_worker_threads: 1,
    }
}
