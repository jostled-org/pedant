//! Adapter module for `ra_ap_ide` semantic analysis.
//!
//! All `ra_ap_*` types are contained within this module. Nothing leaks to the
//! rest of pedant-core. The `SemanticContext` struct exposes a stable internal
//! API that absorbs upstream API churn from rust-analyzer's weekly releases.
//!
//! When the `semantic` feature is disabled, `SemanticContext` and
//! `SemanticFileAnalysis` exist as unconstructable types so that `analyze()`
//! can always accept `Option<&SemanticContext>` without feature gates on the
//! signature.

#[cfg(feature = "semantic")]
mod common;
#[cfg(feature = "semantic")]
mod concurrency;
#[cfg(feature = "semantic")]
mod file_analysis;
#[cfg(feature = "semantic")]
mod function_summary;
#[cfg(feature = "semantic")]
mod perf;
#[cfg(feature = "semantic")]
mod quality;
#[cfg(feature = "semantic")]
mod reachability;
#[cfg(feature = "semantic")]
mod taint;

#[cfg(feature = "semantic")]
pub use file_analysis::SemanticFileAnalysis;
#[cfg(feature = "semantic")]
pub use function_summary::FunctionAnalysisSummary;

#[cfg(feature = "semantic")]
use std::cell::Cell;
#[cfg(feature = "semantic")]
use std::collections::BTreeMap;
#[cfg(feature = "semantic")]
use std::path::Path;
#[cfg(feature = "semantic")]
use std::sync::{Arc, RwLock};

#[cfg(feature = "semantic")]
use ra_ap_ide::AnalysisHost;
#[cfg(feature = "semantic")]
use ra_ap_load_cargo::{LoadCargoConfig, ProcMacroServerChoice, load_workspace_at};
#[cfg(feature = "semantic")]
use ra_ap_project_model::{CargoConfig, RustLibSource};

#[cfg(feature = "semantic")]
use ra_ap_vfs::Vfs;

#[cfg(feature = "semantic")]
use common::with_parsed_file;

/// Function entry: (name, start_line, end_line, is_entry_point).
#[cfg(feature = "semantic")]
type FnEntry = (Box<str>, usize, usize, bool);

/// Opaque handle to a loaded rust-analyzer database and VFS.
///
/// All `ra_ap_*` types stay behind this boundary. When the `semantic`
/// feature is disabled, this type exists but cannot be constructed,
/// allowing `analyze()` to accept `Option<&SemanticContext>` unconditionally.
///
/// `SemanticContext` is a workspace loader. It owns workspace-global
/// rust-analyzer state and caches one `SemanticFileAnalysis` per canonical
/// file path. Public semantic queries delegate through the cached file
/// analysis returned by `analyze_file`.
#[cfg(feature = "semantic")]
pub struct SemanticContext {
    pub(super) host: AnalysisHost,
    pub(super) vfs: Vfs,
    /// Per-file semantic analysis cache. Each entry is built once on first
    /// access via `analyze_file` and shared via `Arc`.
    file_cache: RwLock<BTreeMap<Box<str>, Arc<SemanticFileAnalysis>>>,
    /// Counter tracking `with_parsed_file` invocations (for testing cache reuse).
    pub(super) file_setup_count: Cell<usize>,
}

/// Unconstructable stub — enables `Option<&SemanticContext>` in API signatures
/// without feature gates. Cannot be instantiated when the `semantic` feature
/// is disabled.
#[cfg(not(feature = "semantic"))]
pub struct SemanticContext(());

/// Unconstructable stub — enables `Option<Arc<SemanticFileAnalysis>>` in API
/// signatures without feature gates.
#[cfg(not(feature = "semantic"))]
pub struct SemanticFileAnalysis(());

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
        Some(Self {
            host,
            vfs,
            file_cache: RwLock::new(BTreeMap::new()),
            file_setup_count: Cell::new(0),
        })
    }

    /// Number of times `with_parsed_file` has been invoked on this context.
    ///
    /// Used in tests to verify cache reuse — multiple queries on the same
    /// file should not trigger redundant file setup calls.
    pub fn file_setup_count(&self) -> usize {
        self.file_setup_count.get()
    }

    /// Return the cached analysis for `file`, constructing it on first access.
    ///
    /// On first call for a given file, parses the file and builds the full
    /// `SemanticFileAnalysis` (call graph, reachability, data flows). On
    /// subsequent calls, returns the cached `Arc` without reparsing.
    ///
    /// Returns `None` when the file is not in the VFS or cannot be parsed.
    pub fn analyze_file(&self, file: &str) -> Option<Arc<SemanticFileAnalysis>> {
        // Fast path: return cached analysis under a read lock.
        let cache = match self.file_cache.read() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(cached) = cache.get(file) {
            return Some(Arc::clone(cached));
        }
        drop(cache);

        // Slow path: build analysis, then store under write lock.
        with_parsed_file(self, file, |pf| self.cache_analysis(file, pf))
    }

    /// Return cached analysis or build and cache it from a parsed file context.
    fn cache_analysis(&self, file: &str, pf: &common::ParsedFile<'_>) -> Arc<SemanticFileAnalysis> {
        // Double-check under read lock (another thread may have built it).
        let cache = match self.file_cache.read() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(cached) = cache.get(file).cloned() {
            return cached;
        }
        drop(cache);
        let arc = Arc::new(SemanticFileAnalysis::build(pf));
        let mut cache = match self.file_cache.write() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        cache.insert(Box::from(file), Arc::clone(&arc));
        arc
    }

    /// Resolve the type at a source position to its canonical name, following aliases.
    ///
    /// Delegates to the cached `SemanticFileAnalysis` — no reparsing occurs
    /// after the file has been analyzed.
    ///
    /// Returns `None` when no type can be determined (e.g., macro-generated code).
    pub fn resolve_type(&self, file: &str, line: usize, col: usize) -> Option<Box<str>> {
        let analysis = self.analyze_file(file)?;
        analysis.resolve_type(line, col).map(Box::from)
    }

    /// Static lookup: `true` when `type_name` is a known `Copy` primitive.
    ///
    /// Does not query the database. For resolved types, use enriched IR fields.
    pub fn is_copy(type_name: &str) -> bool {
        COPY_PRIMITIVES.contains(&type_name)
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
