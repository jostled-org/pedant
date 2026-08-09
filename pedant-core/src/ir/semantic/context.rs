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
use ra_ap_vfs::{AbsPathBuf, Vfs, VfsPath};

#[cfg(feature = "semantic")]
use crate::observe::{self, Observation};

#[cfg(feature = "semantic")]
use super::common::with_parsed_file;
#[cfg(feature = "semantic")]
use super::edges::{self, SemanticDefinitionTargets};
#[cfg(feature = "semantic")]
use super::file_analysis::SemanticFileAnalysis;
#[cfg(feature = "semantic")]
use super::snapshot::{self, SemanticSnapshotClaim, SemanticSnapshotMismatch, VerifiedSnapshot};

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
    /// The canonical workspace root this database was loaded at.
    pub(super) root: Box<Path>,
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
        let root = workspace_root.canonicalize().ok()?;
        let cargo_config = cargo_config_minimal(&root)?;
        let load_config = load_config_minimal();
        let (db, vfs, _proc_macro) =
            load_workspace_at(&root, &cargo_config, &load_config, &|_| {}).ok()?;
        observe::record(Observation::SemanticWorkspaceLoad);
        let host = AnalysisHost::with_database(db);
        Some(Self {
            host,
            vfs,
            root: root.into_boxed_path(),
            file_cache: RwLock::new(BTreeMap::new()),
            file_setup_count: Cell::new(0),
        })
    }

    /// The absolute path one repository-relative source has under this root.
    pub(super) fn absolute(&self, relative: &str) -> Box<str> {
        Box::from(self.root.join(relative).to_string_lossy().as_ref())
    }

    /// The repository-relative, `/`-separated path of one database file, when
    /// the file sits beneath this root.
    /// A component that is not UTF-8 answers `None` rather than being replaced
    /// character by character. A lossy rendering names a path that exists
    /// nowhere, and every claim comparison against it fails without saying
    /// why; absence at least reports the file as one this root does not hold.
    pub(super) fn relative_path(&self, file: ra_ap_ide::FileId) -> Option<Box<str>> {
        let path = self.vfs.file_path(file).as_path()?;
        crate::resolution::path_normalization::relative_text(
            self.root.as_ref(),
            Path::new(path.as_str()),
        )
        .ok()
    }

    /// The database file one absolute path names, when the database holds it.
    pub(super) fn file_id(&self, absolute: &str) -> Option<ra_ap_ide::FileId> {
        let path = VfsPath::from(AbsPathBuf::try_from(absolute).ok()?);
        self.vfs.file_id(&path).map(|(file, _)| file)
    }

    /// Prove this database holds exactly what one resolution snapshot claims.
    ///
    /// No query runs after a refusal: the caller receives the difference and
    /// nothing else.
    pub(crate) fn verify_snapshot(
        &self,
        claim: &SemanticSnapshotClaim,
    ) -> Result<VerifiedSnapshot, SemanticSnapshotMismatch> {
        snapshot::verify(self, claim)
    }

    /// Every definition edge the sources of one verified snapshot state.
    ///
    /// A source the database cannot analyze, or a coordinate it cannot read, is
    /// a difference between the database and the snapshot, so it refuses the
    /// pairing rather than answering for a source it never read.
    pub(crate) fn definition_targets(
        &self,
        verified: &VerifiedSnapshot,
    ) -> Result<SemanticDefinitionTargets, SemanticSnapshotMismatch> {
        edges::collect(self, verified)
    }

    /// The analysis of one verified snapshot source, observing the setup its
    /// first analysis performs.
    pub(super) fn analyze_snapshot_file(
        &self,
        relative: &str,
        absolute: &str,
    ) -> Option<Arc<SemanticFileAnalysis>> {
        observe::record(Observation::SemanticQuery(relative));
        match self.cached(absolute) {
            Some(cached) => Some(cached),
            None => self.set_up_snapshot_file(relative, absolute),
        }
    }

    /// The first analysis of one verified snapshot source, observed once the
    /// setup it performs has completed.
    ///
    /// A source that fails to analyze set nothing up, so it records nothing.
    fn set_up_snapshot_file(
        &self,
        relative: &str,
        absolute: &str,
    ) -> Option<Arc<SemanticFileAnalysis>> {
        let analysis = self.analyze_file(absolute)?;
        observe::record(Observation::SemanticFileSetup(relative));
        Some(analysis)
    }

    /// The cached analysis of one file, without building it.
    fn cached(&self, file: &str) -> Option<Arc<SemanticFileAnalysis>> {
        let cache = match self.file_cache.read() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        cache.get(file).map(Arc::clone)
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
        let canonical = canonical_file_path(file)?;
        match self.cached(&canonical) {
            Some(cached) => Some(cached),
            None => with_parsed_file(self, &canonical, |pf| self.cache_analysis(&canonical, pf)),
        }
    }

    fn cache_analysis(
        &self,
        file: &str,
        pf: &super::common::ParsedFile<'_>,
    ) -> Arc<SemanticFileAnalysis> {
        if let Some(cached) = self.cached(file) {
            return cached;
        }
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

/// Minimal `CargoConfig` — no build scripts, no proc macros.
#[cfg(feature = "semantic")]
fn cargo_config_minimal(workspace_root: &Path) -> Option<CargoConfig> {
    let target_path = workspace_root.join("target").join("pedant-semantic");
    let workspace_target = target_path.to_str()?.to_owned();

    Some(CargoConfig {
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
        extra_env: [(String::from("CARGO_TARGET_DIR"), Some(workspace_target))]
            .into_iter()
            .collect(),
        invocation_strategy: Default::default(),
        target_dir_config: Default::default(),
        set_test: false,
        no_deps: false,
        metadata_extra_args: Vec::new(),
        config_path: None,
    })
}

#[cfg(feature = "semantic")]
fn canonical_file_path(file: &str) -> Option<Box<str>> {
    let path = Path::new(file).canonicalize().ok()?;
    Some(Box::from(path.to_str()?))
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
