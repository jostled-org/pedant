//! Claims about one target's module closure: what it contains, what it refuses,
//! and what the production readers may open while it runs.

use pedant_core::resolution::rust::{RustTargetSnapshot, SourceClosureFailureKind, TargetId};

#[cfg(feature = "resolution-test-support")]
use crate::resolution::closure_fixtures::ENTRY_ONLY_READS;
use crate::resolution::closure_fixtures::{
    CFG_ATTR_PATH_LOADED_SIBLINGS, CLOSURE_CASES, EXCLUDED_FROM_LIBRARY_CLOSURE,
    EXPECTED_CFG_ATTR_PATH_LOADED_MODULES, EXPECTED_CFG_ATTR_PATH_LOADED_SOURCES,
    EXPECTED_LIBRARY_CLOSURE, EXPECTED_PATH_LOADED_SOURCES, EXPECTED_REPETITION_MODULES,
    EXPECTED_REPETITION_SOURCES, MISSING_MODULE, MODULE_REPETITION, PATH_ESCAPE,
    PATH_LOADED_SIBLING,
};
use crate::resolution::fixture;
#[cfg(feature = "resolution-test-support")]
use crate::resolution::views::observed_paths;
use crate::resolution::views::{
    app_library, closure_kinds, reached_paths, root_modules, source_paths,
};

/// The closure holds every module form the fixture declares and nothing else.
pub fn assert_library_closure(snapshot: &RustTargetSnapshot, library: TargetId) {
    assert_eq!(
        source_paths(snapshot),
        EXPECTED_LIBRARY_CLOSURE,
        "standard, nested, #[path], and inline-owned modules all belong to the closure"
    );
    assert_eq!(
        snapshot.crate_root(),
        "src/lib.rs",
        "the snapshot records the target's entry point"
    );
    assert_eq!(snapshot.target(), library, "the snapshot keeps its target");
    for excluded in EXCLUDED_FROM_LIBRARY_CLOSURE {
        assert!(
            snapshot.source(excluded).is_none(),
            "{excluded} is not module-reachable from src/lib.rs"
        );
    }
}

/// Each stored source keeps its exact text, its one-pass IR, and its own digest.
pub fn assert_source_evidence(snapshot: &RustTargetSnapshot) {
    let standard = snapshot
        .source("src/standard.rs")
        .expect("a reached source");
    assert_eq!(
        standard.text(),
        "#[path = \"sibling.rs\"]\npub mod sibling;\n\npub fn standard() {}\n",
        "the snapshot keeps the exact source text"
    );
    let names: Vec<&str> = standard
        .ir()
        .functions
        .iter()
        .map(|fact| &*fact.name)
        .collect();
    assert_eq!(names, ["standard"], "each source carries its one-pass IR");
    let leaf = snapshot
        .source("src/nested/leaf.rs")
        .expect("a reached source");
    assert_ne!(
        standard.digest(),
        leaf.digest(),
        "distinct source bytes hash distinctly"
    );
}

/// A source selected by `#[path]` resolves its ordinary child beside itself,
/// not beneath a directory derived from its file stem.
pub fn assert_path_loaded_source_uses_sibling_directory() {
    let tmp = fixture::build_repository(PATH_LOADED_SIBLING, false);
    let project = fixture::load_default(&tmp);
    let snapshot = project
        .snapshot_target(app_library(&project))
        .expect("the explicitly pathed module closes");
    assert_eq!(
        source_paths(&snapshot),
        EXPECTED_PATH_LOADED_SOURCES,
        "#[path] makes platform.rs children relative to the directory that contains platform.rs"
    );
    assert!(
        snapshot.source("src/platform/sibling.rs").is_none(),
        "the platform stem directory is not the lookup base for an explicitly pathed source"
    );
}

/// Every conditional path alternative keeps its own sibling-child lookup
/// directory, and no alternative is discarded by the closure walk.
pub fn assert_cfg_attr_path_loaded_sources_use_sibling_directories() {
    let tmp = fixture::build_repository(CFG_ATTR_PATH_LOADED_SIBLINGS, false);
    let project = fixture::load_default(&tmp);
    let library = app_library(&project);
    let snapshot = project
        .snapshot_target(library)
        .expect("every conditional path alternative closes");
    assert_eq!(
        source_paths(&snapshot),
        EXPECTED_CFG_ATTR_PATH_LOADED_SOURCES,
        "every cfg_attr path source resolves children beside its loaded file"
    );
    for decoy in [
        "src/unix/platform/sibling.rs",
        "src/windows/platform/sibling.rs",
    ] {
        assert!(
            snapshot.source(decoy).is_none(),
            "stem-derived decoy {decoy} is outside the closure"
        );
    }
    assert_eq!(
        root_modules(&project, library),
        EXPECTED_CFG_ATTR_PATH_LOADED_MODULES,
        "both cfg_attr path alternatives and both sibling children remain distinct module instances"
    );
}

/// A source may occupy two module positions, but a chain that includes itself
/// must end on module-instance ancestry rather than run away.
pub fn assert_module_repetition_is_bounded() {
    let tmp = fixture::build_repository(MODULE_REPETITION, false);
    let project = fixture::load_default(&tmp);
    let library = app_library(&project);
    let snapshot = project
        .snapshot_target(library)
        .expect("a self-including module chain ends");
    assert_eq!(
        source_paths(&snapshot),
        EXPECTED_REPETITION_SOURCES,
        "a repeated source is stored once however many positions hold it"
    );
    assert_eq!(
        root_modules(&project, library),
        EXPECTED_REPETITION_MODULES,
        "ancestry ends the self-including chain and still instantiates the \
         shared source, and its child, under both positions"
    );
}

/// Every declared closure failure family reports its own typed kind.
pub fn assert_closure_failure_families() {
    for case in CLOSURE_CASES {
        let tmp = fixture::build_repository(case.files, false);
        let project = fixture::load_default(&tmp);
        let error = project
            .snapshot_target(app_library(&project))
            .expect_err(case.label);
        assert_eq!(
            closure_kinds(&error),
            [case.expected],
            "{}: unexpected failures",
            case.label
        );
    }
}

/// A refused closure names the sources it did reach without accepting them.
pub fn assert_invalid_utf8_is_partial_evidence() {
    let tmp = fixture::build_repository(MISSING_MODULE, false);
    fixture::write_file(tmp.path(), "repo/src/lib.rs", b"pub mod raw;\n");
    fixture::write_file(tmp.path(), "repo/src/raw.rs", &[0xf0, 0x28, 0x8c, 0x28]);
    let project = fixture::load_default(&tmp);
    let error = project
        .snapshot_target(app_library(&project))
        .expect_err("a module source that is not UTF-8");
    assert_eq!(
        closure_kinds(&error),
        [SourceClosureFailureKind::InvalidUtf8],
        "non-UTF-8 source bytes have their own failure kind"
    );
    assert_eq!(
        reached_paths(&error),
        ["src/lib.rs"],
        "partial evidence names only the sources that succeeded"
    );
}

/// What the production readers read while one case runs.
///
/// The observation comes from the loaders themselves, so it can only be taken
/// where `resolution-test-support` compiles the probe. That is the
/// configuration Step 3 runs; every other configuration still proves the
/// refusal.
#[cfg(feature = "resolution-test-support")]
struct ReadWatch(pedant_core::resolution::rust::ResolutionProbe);

#[cfg(not(feature = "resolution-test-support"))]
struct ReadWatch;

#[cfg(feature = "resolution-test-support")]
impl ReadWatch {
    fn install() -> Self {
        Self(pedant_core::resolution::rust::ResolutionProbe::install())
    }

    /// Assert the entry point is the only source the readers opened.
    fn assert_read_only_the_entry(&self, label: &str) {
        let reads = self.0.source_reads();
        assert_eq!(
            observed_paths(&reads),
            ENTRY_ONLY_READS,
            "{label}: the sentinel outside the root must never be read"
        );
    }
}

#[cfg(not(feature = "resolution-test-support"))]
impl ReadWatch {
    fn install() -> Self {
        Self
    }

    /// Without the probe the case proves its refusal alone, so only the label
    /// this configuration can check is checked.
    fn assert_read_only_the_entry(&self, label: &str) {
        assert!(!label.is_empty(), "every confinement case names itself");
    }
}

/// One escape out of the repository root: the closure refuses it, and the
/// production readers never opened what it pointed at.
fn assert_escape_is_refused_without_reading(label: &str, tmp: &tempfile::TempDir) {
    let watch = ReadWatch::install();
    let project = fixture::load_default(tmp);
    let error = project
        .snapshot_target(app_library(&project))
        .expect_err(label);
    assert_eq!(
        closure_kinds(&error),
        [SourceClosureFailureKind::OutOfRoot],
        "{label}: a source outside the root is refused, not read"
    );
    watch.assert_read_only_the_entry(label);
}

/// No escape form reaches a file outside the canonical repository root.
pub fn assert_root_confinement_never_reads_outside() {
    assert_escape_is_refused_without_reading(
        "a #[path] that leaves the repository root",
        &fixture::build_repository(PATH_ESCAPE, false),
    );
    assert_symlink_escape_is_refused();
}

#[cfg(unix)]
fn assert_symlink_escape_is_refused() {
    let tmp = fixture::build_repository(MISSING_MODULE, false);
    fixture::write_file(tmp.path(), "repo/src/lib.rs", b"pub mod link;\n");
    fixture::write_file(tmp.path(), "outside/secret.rs", b"pub fn secret() {}\n");
    std::os::unix::fs::symlink(
        tmp.path().join("outside/secret.rs"),
        tmp.path().join("repo/src/link.rs"),
    )
    .unwrap();
    assert_escape_is_refused_without_reading("a symlink out of the repository root", &tmp);
}

/// Windows fixtures cannot create the symlink this claim needs; the `#[path]`
/// escape carries root confinement there.
#[cfg(not(unix))]
fn assert_symlink_escape_is_refused() {}
