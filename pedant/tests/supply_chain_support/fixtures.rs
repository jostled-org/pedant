//! Temporary vendor trees, the consumer workspaces that resolve them, and the
//! baseline evidence a journey reads back.
//!
//! One fixture owns one `TempDir`, so every root it creates is released when
//! the test drops it, whether the test passed or panicked.

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::baseline_store::{BaselineStore, VendoredWorkspace};
use crate::fake_cargo::{copying_vendor_body, generate_lockfile, run_with_fake_cargo};
use crate::process_guard::Completed;

/// Debug-package inputs expected from the path-override fixture. `false`
/// entries are valid sources placed at the incorrect stem-derived lookup base.
pub(crate) const PATH_OVERRIDE_DEBUG_FILES: &[(&str, bool)] = &[
    ("src/lib.rs", true),
    ("src/direct.rs", true),
    ("src/direct_bindings.rs", true),
    ("src/stack/mod.rs", true),
    ("src/stack/unix.rs", true),
    ("src/stack/unix_bindings.rs", true),
    ("src/stack/windows.rs", true),
    ("src/stack/windows_bindings.rs", true),
    ("src/direct/direct_bindings.rs", false),
    ("src/stack/unix/unix_bindings.rs", false),
    ("src/stack/windows/windows_bindings.rs", false),
];

/// A vendored tree, a consumer workspace, and the baseline store between them.
pub(crate) struct VendorFixture {
    root: TempDir,
    vendor_root: PathBuf,
    consumer: PathBuf,
    baselines: BaselineStore,
}

impl VendorFixture {
    /// A fixture whose consumer resolves nothing but its own lockfile, so the
    /// vendored tree is exactly what the test wrote.
    pub(crate) fn new() -> Self {
        let root = tempfile::tempdir().expect("a temporary root");
        let vendor_root = root.path().join("vendor");
        let consumer = root.path().join("consumer");
        fs::create_dir_all(&vendor_root).expect("a vendor root");
        write_minimal_consumer(&consumer);
        let baselines = BaselineStore::new(&consumer);
        Self {
            root,
            vendor_root,
            consumer,
            baselines,
        }
    }

    /// The directory one vendored package occupies.
    pub(crate) fn crate_dir(&self, name: &str) -> PathBuf {
        self.vendor_root.join(name)
    }

    /// The vendored tree the fake Cargo copies into place.
    pub(crate) fn vendor_root(&self) -> &Path {
        &self.vendor_root
    }

    /// One guarded run, with extra environment for the spawned binary.
    pub(crate) fn run_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> Completed {
        run_with_fake_cargo(
            self.root.path(),
            &self.consumer,
            &format!("{}\n  exit 0", copying_vendor_body(&self.vendor_root)),
            args,
            env,
        )
    }

    /// The directory the fake Cargo script is written into.
    pub(crate) fn script_dir(&self) -> &Path {
        self.root.path()
    }

    /// The consumer workspace a guarded child starts in.
    pub(crate) fn consumer(&self) -> &Path {
        &self.consumer
    }
}

impl VendoredWorkspace for VendorFixture {
    fn baselines(&self) -> &BaselineStore {
        &self.baselines
    }

    /// Every child runs against the fake Cargo, which copies the tree this
    /// fixture wrote instead of resolving anything.
    fn run(&self, args: &[&str]) -> Completed {
        self.run_with_env(args, &[])
    }
}

/// Write one file, creating the directories above it.
pub(crate) fn write(path: &Path, contents: impl AsRef<[u8]>) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("a fixture directory");
    }
    fs::write(path, contents).expect("a writable fixture file");
}

/// A vendored package with one manifest and one library entry point.
pub(crate) fn write_library_crate(dir: &Path, manifest: &str, library: &str) {
    write(&dir.join("Cargo.toml"), manifest);
    write(&dir.join("src/lib.rs"), library);
}

/// A library using a bare path override and two conditional path alternatives.
/// Every loaded source declares a child beside itself. Valid files beneath
/// stem-derived directories make an incorrect closure observable in debug
/// output without making initialization fail first.
pub(crate) fn write_path_override_crate(root: &Path) {
    write_library_crate(
        root,
        &manifest("path-children", "0.1.0"),
        "#[path = \"direct.rs\"]\nmod direct;\nmod stack;\n",
    );
    for (path, source) in PATH_OVERRIDE_SOURCES {
        write(&root.join(path), source);
    }
}

const PATH_OVERRIDE_SOURCES: &[(&str, &str)] = &[
    ("src/direct.rs", "mod direct_bindings;\n"),
    ("src/direct_bindings.rs", "pub fn sibling() {}\n"),
    ("src/direct/direct_bindings.rs", "pub fn stem_decoy() {}\n"),
    (
        "src/stack/mod.rs",
        "#[cfg_attr(unix, path = \"unix.rs\")]\n\
         #[cfg_attr(windows, path = \"windows.rs\")]\n\
         mod sys;\n",
    ),
    ("src/stack/unix.rs", "mod unix_bindings;\n"),
    ("src/stack/unix_bindings.rs", "pub fn sibling() {}\n"),
    (
        "src/stack/unix/unix_bindings.rs",
        "pub fn stem_decoy() {}\n",
    ),
    ("src/stack/windows.rs", "mod windows_bindings;\n"),
    ("src/stack/windows_bindings.rs", "pub fn sibling() {}\n"),
    (
        "src/stack/windows/windows_bindings.rs",
        "pub fn stem_decoy() {}\n",
    ),
];

/// The simplest manifest that declares one package.
pub(crate) fn manifest(name: &str, version: &str) -> String {
    format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2024\"\n")
}

/// The same manifest, declaring an MSRV.
pub(crate) fn manifest_with_msrv(name: &str, version: &str, rust_version: &str) -> String {
    format!(
        "{}rust-version = \"{rust_version}\"\n",
        manifest(name, version)
    )
}

/// A consumer workspace with a lockfile and no dependencies.
fn write_minimal_consumer(root: &Path) {
    write(&root.join("Cargo.toml"), manifest("consumer", "0.1.0"));
    write(&root.join("src/lib.rs"), "");
    generate_lockfile(root);
}
