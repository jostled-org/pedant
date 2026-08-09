//! The workspace whose dependency the real Cargo vendors.
//!
//! A journey that must exercise the real `cargo vendor` path uses this instead
//! of a fake script, so the vendored tree is whatever Cargo actually produces.

use tempfile::TempDir;

use crate::baseline_store::{BaselineStore, VendoredWorkspace};
use crate::fake_cargo::{generate_lockfile, run_pedant_in};
use crate::fixtures::write;
use crate::process_guard::Completed;

/// A workspace whose one real dependency is vendored by the real Cargo.
pub(crate) struct RealVendorFixture {
    root: TempDir,
    baselines: BaselineStore,
}

impl RealVendorFixture {
    /// A crate that depends on `serde`, with a committed lockfile.
    pub(crate) fn new() -> Self {
        let root = tempfile::tempdir().expect("a temporary root");
        write(
            &root.path().join("Cargo.toml"),
            "[package]\nname = \"supply-chain-test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nserde = \"1\"\n",
        );
        write(
            &root.path().join("src/lib.rs"),
            "pub fn demo() { let _ = serde::de::IgnoredAny; }\n",
        );
        generate_lockfile(root.path());
        let baselines = BaselineStore::new(root.path());
        Self { root, baselines }
    }
}

impl VendoredWorkspace for RealVendorFixture {
    fn baselines(&self) -> &BaselineStore {
        &self.baselines
    }

    /// Every child runs with the real Cargo on `PATH`, so `cargo vendor` does
    /// whatever it does to a real dependency.
    fn run(&self, args: &[&str]) -> Completed {
        run_pedant_in(self.root.path(), args)
    }
}
