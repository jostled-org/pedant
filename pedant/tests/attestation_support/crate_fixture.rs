//! One temporary crate on disk and the CLI runs a case makes against it.
//!
//! A submodule of `tests/attestation.rs`, reached through a `#[path]` attribute
//! and not a test root of its own: this directory carries no `main.rs`, so cargo
//! declares no test executable for it. The layout below was written out once per
//! case before; stating it here keeps every case a claim rather than a setup
//! script, and the `TempDir` still lives and dies with the case that built it.

use std::fs;
use std::path::PathBuf;
use std::process::Output;

use crate::common;

/// The manifest a fixture crate declares when it names no build script.
pub(crate) const PLAIN_MANIFEST: &str =
    "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n";

/// A library that reads a file, so its analysis reports one non-hook finding.
pub(crate) const FILE_READ_LIB: &str = "use std::fs::read_to_string;\n";

/// A build script that runs a process, so its analysis reports one hook finding.
pub(crate) const PROCESS_BUILD_SCRIPT: &str =
    "use std::process::Command;\nfn main() { Command::new(\"cc\"); }\n";

/// A crate laid out under a temporary root the case owns.
pub(crate) struct CrateFixture {
    root: tempfile::TempDir,
}

impl CrateFixture {
    /// A crate holding `manifest` and an empty `src/`.
    pub(crate) fn new(manifest: &str) -> Self {
        let root = tempfile::tempdir().expect("a temporary crate root");
        fs::create_dir(root.path().join("src")).expect("a source directory");
        fs::write(root.path().join("Cargo.toml"), manifest).expect("a manifest");
        Self { root }
    }

    /// Write one file inside the crate and hand back its path.
    pub(crate) fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.root.path().join(relative);
        fs::write(&path, contents).unwrap_or_else(|error| {
            panic!("{} should be writable: {error}", path.display());
        });
        path
    }

    /// Run one `pedant` subcommand against a path inside the crate.
    pub(crate) fn run(&self, subcommand: &str, relative: &str) -> Output {
        let path = self.root.path().join(relative);
        let argument = path.to_str().expect("a temporary path is valid UTF-8");
        common::run_subcommand(subcommand, &[argument], None)
    }

    /// Run `attestation` against a path inside the crate, naming the package.
    pub(crate) fn attest(&self, relative: &str) -> Output {
        let path = self.root.path().join(relative);
        let argument = path.to_str().expect("a temporary path is valid UTF-8");
        common::run_subcommand(
            "attestation",
            &[argument, "--crate-name", "test", "--crate-version", "0.1.0"],
            None,
        )
    }
}

/// Decode one successful CLI run, reporting the child's stderr on failure.
pub(crate) fn decoded<T: serde::de::DeserializeOwned>(output: &Output) -> T {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the CLI should print the documented JSON")
}
