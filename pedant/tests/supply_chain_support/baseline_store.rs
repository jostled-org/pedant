//! The baseline store a journey reads back, and the commands that write it.
//!
//! Two fixtures reach the same store: one vendors a tree the test wrote, the
//! other vendors through the real Cargo. What a `supply-chain` command line is
//! belongs to neither of them, so it is stated once here and each fixture
//! supplies only the launcher its children need.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use pedant_types::AttestationContent;

use crate::process_guard::Completed;

/// Where one consumer workspace keeps the attestations it writes and prunes.
pub(crate) struct BaselineStore {
    root: PathBuf,
}

impl BaselineStore {
    /// The store one consumer workspace holds, at the path `pedant` defaults to.
    pub(crate) fn new(consumer: &Path) -> Self {
        Self {
            root: consumer.join(".pedant/baselines"),
        }
    }

    /// The directory every baseline lives under.
    pub(crate) fn path(&self) -> &Path {
        &self.root
    }

    /// The `--baseline-path` argument, which every command needs as `&str`.
    pub(crate) fn argument(&self) -> &str {
        self.root.to_str().expect("a temporary path is valid UTF-8")
    }

    /// Where one package's baseline for one version lives.
    pub(crate) fn path_for(&self, name: &str, version: &str) -> PathBuf {
        self.root
            .join("cargo")
            .join(name)
            .join(format!("{version}.json"))
    }

    /// One written baseline, parsed.
    pub(crate) fn read(&self, name: &str, version: &str) -> AttestationContent {
        let path = self.path_for(name, version);
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("no baseline at {}: {error}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("baseline {} should parse: {error}", path.display()))
    }

    /// Every baseline file's exact bytes, so a failed command can be held to
    /// leaving the store untouched.
    pub(crate) fn bytes(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut bytes = BTreeMap::new();
        collect_bytes(&self.root, &mut bytes);
        bytes
    }
}

fn collect_bytes(path: &Path, bytes: &mut BTreeMap<PathBuf, Vec<u8>>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        match child.is_dir() {
            true => collect_bytes(&child, bytes),
            false => {
                let content = fs::read(&child).expect("a readable baseline");
                bytes.insert(child, content);
            }
        }
    }
}

/// A workspace whose dependencies a `supply-chain` command vendors and attests.
///
/// The command lines live here; the launcher is the implementor's, because one
/// fixture puts a fake Cargo on the child's `PATH` and the other runs the real
/// one. A command line written twice could drift on one side and still pass on
/// the other.
pub(crate) trait VendoredWorkspace {
    /// The baseline store this workspace's commands read and write.
    fn baselines(&self) -> &BaselineStore;

    /// Run one guarded `pedant` child in this workspace.
    fn run(&self, args: &[&str]) -> Completed;

    /// Run one `supply-chain` subcommand against the vendored tree.
    fn supply_chain(&self, command: &str) -> Completed {
        self.run(&[
            "supply-chain",
            command,
            "--baseline-path",
            self.baselines().argument(),
        ])
    }

    /// Run `verify --debug-package`, which dumps one package's hashed inputs.
    fn debug_package(&self, package: &str) -> Completed {
        self.run(&[
            "supply-chain",
            "verify",
            "--baseline-path",
            self.baselines().argument(),
            "--debug-package",
            package,
        ])
    }
}
