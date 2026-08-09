//! Snapshot/database pairings the Tier 2 freshness handshake must refuse.
//!
//! Each pairing states its own load order explicitly, because the handshake
//! owes the same refusal whether the database or the snapshot was taken first.

use pedant_core::resolution::rust::CargoTargetKind;
use std::fs;

use crate::resolution::fixture::{self, FixtureFile};
use crate::resolution::semantic_fixtures::{
    CHANGED_ALPHA, MANIFEST_WITH_OPTIONAL_DEPENDENCY, MANIFEST_WITHOUT_DEPENDENCY, SEMANTIC_CORPUS,
};
use crate::resolution::semantic_pairing::{Pairing, library_snapshot, load_context};
use crate::resolution::views::{sole_library, target_id};

/// One refused pairing: how it is built, and the words its refusal owes.
pub struct HandshakeCase {
    /// Which identity this row perturbs.
    pub label: &'static str,
    /// The repository the row starts from.
    pub files: &'static [FixtureFile],
    /// How the snapshot and the database are produced, in this row's order.
    pub pairing: fn(&tempfile::TempDir) -> Pairing,
    /// Text the typed refusal must name.
    pub expected: &'static str,
}

/// Every identity the handshake compares, one row each, with both load orders
/// represented among the digest rows.
pub const HANDSHAKE_CASES: &[HandshakeCase] = &[
    HandshakeCase {
        label: "the database was loaded at another repository root",
        files: SEMANTIC_CORPUS,
        pairing: context_at_dependency_root,
        expected: "repository root",
    },
    HandshakeCase {
        label: "the database holds no crate for the requested target",
        files: crate::resolution::semantic_fixtures::EXCLUDED_BINARY,
        pairing: context_for_excluded_binary,
        expected: "requested target",
    },
    HandshakeCase {
        label: "the dependency left the unit graph after the snapshot",
        files: SEMANTIC_CORPUS,
        pairing: context_after_dependency_removed,
        expected: "unit graph",
    },
    HandshakeCase {
        label: "the dependency is conditional and the database activates it not",
        files: SEMANTIC_CORPUS,
        pairing: context_for_optional_dependency,
        expected: "activate",
    },
    HandshakeCase {
        label: "a conditionally declared module leaves the database's path set",
        files: crate::resolution::semantic_fixtures::CONDITIONAL_MODULE,
        pairing: context_for_conditional_module,
        expected: "source set",
    },
    HandshakeCase {
        label: "a source changed after the database was loaded",
        files: SEMANTIC_CORPUS,
        pairing: context_before_source_change,
        expected: "different bytes",
    },
    HandshakeCase {
        label: "a source changed before the database was loaded",
        files: SEMANTIC_CORPUS,
        pairing: context_after_source_change,
        expected: "different bytes",
    },
];

fn context_at_dependency_root(tmp: &tempfile::TempDir) -> Pairing {
    let root = fixture::repository_root(tmp);
    Pairing {
        snapshot: library_snapshot(tmp),
        context: load_context(&root.join("crates").join("helper")),
    }
}

fn context_for_excluded_binary(tmp: &tempfile::TempDir) -> Pairing {
    let project = fixture::load_default(tmp);
    let binary = target_id(&project, "helper", CargoTargetKind::Binary, "helper");
    Pairing {
        snapshot: project
            .snapshot_resolution(binary)
            .expect("the excluded package's binary snapshots"),
        context: load_context(&fixture::repository_root(tmp)),
    }
}

fn context_after_dependency_removed(tmp: &tempfile::TempDir) -> Pairing {
    let snapshot = library_snapshot(tmp);
    rewrite(tmp, "repo/Cargo.toml", MANIFEST_WITHOUT_DEPENDENCY);
    Pairing {
        context: load_context(&fixture::repository_root(tmp)),
        snapshot,
    }
}

fn context_for_optional_dependency(tmp: &tempfile::TempDir) -> Pairing {
    rewrite(tmp, "repo/Cargo.toml", MANIFEST_WITH_OPTIONAL_DEPENDENCY);
    Pairing {
        snapshot: library_snapshot(tmp),
        context: load_context(&fixture::repository_root(tmp)),
    }
}

fn context_for_conditional_module(tmp: &tempfile::TempDir) -> Pairing {
    let project = fixture::load_default(tmp);
    let snapshot = project
        .snapshot_resolution(sole_library(&project))
        .expect("the conditional module stays in the syntactic closure");
    Pairing {
        context: load_context(&fixture::repository_root(tmp)),
        snapshot,
    }
}

fn context_before_source_change(tmp: &tempfile::TempDir) -> Pairing {
    let context = load_context(&fixture::repository_root(tmp));
    rewrite(tmp, "repo/src/alpha.rs", CHANGED_ALPHA);
    Pairing {
        snapshot: library_snapshot(tmp),
        context,
    }
}

fn context_after_source_change(tmp: &tempfile::TempDir) -> Pairing {
    let snapshot = library_snapshot(tmp);
    rewrite(tmp, "repo/src/alpha.rs", CHANGED_ALPHA);
    Pairing {
        context: load_context(&fixture::repository_root(tmp)),
        snapshot,
    }
}

/// Replace one fixture file's bytes and prove the replacement landed.
fn rewrite(tmp: &tempfile::TempDir, relative: &str, contents: &str) {
    fixture::write_file(tmp.path(), relative, contents.as_bytes());
    let written = fs::read_to_string(tmp.path().join(relative)).expect("the rewrite is readable");
    assert_eq!(written, contents, "{relative} was not rewritten");
}
