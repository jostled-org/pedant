//! Which authorities and project keys reach the index identity.
//!
//! Every authority a selected project claimed is recorded, not only the one
//! discovery started from: a workspace member's manifest and a Go replacement's
//! manifest each decide which sources the project reaches without changing a
//! byte of any source already admitted.
//!
//! One row cannot isolate one project-key component here, and saying so is more
//! useful than pretending otherwise: a repository cannot change a key's unit
//! without changing the target that states it, or its language without changing
//! the authority that selects it. The isolation is
//! [`claims`](super::claims)'s, which writes `ProjectLanguage`,
//! `ProjectAuthority`, and `ProjectUnit` one at a time under equal payloads.
//! These rows prove the other half: production writes those inputs from the
//! keys it actually selected.

use pedant_snippet::{CodeIntelligenceState, ProjectAuthority};

use super::fixture::Repository;
use super::harness::{indexed, project_keys};
use super::sources::MIXED_REPOSITORY;

/// A Go main module and the local replacement it admits.
///
/// The replacement's own `go.mod` is reached recursively — nobody named it —
/// and it is exactly the case a claim over "the authority discovery found"
/// would miss.
const REPLACED_MODULE: &[(&str, &str)] = &[
    (
        "go.mod",
        "module example.com/root\n\ngo 1.22\n\nrequire example.com/lib v1.0.0\n\nreplace example.com/lib => ./local/lib\n",
    ),
    ("root.go", "package main\n\nfunc Start() {}\n"),
    ("local/lib/go.mod", "module example.com/lib\n\ngo 1.22\n"),
    ("local/lib/lib.go", "package lib\n\nfunc Helper() {}\n"),
];

/// Every selected and claimed manifest's bytes, and every project key, reach
/// the index identity.
///
/// The unperturbed mixed repository is built once and its index lent to all
/// three rows. Each row still writes its own perturbed checkout, because a
/// perturbation is what it is about; the baseline it compares against is not.
pub fn authorities_and_project_keys_participate() {
    let repository = Repository::of(MIXED_REPOSITORY);
    let base = indexed(&repository);

    selected_manifest_bytes_participate(&base);
    claimed_member_and_replacement_manifests_participate(&base);
    project_keys_participate(&base);
    parent_authorities_sort_before_members();
}

/// Selection loads a container before authorities nested beneath it.
fn parent_authorities_sort_before_members() {
    let mut authorities = [
        ProjectAuthority::GoModule {
            path: Box::from("cmd/go.mod"),
        },
        ProjectAuthority::RustManifest {
            path: Box::from("crates/member/Cargo.toml"),
        },
        ProjectAuthority::GoModule {
            path: Box::from("go.mod"),
        },
        ProjectAuthority::RustManifest {
            path: Box::from("Cargo.toml"),
        },
    ];
    authorities.sort();
    let paths: Vec<&str> = authorities.iter().map(ProjectAuthority::path).collect();
    assert_eq!(
        paths,
        ["Cargo.toml", "go.mod", "cmd/go.mod", "crates/member/Cargo.toml"]
    );
}

/// The exact bytes of a manifest discovery selected are part of the identity.
///
/// The other half — that an unperturbed second checkout states the same index —
/// belongs to [`corpus`](super::corpus), which owns "identity does not depend on
/// where the repository sits". A copy of it here cost an eighteen-file tree
/// write and a six-language build with graph resolution for an answer that
/// module already states.
fn selected_manifest_bytes_participate(base: &CodeIntelligenceState) {
    let commented = Repository::perturbed(
        MIXED_REPOSITORY,
        "Cargo.toml",
        "# a comment no source can see\n[workspace]\nmembers = [\"crate-a\"]\nresolver = \"3\"\n",
    );
    assert_ne!(
        indexed(&commented).index().revision(),
        base.index().revision(),
        "a selected manifest's exact bytes are part of what the index holds"
    );
}

/// A manifest a selected project claimed on its own is recorded too.
fn claimed_member_and_replacement_manifests_participate(base: &CodeIntelligenceState) {
    let identity = base.index().revision();
    let member = Repository::perturbed(
        MIXED_REPOSITORY,
        "crate-a/Cargo.toml",
        "# a comment no source can see\n[package]\nname = \"crate-a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    assert_ne!(
        indexed(&member).index().revision(),
        identity,
        "a workspace member's manifest is claimed recursively, and its bytes are part of the index"
    );

    let replaced = Repository::of(REPLACED_MODULE);
    let replacement = indexed(&replaced);
    assert_eq!(
        &*project_keys(&replacement),
        ["Go|go.mod|example.com/root"],
        "a replaced module is claimed by the project that admitted it, not selected again"
    );

    let commented = Repository::perturbed(
        REPLACED_MODULE,
        "local/lib/go.mod",
        "// a comment no source can see\nmodule example.com/lib\n\ngo 1.22\n",
    );
    assert_ne!(
        indexed(&commented).index().revision(),
        replacement.index().revision(),
        "the replacement manifest the project admitted is part of what the index holds"
    );

    let renamed = Repository::perturbed(
        REPLACED_MODULE,
        "go.mod",
        "module example.com/other\n\ngo 1.22\n\nrequire example.com/lib v1.0.0\n\nreplace example.com/lib => ./local/lib\n",
    );
    let moved = indexed(&renamed);
    assert_eq!(
        &*project_keys(&moved),
        ["Go|go.mod|example.com/other"],
        "the module root the manifest declares is the unit the key names"
    );
    assert_ne!(
        moved.index().revision(),
        replacement.index().revision(),
        "so a repository that renamed its module states a different index"
    );
}

/// A new project key is a new index, and a slice of its own.
fn project_keys_participate(base: &CodeIntelligenceState) {
    let identity = base.index().revision();
    let slices = base.index().projects().len();

    let extra_target = Repository::perturbed(
        MIXED_REPOSITORY,
        "crate-a/src/bin/second.rs",
        "fn main() {}\n",
    );
    let widened = indexed(&extra_target);
    assert_ne!(
        widened.index().revision(),
        identity,
        "a new project key is a new index"
    );
    assert_eq!(
        widened.index().projects().len(),
        slices + 1,
        "and the new target is a slice of its own"
    );
    assert!(
        project_keys(&widened).contains(&"Rust|Cargo.toml|crate-a::bin::second".to_owned()),
        "keyed by the unit the target states: {:?}",
        project_keys(&widened)
    );

    let renamed_target = Repository::perturbed(
        MIXED_REPOSITORY,
        "crate-a/src/bin/third.rs",
        "fn main() {}\n",
    );
    assert_ne!(
        indexed(&renamed_target).index().revision(),
        widened.index().revision(),
        "two repositories differing only in which unit they state are different indexes"
    );
}
