//! What the index admits, and which projects it selects.

use pedant_snippet::{CodeIntelligenceState, ProjectAuthority};
use pedant_types::Language;

use super::fixture::Repository;
use super::harness::{
    assert_sorted, go_module, indexed, paths, project_key_rows, project_keys, required,
    rust_manifest,
};
use super::sources::{MIXED_REPOSITORY, MIXED_SOURCES};

/// The corpus is the exact union of every project closure and the loose walk,
/// with one physical record per source, and it does not depend on where the
/// repository sits.
#[test]
fn code_intelligence_build_discovers_projects_and_loose_sources_deterministically() {
    let repository = Repository::of(MIXED_REPOSITORY);
    let state = indexed(&repository);

    assert_eq!(
        &*paths(&state),
        MIXED_SOURCES,
        "the corpus is every project source and every recognized loose source, and nothing else"
    );
    assert_sorted(
        &paths(&state),
        "one physical file states one record, and the admitted source paths",
    );

    let languages: Box<[Language]> = state
        .index()
        .files()
        .iter()
        .map(|file| file.language())
        .collect();
    assert_eq!(
        &*languages,
        [
            Language::Rust,
            Language::Rust,
            Language::Go,
            Language::Go,
            Language::Python,
            Language::Bash,
            Language::JavaScript,
            Language::TypeScript,
        ],
        "each admitted source carries the language its own owner recognized"
    );

    // The exact list, which is where the claim that a `tsconfig.json` or a
    // `jsconfig.json` selects no project lives too: neither is in it.
    assert_eq!(
        &*project_keys(&state),
        [
            "Rust|Cargo.toml|crate-a::bin::crate-a",
            "Rust|Cargo.toml|crate-a::lib::crate_a",
            "Go|go.mod|example.com/main",
            "Go|nested/go.mod|example.com/nested",
        ],
        "one selected workspace emits its target slices, and an independent nested module is its own"
    );

    // A second checkout at a different absolute path. The identity claim
    // excludes the root's spelling, so this is the same index.
    let elsewhere = Repository::of(MIXED_REPOSITORY);
    let again = indexed(&elsewhere);
    assert_eq!(
        again.index().revision(),
        state.index().revision(),
        "the same repository states the same identity wherever it is checked out"
    );
    assert_eq!(paths(&again), paths(&state), "and the same corpus");

    permutations_state_one_corpus(&state);
}

/// The same repository, laid down and asked for in other orders, is one index.
///
/// Three permutations, because three different orders reach the build: the
/// order the tree was created in, which is the only handle a test has on the
/// order a filesystem enumerates; the order a caller names explicit
/// authorities in; and the directory layout a tree that has held and lost a
/// file ends up with. An identity that depended on any of them would give one
/// repository two names on two machines.
fn permutations_state_one_corpus(state: &CodeIntelligenceState) {
    let backwards = Repository::of_reversed(MIXED_REPOSITORY);
    let reversed = indexed(&backwards);
    assert_eq!(
        paths(&reversed),
        paths(state),
        "the corpus does not depend on the order the tree was written in"
    );
    assert_eq!(
        project_keys(&reversed),
        project_keys(state),
        "and neither do the project keys"
    );
    assert_eq!(
        reversed.index().revision(),
        state.index().revision(),
        "so the identity is the same"
    );

    let churned = Repository::perturbed(
        MIXED_REPOSITORY,
        "scripts/removed.py",
        "def removed():\n    return 1\n",
    );
    std::fs::remove_file(churned.root().join("scripts/removed.py"))
        .expect("the churned entry is removed");
    assert_eq!(
        indexed(&churned).index().revision(),
        state.index().revision(),
        "a directory that has held and lost a file states the same index"
    );

    let named = |first: ProjectAuthority, second: ProjectAuthority| {
        required(&churned, &[first, second])
            .expect("both authorities are the ones discovery already found")
            .index()
            .revision()
    };
    assert_eq!(
        named(rust_manifest("Cargo.toml"), go_module("go.mod")),
        named(go_module("go.mod"), rust_manifest("Cargo.toml")),
        "and the order a caller names its authorities in is not part of the index"
    );
}

/// Explicit and automatic authorities select each project exactly once, and a
/// project key names the one graph it selects.
#[test]
fn code_intelligence_authority_selection_overlap_and_slice_keys_are_exact() {
    let repository = Repository::of(MIXED_REPOSITORY);
    let automatic = indexed(&repository);

    // The baseline is pinned before anything below is compared against it.
    // Every row in this predicate states that some explicit spelling selects
    // the same keys the automatic selection did, and all of them are true of a
    // selection that found no project at all.
    //
    // Sorted by the shared enum's own `Ord` rather than by a token table
    // written here: a restated order is one a language added to the enum, or
    // renamed in it, silently stops describing. The guard refuses an empty
    // list, which is what makes it the pin as well as the order claim.
    assert_sorted(
        &project_key_rows(&automatic),
        "project keys ordered by language, authority path, then unit",
    );

    an_explicit_authority_equal_to_an_automatic_one_selects_once(&repository, &automatic);
    a_repeated_explicit_authority_selects_once(&repository, &automatic);
    a_claimed_member_selects_once_whatever_its_place_in_the_list(&repository, &automatic);
}

/// Naming what discovery would have found anyway suppresses the automatic
/// selection rather than doubling it.
fn an_explicit_authority_equal_to_an_automatic_one_selects_once(
    repository: &Repository,
    automatic: &CodeIntelligenceState,
) {
    let explicit = required(
        repository,
        &[rust_manifest("Cargo.toml"), go_module("go.mod")],
    )
    .expect("the explicit authorities are the ones discovery already found");
    assert_eq!(
        project_keys(&explicit),
        project_keys(automatic),
        "an explicit authority equal to an automatic one suppresses it rather than doubling it"
    );
    assert_eq!(
        explicit.index().revision(),
        automatic.index().revision(),
        "and states the same index"
    );
}

/// One authority named twice is one authority.
fn a_repeated_explicit_authority_selects_once(
    repository: &Repository,
    automatic: &CodeIntelligenceState,
) {
    let duplicated = required(
        repository,
        &[rust_manifest("Cargo.toml"), rust_manifest("Cargo.toml")],
    )
    .expect("a repeated explicit authority is one authority");
    assert_eq!(
        project_keys(&duplicated),
        project_keys(automatic),
        "the same authority named twice selects one project"
    );
}

/// A workspace member the automatic ancestor already claimed appears once,
/// under the workspace's keys, wherever the caller names it.
fn a_claimed_member_selects_once_whatever_its_place_in_the_list(
    repository: &Repository,
    automatic: &CodeIntelligenceState,
) {
    let member = required(repository, &[rust_manifest("crate-a/Cargo.toml")])
        .expect("a workspace member's own manifest is a usable authority");
    assert_eq!(
        project_keys(&member),
        project_keys(automatic),
        "an explicitly required member claimed by the automatic workspace appears once under the workspace's stable keys"
    );
    assert_eq!(
        member.index().revision(),
        automatic.index().revision(),
        "required provenance does not change the index identity when it selects no additional project"
    );

    let named_with_go = |authorities: &[ProjectAuthority]| {
        required(repository, authorities)
            .expect("the nested member and Go module are usable explicit authorities")
    };
    let nested_first = named_with_go(&[rust_manifest("crate-a/Cargo.toml"), go_module("go.mod")]);
    let nested_last = named_with_go(&[go_module("go.mod"), rust_manifest("crate-a/Cargo.toml")]);
    assert_eq!(
        project_keys(&nested_first),
        project_keys(&nested_last),
        "explicit ordering does not change keys when an automatic ancestor claims one authority"
    );
    assert_eq!(
        nested_first.index().revision(),
        nested_last.index().revision(),
        "explicit ordering does not change the index revision"
    );
}
