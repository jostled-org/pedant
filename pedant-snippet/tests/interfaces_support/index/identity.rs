//! What moves an index identity, what moves only a state identity, and what
//! moves neither.
//!
//! Every assertion uses public inputs and outputs. The claim encoder remains an
//! implementation detail; these cases prove that production feeds it.

#[cfg(feature = "test-support")]
use pedant_snippet::{CodeIntelligenceLimits, LimitField, stated_ceilings};
use pedant_types::Language;

#[cfg(feature = "test-support")]
use super::claims::claim_registry_is_closed_and_tagged;
use super::fixture::Repository;
#[cfg(feature = "test-support")]
use super::framing::claim_framing_survives_every_boundary_and_order;
#[cfg(feature = "test-support")]
use super::harness::built;
use super::harness::indexed;
use super::keys::authorities_and_project_keys_participate;
use super::sources::{EDITED, KEPT};
use super::state_identity::{issues_move_only_the_state, stale_handles_refuse_before_lookup};

/// Every claim input independently moves the identity it belongs to, and a
/// handle from another revision refuses before it reads a position.
#[test]
fn code_intelligence_revisions_dense_handles_and_health_are_exact() {
    admitted_bytes_and_paths_participate();
    every_language_states_its_own_sources_and_digests();
    authorities_and_project_keys_participate();
    issues_move_only_the_state();
    stale_handles_refuse_before_lookup();
}

/// Direct claim framing is available only through the non-default test seam.
#[cfg(feature = "test-support")]
#[test]
fn revision_claim_framing_is_closed_and_exact() {
    claim_registry_is_closed_and_tagged();
    claim_framing_survives_every_boundary_and_order();
    every_ceiling_is_stated_and_claimed();
}

/// Every configured ceiling has one claim row and moves the public revision.
#[cfg(feature = "test-support")]
fn every_ceiling_is_stated_and_claimed() {
    let repository = Repository::of(&[KEPT]);
    let base = indexed(&repository).index().revision();
    let defaults = CodeIntelligenceLimits::default();
    let registry: Box<[(&str, u64)]> = LimitField::ALL
        .iter()
        .map(|field| (field.token(), field.read(&defaults)))
        .collect();

    assert!(!registry.is_empty());
    assert_eq!(&*registry, &*stated_ceilings(&defaults));

    let mut tokens: Vec<&str> = LimitField::ALL.iter().map(|field| field.token()).collect();
    let stated = tokens.len();
    tokens.sort_unstable();
    tokens.dedup();
    assert_eq!(tokens.len(), stated);

    for field in LimitField::ALL {
        let held = field.read(&defaults);
        let perturbed = field.written(&defaults, held.saturating_sub(1).max(1));
        assert_ne!(perturbed, defaults, "{}", field.token());
        let moved = built(&repository, &[], perturbed)
            .unwrap_or_else(|error| panic!("{}: {error}", field.token()))
            .index()
            .revision();
        assert_ne!(moved, base, "{}", field.token());
    }
}

/// A path, a digest, and a record count each move the index identity; where the
/// repository sits does not.
fn admitted_bytes_and_paths_participate() {
    let base = Repository::of(&[KEPT]);
    let identity = indexed(&base).index().revision();

    let renamed = Repository::of(&[("b.py", KEPT.1)]);
    assert_ne!(
        indexed(&renamed).index().revision(),
        identity,
        "the normalized path is part of what the index holds"
    );

    let edited = Repository::of(&[EDITED]);
    assert_ne!(
        indexed(&edited).index().revision(),
        identity,
        "the exact source digest is part of what the index holds"
    );

    let two = Repository::of(&[KEPT, ("b.py", "def b():\n    return 1\n")]);
    assert_ne!(
        indexed(&two).index().revision(),
        identity,
        "how many sources the index holds is part of what it holds"
    );

    let repeated = Repository::of(&[KEPT]);
    assert_eq!(
        indexed(&repeated).index().revision(),
        identity,
        "and nothing about where the repository sits is"
    );
}

/// One source in each of the six languages, recognized as that language, and
/// its digest reaching the identity.
///
/// Every language separately, because a recognizer that stopped seeing one of
/// them would leave that language's sources out of the corpus while every other
/// row here stayed green — and a digest that reached the claim for Python
/// proves nothing about the one this build takes for Bash.
fn every_language_states_its_own_sources_and_digests() {
    let rows: [(&str, &str, &str, Language); 6] = [
        (
            "a.rs",
            "pub fn a() {}\n",
            "pub fn a() -> u32 {\n    1\n}\n",
            Language::Rust,
        ),
        (
            "a.go",
            "package a\n\nfunc A() {}\n",
            "package a\n\nfunc A() int {\n\treturn 1\n}\n",
            Language::Go,
        ),
        (
            "a.js",
            "export function a() {}\n",
            "export function a() {\n  return 1;\n}\n",
            Language::JavaScript,
        ),
        (
            "a.ts",
            "export interface A {}\n",
            "export interface A {\n  size: number;\n}\n",
            Language::TypeScript,
        ),
        (
            "a.py",
            "def a():\n    return 1\n",
            "def a():\n    return 2\n",
            Language::Python,
        ),
        (
            "a.sh",
            "a() {\n  echo one\n}\n",
            "a() {\n  echo two\n}\n",
            Language::Bash,
        ),
    ];

    // Mapped over the table rather than pushed into a growing list, so the
    // arity stays in the type: six rows in, six labelled digests out, and a
    // row that returned nothing cannot shrink the set the guard below compares.
    let identities: [(String, String); 6] = rows.map(|(path, source, edited, language)| {
        let repository = Repository::of(&[(path, source)]);
        let state = indexed(&repository);
        let record = state
            .index()
            .file(path)
            .unwrap_or_else(|error| panic!("{path} is admitted: {error}"));
        assert_eq!(
            record.language(),
            language,
            "{path} carries the language its own owner recognized"
        );

        let changed = Repository::of(&[(path, edited)]);
        assert_ne!(
            indexed(&changed).index().revision(),
            state.index().revision(),
            "{path}: this language's exact digest is part of what the index holds"
        );
        (
            format!("{language:?}"),
            state.index().revision().to_string(),
        )
    });

    assert_distinct_language_revisions(&identities);
}

/// Every language corpus above claims a distinct revision.
fn assert_distinct_language_revisions(identities: &[(String, String)]) {
    assert!(!identities.is_empty());
    for (position, (label, digest)) in identities.iter().enumerate() {
        assert!(
            identities[position + 1..]
                .iter()
                .all(|(_, other)| other != digest),
            "language corpus {label} has a distinct revision"
        );
    }
}
