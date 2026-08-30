//! The identity a feature profile states, and the receipt the configuration
//! harness compares across profiles.
//!
//! This is the one index predicate that runs in every profile, so it indexes an
//! empty repository: equal admitted bytes, equal authorities, equal limits, and
//! equal project keys in all of them. What is left to differ is the enabled
//! language vector and the graph-coverage vector, which is exactly the claim
//! under test.
//!
//! The cross-profile comparison itself belongs to the shell harness that runs
//! this predicate twelve times. A test process links one profile and cannot see
//! another, so the receipt line below is how it hands its answer over.

use pedant_snippet::{CodeIntelligenceIndex, CodeIntelligenceLimits};
use pedant_types::Language;

use super::root::TempRoot;

/// This profile's language vectors are exact, and its empty index states one
/// identity under them.
#[test]
fn code_intelligence_revision_language_profiles_change_identity() {
    let repository = TempRoot::new();
    let state = CodeIntelligenceIndex::build(
        repository.canonical(),
        &[],
        CodeIntelligenceLimits::default(),
    )
    .expect("an empty repository indexes in every profile");
    let index = state.index();

    assert!(
        index.files().is_empty(),
        "an empty repository admits no source, so the corpus cannot differ between profiles"
    );
    assert!(index.projects().is_empty(), "and states no project key");
    assert!(
        state.issues().is_empty(),
        "an empty repository refuses nothing"
    );

    assert_eq!(
        index.enabled_languages(),
        &*expected_languages(),
        "the enabled-language vector is the one this profile's features select"
    );
    assert_eq!(
        index.graph_coverage(),
        &*expected_coverage(),
        "the graph-coverage vector is the one this profile's features select"
    );
    assert!(
        index
            .graph_coverage()
            .iter()
            .all(|language| index.enabled_languages().contains(language)),
        "a build cannot resolve a language it cannot read"
    );

    // The receipt the configuration harness reads. One line, three fields, and
    // the revision last so a shell reading it needs no quoting rules.
    //
    // A test process links one profile and cannot compare itself with another,
    // so the comparison is the harness's. libtest captures stdout for a passing
    // test, which is why the receipt also goes to the path the harness names:
    // a printed line the caller never sees is not a receipt.
    let receipt = format!(
        "languages={} coverage={} revision={}",
        vector(index.enabled_languages()),
        vector(index.graph_coverage()),
        index.revision()
    );
    println!("[code-intelligence-identity] {receipt}");
    if let Ok(path) = std::env::var("PEDANT_CODE_INTELLIGENCE_RECEIPT") {
        std::fs::write(&path, format!("{receipt}\n"))
            .unwrap_or_else(|error| panic!("the receipt is written to {path}: {error}"));
    }
}

/// Every language this profile's features select an inventory for.
///
/// One row per language, each pairing the feature that selects it with the
/// language it selects, kept in the order the published vector claims. A gate
/// and its language written as separate statements are two places a profile can
/// be wrong; a boxed slice rather than a `Vec` because the caller compares it
/// and drops it.
fn expected_languages() -> Box<[Language]> {
    selected(&[
        (cfg!(feature = "lang-rust"), Language::Rust),
        (cfg!(feature = "lang-python"), Language::Python),
        (cfg!(feature = "lang-javascript"), Language::JavaScript),
        (cfg!(feature = "lang-typescript"), Language::TypeScript),
        (cfg!(feature = "lang-go"), Language::Go),
        (cfg!(feature = "lang-bash"), Language::Bash),
    ])
}

/// Every language this profile's features select a graph producer for.
fn expected_coverage() -> Box<[Language]> {
    selected(&[
        (cfg!(feature = "graph-rust"), Language::Rust),
        (cfg!(feature = "graph-go"), Language::Go),
    ])
}

/// The languages whose gate this profile enables, in the order stated.
fn selected(rows: &[(bool, Language)]) -> Box<[Language]> {
    rows.iter()
        .filter_map(|(enabled, language)| enabled.then_some(*language))
        .collect()
}

/// One language vector, as a receipt spells it.
fn vector(languages: &[Language]) -> String {
    match languages.is_empty() {
        true => "none".to_owned(),
        false => languages
            .iter()
            .map(|language| format!("{language:?}"))
            .collect::<Vec<_>>()
            .join(","),
    }
}
