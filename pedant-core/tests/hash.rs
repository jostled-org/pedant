use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_core::hash::compute_source_hash;

#[test]
fn source_hash_is_deterministic() {
    let mut sources = BTreeMap::new();
    sources.insert(Arc::from("a.rs"), Arc::from("fn main() {}"));
    sources.insert(Arc::from("b.rs"), Arc::from("fn helper() {}"));

    let first_hash = compute_source_hash(&sources);
    let second_hash = compute_source_hash(&sources);

    assert_eq!(first_hash, second_hash);
}

#[test]
fn source_hash_uses_sorted_order() {
    let mut sources_a = BTreeMap::new();
    sources_a.insert(Arc::from("b.rs"), Arc::from("second"));
    sources_a.insert(Arc::from("a.rs"), Arc::from("first"));

    let mut sources_b = BTreeMap::new();
    sources_b.insert(Arc::from("a.rs"), Arc::from("first"));
    sources_b.insert(Arc::from("b.rs"), Arc::from("second"));

    assert_eq!(
        compute_source_hash(&sources_a),
        compute_source_hash(&sources_b)
    );
}

#[test]
fn source_hash_distinguishes_file_boundaries() {
    let mut split_sources = BTreeMap::new();
    split_sources.insert(Arc::from("a.rs"), Arc::from("ab"));
    split_sources.insert(Arc::from("b.rs"), Arc::from("c"));

    let mut merged_sources = BTreeMap::new();
    merged_sources.insert(Arc::from("a.rs"), Arc::from("a"));
    merged_sources.insert(Arc::from("b.rs"), Arc::from("bc"));

    assert_ne!(
        compute_source_hash(&split_sources),
        compute_source_hash(&merged_sources)
    );
}

#[test]
fn source_hash_distinguishes_file_names() {
    let mut first_sources = BTreeMap::new();
    first_sources.insert(Arc::from("alpha.rs"), Arc::from("hello"));

    let mut second_sources = BTreeMap::new();
    second_sources.insert(Arc::from("beta.rs"), Arc::from("hello"));

    assert_ne!(
        compute_source_hash(&first_sources),
        compute_source_hash(&second_sources)
    );
}

#[test]
fn source_hash_known_value() {
    let mut sources = BTreeMap::new();
    sources.insert(Arc::from("test.rs"), Arc::from("hello"));

    let hash = compute_source_hash(&sources);

    assert_eq!(
        hash.as_ref(),
        "1fd425805ca3337961be47d3ff75858708d9c19d92701bde9033e69a046fc0fc"
    );
}

#[test]
fn source_hash_empty() {
    let sources: BTreeMap<Arc<str>, Arc<str>> = BTreeMap::new();
    let hash = compute_source_hash(&sources);

    assert_eq!(
        hash.as_ref(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}
