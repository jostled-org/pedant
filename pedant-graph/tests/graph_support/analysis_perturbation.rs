//! The two ways a corpus is perturbed without changing the library it states.
//!
//! Creating the same files in the opposite order changes nothing a graph can
//! observe. Stating the same declarations in the opposite order changes the
//! identities the builder mints and nothing else. Both determinism cases enter
//! through here, so one module decides what "the same library, written
//! differently" means.

use std::collections::BTreeSet;

use pedant_graph::CodeGraph;

use super::corpus::FixtureFile;
use super::corpus_generated::GeneratedFile;

/// One corpus with its files created in the opposite order.
pub fn created_in_reverse(corpus: &[FixtureFile]) -> Vec<(&str, &str)> {
    corpus.iter().rev().copied().collect()
}

/// The reordered corpus states the same nodes, names each of them once, and
/// mints them in another order.
///
/// Without all three this case would compare a graph with itself: the
/// perturbation has to reach the identities every answer is derived from, and a
/// name has to name one node before it can key one answer.
pub fn assert_perturbation_reaches_minted_identities(written: &CodeGraph, reordered: &CodeGraph) {
    let minted = minted_names(written);
    let moved = minted_names(reordered);
    let named_once: BTreeSet<&String> = minted.iter().collect();
    assert_eq!(
        named_once.len(),
        minted.len(),
        "every node of this corpus is named once, so a name keys one answer"
    );
    assert_eq!(
        sorted(&minted),
        sorted(&moved),
        "reordering declarations states the same nodes"
    );
    assert_ne!(
        minted, moved,
        "reordered declarations must be minted in another order, or this case \
         compares a graph with itself"
    );
}

/// Every node's name, in the order the graph minted them.
fn minted_names(graph: &CodeGraph) -> Vec<String> {
    graph
        .nodes()
        .iter()
        .map(|node| node.name().to_owned())
        .collect()
}

/// One corpus with the declarations of each of its Rust sources reversed.
///
/// Item order carries no meaning in Rust, so a source whose blank-line
/// separated blocks are reversed states exactly the same library. A manifest is
/// not item-ordered and is carried over as written.
pub fn declared_in_reverse(corpus: &[FixtureFile]) -> Vec<GeneratedFile> {
    corpus
        .iter()
        .map(|(path, text)| (*path, restated(path, text)))
        .collect()
}

/// One Rust source's blocks in the opposite order; any other file as written.
fn restated(path: &str, text: &str) -> String {
    let blocks: Vec<&str> = text.split("\n\n").collect();
    match path.ends_with(".rs") {
        true => blocks
            .iter()
            .rev()
            .copied()
            .collect::<Vec<&str>>()
            .join("\n\n"),
        false => text.to_owned(),
    }
}

/// Every named string, in sorted order.
pub fn sorted(texts: &[String]) -> Vec<String> {
    let mut ordered = texts.to_vec();
    ordered.sort();
    ordered
}
