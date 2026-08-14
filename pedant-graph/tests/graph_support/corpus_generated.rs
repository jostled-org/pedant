//! The temporary Cargo repositories a case states as a rule rather than as text.
//!
//! A written corpus states its source once, as a constant. A corpus whose source
//! is a function of a count — every three-node topology, one branch
//! multiplicity, one chain length — states the rule instead, so the repository
//! and the expectation cannot drift apart by a hand edit.

/// One generated fixture file: repository-relative path and owned contents.
pub type GeneratedFile = (&'static str, String);

/// The manifest every generated single-package repository states.
const GENERATED_MANIFEST: &str = r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"
"#;

/// How many participating functions each generated topology module states.
pub const TOPOLOGY_WIDTH: usize = 3;

/// How many simple directed topologies [`TOPOLOGY_WIDTH`] functions admit.
///
/// Each ordered pair, including a pair of one function with itself, is either
/// stated or not, so the corpus holds one module per subset of the nine pairs.
pub const TOPOLOGY_MODULES: usize = 1 << (TOPOLOGY_WIDTH * TOPOLOGY_WIDTH);

/// The suffix each participating function of one topology module carries.
const TOPOLOGY_SUFFIXES: [&str; TOPOLOGY_WIDTH] = ["a", "b", "c"];

/// One generated single-package repository whose library root holds `source`.
fn generated_library(source: String) -> Vec<GeneratedFile> {
    vec![
        ("repo/Cargo.toml", GENERATED_MANIFEST.to_owned()),
        ("repo/src/lib.rs", source),
    ]
}

/// Whether one topology subset states the call from `from` to `to`.
///
/// The subset is read as a bit per ordered pair, so the corpus and every
/// expectation compared against it agree on one rule rather than on a table.
pub fn topology_states(subset: usize, from: usize, to: usize) -> bool {
    subset & (1 << (from * TOPOLOGY_WIDTH + to)) != 0
}

/// The name one participating function of one topology module declares.
///
/// Every name is unique across the corpus, so a call resolves inside the module
/// that states it and each module's call topology is exactly its own subset.
pub fn topology_name(subset: usize, at: usize) -> String {
    format!("m{subset}_{}", TOPOLOGY_SUFFIXES[at])
}

/// One library stating every simple directed topology over three functions,
/// one per inline module.
pub fn topology_corpus() -> Vec<GeneratedFile> {
    generated_library((0..TOPOLOGY_MODULES).map(topology_module).collect())
}

/// One inline module holding the three functions of one topology subset.
fn topology_module(subset: usize) -> String {
    let declared: String = (0..TOPOLOGY_WIDTH)
        .map(|from| topology_function(subset, from))
        .collect();
    format!("pub mod m{subset} {{\n{declared}}}\n\n")
}

/// One function of one topology subset, calling exactly the targets it states.
fn topology_function(subset: usize, from: usize) -> String {
    let calls: String = (0..TOPOLOGY_WIDTH)
        .filter(|to| topology_states(subset, from, *to))
        .map(|to| format!("        {}();\n", topology_name(subset, to)))
        .collect();
    format!(
        "    pub fn {}() {{\n{calls}    }}\n",
        topology_name(subset, from)
    )
}

/// One library whose call graph is a diamond with `multiplicity` parallel calls
/// along every branch.
///
/// `seed` calls `left` and `right`, and both arms call `sink`, each call written
/// `multiplicity` times, so every branch of the diamond carries exactly that
/// many distinct shortest routes.
pub fn diamond_corpus(multiplicity: usize) -> Vec<GeneratedFile> {
    generated_library(format!(
        "pub fn seed() {{\n{}{}}}\n\npub fn left() {{\n{}}}\n\npub fn right() \
         {{\n{}}}\n\npub fn sink() {{}}\n",
        repeated_call("left", multiplicity),
        repeated_call("right", multiplicity),
        repeated_call("sink", multiplicity),
        repeated_call("sink", multiplicity),
    ))
}

/// One call written `multiplicity` times, each on its own line.
fn repeated_call(target: &str, multiplicity: usize) -> String {
    (0..multiplicity)
        .map(|_| format!("    {target}();\n"))
        .collect()
}

/// One library whose call graph is a chain of `length` functions.
///
/// Each function calls the next and the last calls nothing, so the selected
/// call topology is one path as long as the corpus and every traversal or
/// component walk over it is as deep as the graph is.
pub fn linear_corpus(length: usize) -> Vec<GeneratedFile> {
    generated_library((0..length).map(|at| linear_function(at, length)).collect())
}

/// One function of the chain, calling its successor unless it is the last.
fn linear_function(at: usize, length: usize) -> String {
    let call = match at + 1 < length {
        true => format!("    {}();\n", linear_name(at + 1)),
        false => String::new(),
    };
    format!("pub fn {}() {{\n{call}}}\n\n", linear_name(at))
}

/// The name the chain's function at one position declares.
pub fn linear_name(at: usize) -> String {
    format!("step{at}")
}
