//! The temporary Cargo repositories the derived-analysis cases project.
//!
//! Each states one topology a query, a metric, a component walk, or a divergence
//! calculation is asserted against, so a case reads its own fixture rather than
//! sharing the general graph corpus with the construction cases.

use super::corpus::FixtureFile;

/// One library whose call graph is a diamond with a cycle, a self-loop,
/// parallel call evidence, an isolated definition, and one external module
/// whose declaration and import are the corpus's only non-call edges.
///
/// Every call is same-file and same-scope, so the selected `Call` topology is
/// exactly the one written here: `seed` calls `left` twice and `right` once,
/// both arms call `sink`, `sink` closes the cycle back to `seed`, `wheel` calls
/// itself, `stranded` is isolated, and `user` calls the imported `helper`.
pub const ANALYSIS_TRAVERSAL_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/src/part.rs",
        r#"pub fn helper() {}
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub mod part;

use part::helper;

pub fn seed() {
    left();
    left();
    right();
}

pub fn left() {
    sink();
}

pub fn right() {
    sink();
}

pub fn sink() {
    seed();
}

pub fn wheel() {
    wheel();
}

pub fn stranded() {}

pub fn user() {
    helper();
}
"#,
    ),
];

/// One library whose logical module tree disagrees with its physical sources.
///
/// `deep` sits in `src/lib.rs` beneath two nested inline modules; `away`,
/// `nested`, and `far` sit in `src/detached.rs` beneath a module declared in
/// `src/lib.rs`. No node's nearest container is the file its bytes sit in.
pub const ANALYSIS_PARTITION_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub mod outer {
    pub fn shallow() {}

    pub mod inner {
        pub fn deep() {}
    }
}

pub mod detached;

pub fn top() {}
"#,
    ),
    (
        "repo/src/detached.rs",
        r#"pub fn away() {}

pub mod nested {
    pub fn far() {}
}
"#,
    ),
];

/// One library whose call graph states every component shape at once.
///
/// `entry` calls `ring_a` twice, `ring_a` and `ring_b` call each other, `ring_b`
/// calls `tail` twice, `wheel` calls itself, and `alone` is isolated. The two
/// parallel pairs cross component boundaries, so a condensation must coalesce
/// them without losing either raw identity.
pub const ANALYSIS_COMPONENT_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub fn entry() {
    ring_a();
    ring_a();
}

pub fn ring_a() {
    ring_b();
}

pub fn ring_b() {
    ring_a();
    tail();
    tail();
}

pub fn tail() {}

pub fn wheel() {
    wheel();
}

pub fn alone() {}
"#,
    ),
];

/// One library whose calls cross its declared module boundaries in both
/// directions, beside a package dependency no source names.
///
/// Every blank line separates one whole declaration, so the determinism case can
/// state the same library with its declarations in the opposite order.
///
/// `root_call` calls into `alpha`, into `beta`, and into its own unit root;
/// `alpha_leaf` calls back into the unit root, which closes one cycle across two
/// partitions. `beta` calls only itself, and the dependency edge to `helper`
/// crosses two unit roots without any source relation stating it — so a
/// dependency-bearing selection changes the arithmetic openly.
pub const ANALYSIS_DIVERGENCE_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
helper = { path = "crates/helper" }
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub mod alpha;

pub mod beta {
    pub fn beta_call() {
        beta_leaf();
    }
    pub fn beta_leaf() {}
}

pub fn root_call() {
    alpha::alpha_call();
    beta::beta_call();
    root_leaf();
}

pub fn root_leaf() {}
"#,
    ),
    (
        "repo/src/alpha.rs",
        r#"pub fn alpha_call() {
    alpha_leaf();
}

pub fn alpha_leaf() {
    crate::root_call();
}
"#,
    ),
    (
        "repo/crates/helper/Cargo.toml",
        r#"[package]
name = "helper"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/crates/helper/src/lib.rs",
        r#"pub fn assist() {}
"#,
    ),
];

/// The smallest repository a real Rust workspace can state: one unit root and
/// the one empty source it instantiates.
///
/// Two nodes is below the directed normalization divisor's own floor, which is
/// the case the centrality contract answers with zero rather than a division.
pub const ANALYSIS_PAIR_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"
"#,
    ),
    ("repo/src/lib.rs", ""),
];
