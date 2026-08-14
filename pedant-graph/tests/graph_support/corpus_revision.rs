//! The temporary Cargo repositories the revision matrix and the bounded
//! projection store are read over, written out.
//!
//! Each corpus is a real repository the production loader, snapshot, and
//! syntactic resolver read, and each revised file beside it is the exact text
//! one revision writes. A revision that changed two dimensions at once would
//! prove nothing about either, so the files here move one at a time.

use super::corpus::FixtureFile;

/// One library over three sources beside one dependency source, so a revision
/// can change one fragment and leave the other three alone.
///
/// Every leaf module states a definition and no reference, so a change to one
/// of them is graph-relevant to itself and to whatever names it, and to nothing
/// else.
pub const REVISION_CORPUS: &[FixtureFile] = &[
    ("repo/Cargo.toml", REVISION_MANIFEST),
    ("repo/src/lib.rs", REVISION_ROOT),
    ("repo/src/alpha.rs", REVISION_ALPHA),
    ("repo/src/beta.rs", REVISION_BETA),
    ("repo/crates/helper/Cargo.toml", REVISION_HELPER_MANIFEST),
    ("repo/crates/helper/src/lib.rs", REVISION_HELPER),
];

/// How many source-unit fragments [`REVISION_CORPUS`] states.
pub const REVISION_FRAGMENTS: u64 = 4;

/// The revision corpus manifest.
pub const REVISION_MANIFEST: &str = r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
helper = { path = "crates/helper" }
"#;

/// The revision corpus manifest, with the unused spare dependency added.
pub const REVISION_MANIFEST_WITH_SPARE: &str = r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
helper = { path = "crates/helper" }
spare = { path = "crates/spare" }
"#;

/// The revision corpus manifest, naming the dependency by its renamed package.
pub const REVISION_MANIFEST_RENAMED_UNIT: &str = r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
assistant = { path = "crates/helper" }
"#;

/// The dependency package's own manifest.
pub const REVISION_HELPER_MANIFEST: &str = r#"[package]
name = "helper"
version = "0.1.0"
edition = "2021"
"#;

/// The dependency package's manifest after the package is renamed.
///
/// The manifest path is unchanged, so the unit's stable key moves on the target
/// name alone.
pub const REVISION_HELPER_MANIFEST_RENAMED: &str = r#"[package]
name = "assistant"
version = "0.1.0"
edition = "2021"
"#;

/// The dependency source.
pub const REVISION_HELPER: &str = "pub fn assist() {}\n";

/// The library root of the revision corpus.
pub const REVISION_ROOT: &str = r#"pub mod alpha;
pub mod beta;

use helper::assist;

pub fn run() {
    alpha::first();
    beta::second();
    assist();
}
"#;

/// The library root after one further module is declared.
pub const REVISION_ROOT_WITH_GAMMA: &str = r#"pub mod alpha;
pub mod beta;
pub mod gamma;

use helper::assist;

pub fn run() {
    alpha::first();
    beta::second();
    assist();
}
"#;

/// The library root after one module is withdrawn.
pub const REVISION_ROOT_WITHOUT_BETA: &str = r#"pub mod alpha;

use helper::assist;

pub fn run() {
    alpha::first();
    assist();
}
"#;

/// The library root after one module is renamed, source and all.
///
/// The renamed declaration takes the line the old one held, so the module that
/// keeps its name keeps the declaration its own definitions are owned by.
pub const REVISION_ROOT_RENAMED_SOURCE: &str = r#"pub mod gamma;
pub mod beta;

use helper::assist;

pub fn run() {
    gamma::first();
    beta::second();
    assist();
}
"#;

/// The library root after the dependency package is renamed.
pub const REVISION_ROOT_RENAMED_UNIT: &str = r#"pub mod alpha;
pub mod beta;

use assistant::assist;

pub fn run() {
    alpha::first();
    beta::second();
    assist();
}
"#;

/// The first leaf module.
pub const REVISION_ALPHA: &str = "pub fn first() {}\n";

/// The second leaf module.
pub const REVISION_BETA: &str = "pub fn second() {}\n";

/// The second leaf module after a trailing comment.
///
/// The bytes differ and the report does not: the digest is the only part of the
/// fragment key this revision moves.
pub const REVISION_BETA_COMMENTED: &str = "pub fn second() {}\n// a note no graph states\n";

/// The second leaf module after one further definition.
///
/// The addition follows every retained definition, so no other span moves.
pub const REVISION_BETA_EXTENDED: &str = "pub fn second() {}\npub fn extra() {}\n";

/// The second leaf module after one further definition is stated before the
/// declaration it retains.
///
/// The retained declaration keeps its name and its kind and moves, so every
/// site naming it states a different target identity while its own bytes still
/// read the same.
pub const REVISION_BETA_SHIFTED: &str = "pub fn moved() {}\npub fn second() {}\n";

/// The module one revision adds, and the one another revision renames into.
pub const REVISION_GAMMA: &str = "pub fn third() {}\n";

/// A dependency package no source names.
///
/// Adding it changes one manifest and no source, so it states one further
/// fragment beside fragments that must all still be reused.
pub const SPARE_MANIFEST: &str = r#"[package]
name = "spare"
version = "0.1.0"
edition = "2021"
"#;

/// The unused dependency package's one source.
pub const SPARE_SOURCE: &str = "pub fn spare() {}\n";

/// One library over two sources, so a bounded projection store can be filled,
/// perturbed, and overflowed by one further fragment.
pub const PROJECTION_CORPUS: &[FixtureFile] = &[
    ("repo/Cargo.toml", PROJECTION_MANIFEST),
    ("repo/src/lib.rs", PROJECTION_ROOT),
    ("repo/src/alpha.rs", REVISION_ALPHA),
];

/// The projection corpus manifest.
pub const PROJECTION_MANIFEST: &str = r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"
"#;

/// The projection corpus manifest, with the unused spare dependency added.
pub const PROJECTION_MANIFEST_WITH_SPARE: &str = r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
spare = { path = "crates/spare" }
"#;

/// The library root of the projection corpus.
pub const PROJECTION_ROOT: &str = r#"pub mod alpha;

pub fn run() {
    alpha::first();
}
"#;

/// The projection corpus leaf after a trailing comment.
pub const PROJECTION_ALPHA_COMMENTED: &str = "pub fn first() {}\n// a note no graph states\n";

/// One library whose root names a symbol no source declares, so one of its own
/// sites is answered with a gap rather than a candidate.
///
/// The gap dimension needs a report that states one: a corpus that resolves
/// every site has no record whose gaps a restatement could move, and a rewritten
/// source would move the digest beside them.
pub const GAPPED_CORPUS: &[FixtureFile] = &[
    ("repo/Cargo.toml", PROJECTION_MANIFEST),
    ("repo/src/lib.rs", GAPPED_ROOT),
    ("repo/src/alpha.rs", REVISION_ALPHA),
];

/// How many source-unit fragments [`GAPPED_CORPUS`] states.
pub const GAPPED_FRAGMENTS: u64 = 2;

/// The library root that names one resolvable and one unresolvable symbol.
pub const GAPPED_ROOT: &str = r#"pub mod alpha;

pub fn run() {
    alpha::first();
    absent();
}
"#;
