//! Resolution-substrate cases declared by `tests/substrate.rs`.
//!
//! Each file below owns one resolution concern. The tree is declared with
//! `#[path]` from the root for the reason stated there: cargo builds one test
//! executable per `tests/*.rs`, so a support tree must not become a root.

// The `authority*` modules hold the committed source tree to its declared
// ownership model. `authority_asserts` is a different subject — refused target
// identities — and carries the feature because only the probe can construct
// one.
mod authority;
#[cfg(feature = "resolution-test-support")]
mod authority_asserts;
#[cfg(feature = "resolution-test-support")]
mod authority_invalidation;
mod authority_model;
// `read_text` is the one reader of a tracked file: the committed-tree
// authority, the release checks, and the packaged-workspace provers all take
// it. The last of those carried its own copy until the same script was being
// read through both.
pub(crate) mod authority_scan;
/// How deeply one production body nests its control flow, read from the syntax
/// tree rather than the page, for the reason [`body_scan`] is.
pub(crate) mod body_nesting;
/// Which function bodies one production source declares: how many statements
/// each states, how deeply it nests, and what shape its tokens take. Read from
/// the syntax tree rather than the page, and language-neutral: the Go policy
/// case and the code-intelligence structure case ask the same question of
/// different trees, and a second copy of the walk would let one of them drift.
pub(crate) mod body_scan;
mod closure_asserts;
mod closure_fixtures;
/// The code-intelligence substrate: the physical declaration sites one Rust
/// extraction retains beside its definition sites.
mod code_intelligence;
/// Which bytes of one Rust source are code rather than prose. Every negative
/// claim written as a text search reads through it, so the block comment, the
/// trailing comment, and the string that only looks like a comment are answered
/// once for all of them.
pub(crate) mod comment_scan;
pub(crate) mod comment_spans;
/// Which typed error enums one production source declares. Shared by the Go
/// policy case and the code-intelligence structure case for the same reason
/// [`body_scan`] is.
pub(crate) mod error_enums;
mod fingerprint;
// The claim table and the cases that read it are split for the source-file
// budget alone, the way `closure_fixtures` sits beside `closure_asserts`.
#[cfg(feature = "resolution-test-support")]
mod fingerprint_claims;
mod fixture;
/// The Go module project cases, which name types only `go-resolution` compiles.
#[cfg(feature = "go-resolution")]
mod go;
mod inline_path_cases;
mod inline_path_fixtures;
mod limits;
/// Reading a tracked Cargo manifest, shared by every structural claim that
/// asks what a feature selects or what an edge declares.
pub(crate) mod manifest_reader;
/// Which child modules one Rust source declares, and how. The one reading
/// [`test_identity`] walks a module path with.
pub(crate) mod module_scan;
/// One production tree, claimed whole: the shape a model states it in, and the
/// walk that refuses a module nothing registered.
pub(crate) mod production_tree;
mod project;
mod project_fixtures;
mod report_views;
pub(crate) mod root_inventory;
#[cfg(feature = "resolution-test-support")]
mod selection_chain;
#[cfg(feature = "resolution-test-support")]
mod selection_chain_fixtures;
#[cfg(feature = "semantic")]
mod semantic;
/// The handshake refusal table, which only the probe-gated handshake case
/// reads. It carries the same pair of gates as its one consumer, so a build
/// with `semantic` but no probe does not compile a table nothing runs.
#[cfg(all(feature = "semantic", feature = "resolution-test-support"))]
mod semantic_asserts;
#[cfg(feature = "semantic")]
mod semantic_expectations;
#[cfg(feature = "semantic")]
mod semantic_fixtures;
#[cfg(feature = "semantic")]
mod semantic_pairing;
mod snapshot;
/// Which forbidden routes one production source takes — a panic macro, an
/// output macro, a named method, an inline test, or a trait object. Shared for
/// the same reason [`body_scan`] is.
pub(crate) mod source_routes;
mod syntactic;
mod syntactic_asserts;
mod syntactic_expectations;
mod syntactic_fixtures;
#[cfg(feature = "resolution-test-support")]
mod syntactic_probe;
/// Which file a `--exact` filter selects a registered predicate from, and where
/// a predicate is declared. Shared by the Go registration case and the
/// code-intelligence hosted-filter case for the same reason [`body_scan`] is:
/// the second question is the first plus a module walk, and two walks would let
/// one keep selecting after the other stopped.
pub(crate) mod test_identity;
/// What Git tracks, shared by every claim whose subject is a committed file
/// rather than a file that happens to be on this disk.
pub(crate) mod tracked_index;
/// Holding a tracked repository check to its executability, ShellCheck
/// registration, and CI invocation.
pub(crate) mod tracked_script;
mod unit_asserts;
mod unit_fixtures;
mod views;
