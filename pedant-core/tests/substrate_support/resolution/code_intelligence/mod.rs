//! The code-intelligence substrate `pedant-core` owns.
//!
//! One concern per file, the way the sibling resolution modules are split.

mod rust_sites;

/// Where a retained site's bytes begin and end, including the fallbacks no
/// parse can reach. It carries the proof gate because only the adapter that
/// feature compiles can put a coordinate the parser never produces in front of
/// the resolution.
#[cfg(feature = "resolution-test-support")]
mod rust_coordinates;

/// The product dependency and feature boundary, and the tracked owners that
/// hold the admitted closure to it. Both read tracked manifests and scripts, so
/// they compile and run in every configuration — including the one a release is
/// cut from, which is where a widened edge would first cost something.
mod dependency_attestation;
mod dependency_boundary;
mod dependency_capabilities;
mod dependency_model;
mod feature_model;

/// The completed product boundary: what the finished tree is allowed to do, how
/// it is allowed to be written, and what the repository ships once it exists.
///
/// [`product_model`] is the one inventory all three read, and
/// [`product_surface`] is the one parse. Two inventories or two parses would let
/// one claim range over a tree another never saw, which is the failure that
/// makes a structural forbid pass over the module it was written to catch.
mod capability_model;
mod error_model;
mod forbidden_model;
mod graph_model;
/// Which registered predicate each `--exact` filter in the tracked workflow
/// selects. Read here rather than beside the receipt classifier because the
/// answer is a property of the workspace, and the classifier only reads what the
/// workflow says.
mod hosted_filter_model;
mod hosted_filters;
/// The products an operator is told to install, one row per published binary.
/// Beside [`operator_documentation`] rather than inside it because an installed
/// product and a served command are different subjects: nothing relates the two
/// but the document that states both.
mod installation_model;
mod limit_model;
mod operation_model;
/// What the README tells an operator to install and run, compared with the
/// command tree and tool registry that serve it. Read here rather than in the
/// product's own root because the subject is a repository document, and the
/// three-product boundary it describes is this file's whole neighbourhood.
mod operator_documentation;
mod product_model;
mod product_surface;
/// How the completed product's bodies are written: none twice, none nested past
/// two layers, and every ceiling checked before the first retention. Split from
/// [`production_structure`] for the source-file budget alone, and driven from
/// it, so both halves read the one surface that case reads.
mod production_bodies;
mod production_structure;
mod repository_inventory;
/// The commands and tools the navigation product serves, read from its `clap`
/// command tree and its registry table. The source half of
/// [`operator_documentation`], which reads the document those two are compared
/// against.
mod served_inventory;
mod source_capabilities;

/// The negative half of the same boundary: the lint CLI and the security MCP
/// server register no navigation surface, and their own byte controls are still
/// declared where the route runs them. It reads tracked sources and manifests
/// and runs nothing, so it holds in every configuration.
mod product_registries;

/// The shared source provider: the repositories its cases read, the
/// caller-written providers that prove the entry points are generic, and the
/// three claims about what sharing one changes. Every case names both language
/// owners and reads the production observation stream, so all of them carry the
/// Go and proof gates their exact route selects.
#[cfg(all(feature = "go-resolution", feature = "resolution-test-support"))]
mod caller;
#[cfg(all(feature = "go-resolution", feature = "resolution-test-support"))]
mod go_fixture;
#[cfg(all(feature = "go-resolution", feature = "resolution-test-support"))]
mod provider_contract;
#[cfg(all(feature = "go-resolution", feature = "resolution-test-support"))]
mod provider_parity;
#[cfg(all(feature = "go-resolution", feature = "resolution-test-support"))]
mod provider_sharing;
#[cfg(all(feature = "go-resolution", feature = "resolution-test-support"))]
mod rust_fixture;
