//! Go module repositories the directive-authority, refusal, and limit cases
//! read.
//!
//! Every replacement target that must never be followed is written into the
//! tree, so "the loader did not read it" is a claim about the loader rather
//! than about a directory that happened to be missing.

use crate::resolution::fixture::FixtureFile;

/// One main module whose root manifest exercises every directive form at once:
/// an exact replacement that outranks a path-only one, a path-only replacement
/// that applies alone, an unused local replacement, a version-only replacement,
/// an unreplaced external requirement, and an exclusion that matches nothing
/// required.
///
/// The admitted child re-states `replace` and `exclude` for its own requirement.
/// Only the root may decide either, so the child's requirement must stay
/// external and `local/child-ignored` must never be read.
pub const DIRECTIVE_AUTHORITY: &[FixtureFile] = &[
    (
        "repo/go.mod",
        r#"module example.com/root

go 1.22

require (
	example.com/exact v1.0.0
	example.com/wide v0.3.0
	example.com/absent v2.1.0
	example.com/rehomed v1.5.0
)

exclude example.com/never v9.9.9

replace (
	example.com/exact v1.0.0 => ./local/exact
	example.com/exact => ./local/outranked
	example.com/wide => ./local/wide
	example.com/unused => ./local/unused
	example.com/rehomed v1.5.0 => example.com/elsewhere v3.0.0
)
"#,
    ),
    ("repo/root.go", "package root\n"),
    (
        "repo/local/exact/go.mod",
        r#"module example.com/exact

go 1.22

require example.com/child v0.1.0

exclude example.com/child v0.1.0

replace example.com/child => ./child-ignored
"#,
    ),
    (
        "repo/local/exact/child-ignored/go.mod",
        "module example.com/child\n",
    ),
    (
        "repo/local/outranked/go.mod",
        "module example.com/mismatched-and-never-read\n",
    ),
    (
        "repo/local/wide/go.mod",
        r#"module example.com/wide

require example.com/absent v1.0.0
"#,
    ),
    ("repo/local/unused/go.mod", "module example.com/unused\n"),
];

/// A root, one admitted child, and one grandchild the root also replaces. Three
/// manifests over two dependency hops, so the manifest ceiling and the depth
/// ceiling each refuse at a different lowered value.
pub const CHAINED_MODULES: &[FixtureFile] = &[
    (
        "repo/go.mod",
        r#"module example.com/root

require example.com/first v1.0.0

replace (
	example.com/first => ./local/first
	example.com/second => ./local/second
)
"#,
    ),
    (
        "repo/local/first/go.mod",
        r#"module example.com/first

require example.com/second v1.0.0
"#,
    ),
    ("repo/local/second/go.mod", "module example.com/second\n"),
];
