//! Every packaged graph the release proof has to refuse.
//!
//! The clean lifecycle row proves the graph check accepts a good graph, which a
//! check that accepted everything would also do. These rows are the other half:
//! the fake Cargo hands the proof one bent graph per violation class, and each
//! is required to draw the refusal that names it.

use super::fixture;
use super::row::{Fault, RowRoot};
use super::verdict::{
    REFUSED_STATUS, assert_nothing_compiled, assert_refusal, assert_row_is_clean,
};

/// The refusal every unreleaseable graph must produce.
const GRAPH_REFUSAL: &str = "the packaged graph is not releaseable";

/// The warning Cargo prints when a patch redirects a requirement no member
/// states, which the proof reads out of the metadata transcript.
const UNUSED_PATCH_WARNING: &str =
    "warning: Patch `fixture-a v0.2.0` was not used in the crate graph.";

/// One way the packaged graph can be wrong, and the refusal it must draw.
///
/// The proof's graph check is a single jq expression producing five violation
/// classes, and a conforming graph exercises none of them: an expression that
/// silently matched nothing would pass every other row here and the real run
/// besides. Each row below bends exactly one thing and requires the refusal
/// that names it.
struct GraphViolation {
    /// What is wrong with the graph, for the assertion message.
    label: &'static str,
    /// The jq filter that bends the archive metadata into that shape.
    ///
    /// `{origin}` expands to the row's repository root, which is the checkout
    /// the proof must refuse a member for resolving through.
    mutation: &'static str,
    /// The fragment of the refusal the proof must print.
    refusal: &'static str,
}

/// Every violation class the packaged-graph check implements.
const GRAPH_VIOLATIONS: &[GraphViolation] = &[
    GraphViolation {
        label: "a member short of the release order",
        mutation: ".packages |= map(select(.name != \"fixture-h\"))",
        refusal: "first-party members rather than 8",
    },
    GraphViolation {
        label: "a member resolved from the registry",
        mutation: ".packages[0].source = \"registry+https://example.invalid/index\"",
        refusal: "resolves through the registry rather than its archive",
    },
    GraphViolation {
        label: "a member resolved through the operator's checkout",
        mutation: ".packages[0].manifest_path = \"{origin}/fixture-a/Cargo.toml\"",
        refusal: "resolves through the original checkout",
    },
    GraphViolation {
        label: "a member resolved outside the archive workspace",
        mutation: ".packages[0].manifest_path = \"/nowhere/fixture-a/Cargo.toml\"",
        refusal: "resolves outside the archive workspace",
    },
    GraphViolation {
        label: "a member carrying an unstaged version",
        mutation: ".packages[0].version = \"9.9.9\"",
        refusal: "carries version 9.9.9 rather than the staged 0.2.0",
    },
    GraphViolation {
        label: "a member stating an unstaged requirement",
        mutation: "(.packages[] | select(.name == \"fixture-b\") | .dependencies[0].req) = \"^9.9.9\"",
        refusal: "states requirement ^9.9.9",
    },
    GraphViolation {
        label: "a resolved edge pointing outside the archive members",
        mutation: "(.resolve.nodes[] | select(.deps | length > 0) | .deps[0].pkg) \
                   = \"registry+https://example.invalid/index#fixture-a@0.2.0\"",
        refusal: "resolves through the registry rather than its archive",
    },
];

/// Every unreleaseable packaged graph is refused, by name, before the archive
/// workspace compiles.
pub(super) fn verify_packaged_graph_refusals() {
    for violation in GRAPH_VIOLATIONS {
        unreleaseable_graph_is_refused(&RowRoot::new(), violation);
    }
    unused_patch_is_refused(&RowRoot::new());
}

/// One bent graph draws its own refusal and compiles nothing.
fn unreleaseable_graph_is_refused(root: &RowRoot, violation: &GraphViolation) {
    let label: Box<str> = format!("a packaged graph with {}", violation.label).into();
    let origin = fixture::original_checkout(&root.repository);
    let mutation: Box<str> = violation.mutation.replace("{origin}", &origin).into();
    let fault = Fault::Graph {
        mutation: &mutation,
        warning: "",
    };
    let completed = root.run(&fault);

    assert_row_is_clean(
        root,
        &label,
        &completed,
        REFUSED_STATUS,
        fault.surviving_tool_builds(),
    );
    assert_refusal(&label, &completed, GRAPH_REFUSAL);
    assert_refusal(&label, &completed, violation.refusal);
    assert_nothing_compiled(root, &label);
}

/// A patch the crate graph never consulted is refused, because the graph below
/// it proves nothing about the requirement that patch was meant to redirect.
fn unused_patch_is_refused(root: &RowRoot) {
    let label = "a packaged graph holding an unused patch";
    let fault = Fault::Graph {
        mutation: "",
        warning: UNUSED_PATCH_WARNING,
    };
    let completed = root.run(&fault);

    assert_row_is_clean(
        root,
        label,
        &completed,
        REFUSED_STATUS,
        fault.surviving_tool_builds(),
    );
    assert_refusal(label, &completed, "was not used in the crate graph");
    assert_nothing_compiled(root, label);
}
