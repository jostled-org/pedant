//! The release protocol a releaseable packaged workspace is published through.
//!
//! [`super::graph_cases`] states every packaged graph the proof has to refuse;
//! this module states what the accepted one has to show. One row drives the
//! whole protocol against tools that compile nothing, and reads the four
//! documents between the release and the archives: the order, the manifests the
//! archives carry, the workspace those archives are resolved in, and the
//! caller's own repository.

use super::fixture::{
    FIRST_PARTY_EDGES, NAVIGATION_PACKAGE, RELEASE_ORDER, STAGED_VERSION, staged_manifest,
};
use super::row::{Fault, PINNED_BINARIES, RowRoot};
use super::verdict::assert_row_is_clean;

/// How many optional, feature-gated first-party edges the released workspace
/// holds, and how many of them one consumer takes.
///
/// Both numbers, because they are two shapes. Three edges spread over three
/// consumers is the release the Go surface left; three with two on the
/// navigation product is the release this one publishes, and only the second
/// number can tell them apart.
const GATED_EDGES: usize = 3;

/// How many of those gated edges the navigation product takes.
const GATED_NAVIGATION_EDGES: usize = 2;

/// How many members the fixture releases.
///
/// Every reading below compares a table derived from a fixture table against a
/// document the run produced out of that same table. The two sides agree for a
/// release that lost members as readily as for the one this proof is about, so
/// the count is what makes the comparison a claim rather than a tautology.
const RELEASED_PACKAGES: usize = 8;

/// How many first-party edges the fixture declares, for the same reason.
const FIRST_PARTY_EDGE_COUNT: usize = 12;

/// How many released packages carry an inbound first-party edge, which is
/// exactly what the archive workspace has to patch.
///
/// Four with and four without, so a patch table covering every member — or only
/// the first — is visibly wrong. An edge set collapsed onto one dependency
/// keeps both counts above and shrinks this one.
const PATCHED_PACKAGES: usize = 4;

/// The staged release, the archives it produced, and the workspace they are
/// resolved in, read from one clean row.
pub(super) fn verify_dependency_ordered_release_protocol() {
    assert_eq!(
        RELEASE_ORDER.len(),
        RELEASED_PACKAGES,
        "the fixture must still release {RELEASED_PACKAGES} members"
    );
    assert_eq!(
        FIRST_PARTY_EDGES.len(),
        FIRST_PARTY_EDGE_COUNT,
        "the fixture must still declare {FIRST_PARTY_EDGE_COUNT} first-party edges"
    );

    let root = RowRoot::new();
    let label = "the dependency-ordered release protocol";
    let completed = root.run(&Fault::None);

    assert_row_is_clean(&root, label, &completed, 0, PINNED_BINARIES);
    assert_release_order_precedes_every_consumer(label);
    assert_archives_carry_the_staged_release(&root, label);
    assert_archive_workspace_answers_for_every_inbound_edge(&root, label);
}

/// Every dependency is released before the package that requires it, whether or
/// not a feature selects the edge, and the model still holds all three gated
/// ones — two of them on one consumer.
///
/// The two readings after the order are what stop it from going quiet. An order
/// check over a fixture whose edges had all become unconditional would keep
/// passing while the shape this predicate exists for was gone, and one that
/// counted three gated edges spread over three consumers would miss the shape
/// the navigation product added: one consumer whose two optional dependencies
/// each force it later in the order.
fn assert_release_order_precedes_every_consumer(label: &str) {
    let position = |name: &str| {
        RELEASE_ORDER
            .iter()
            .position(|released| *released == name)
            .unwrap_or_else(|| panic!("{label}: the release order does not name {name}"))
    };
    for (consumer, dependency, _) in FIRST_PARTY_EDGES {
        assert!(
            position(dependency) < position(consumer),
            "{label}: {dependency} must be released before {consumer}"
        );
    }
    let gated: Box<[&str]> = FIRST_PARTY_EDGES
        .iter()
        .filter(|(_, _, gated)| *gated)
        .map(|(consumer, _, _)| *consumer)
        .collect();
    assert_eq!(
        gated.len(),
        GATED_EDGES,
        "{label}: the fixture models exactly {GATED_EDGES} optional, feature-gated edges"
    );
    assert_eq!(
        gated
            .iter()
            .filter(|consumer| **consumer == NAVIGATION_PACKAGE)
            .count(),
        GATED_NAVIGATION_EDGES,
        "{label}: the navigation product takes {GATED_NAVIGATION_EDGES} of them"
    );
}

/// The eight archives are the staged release, and each carries the exact
/// manifest release-plz staged for it.
///
/// The manifest is compared whole rather than by version, because the
/// requirement is the other half of the same claim: an archive that carried the
/// staged version while still requiring a dependency's previous one is the
/// failure a registry publication reports and this repository cannot.
fn assert_archives_carry_the_staged_release(root: &RowRoot, label: &str) {
    // Sorted, because the archives are read as a directory listing and the
    // release order is a dependency order. Comparing the two unsorted would
    // have made this claim about where the navigation product sits in the
    // release, which is [`assert_release_order_precedes_every_consumer`]'s.
    let mut expected: Box<[Box<str>]> = RELEASE_ORDER
        .iter()
        .map(|name| format!("{name}-{STAGED_VERSION}.crate").into())
        .collect();
    expected.sort_unstable();
    assert_eq!(
        root.record().archives(),
        expected,
        "{label}: the packaging left archives other than this release's"
    );
    for name in RELEASE_ORDER {
        assert_eq!(
            root.record().packaged_manifest(name, STAGED_VERSION),
            staged_manifest(name),
            "{label}: the {name} archive carries a manifest release-plz never staged"
        );
    }
}

/// The generated workspace compiles the extracted archives and patches every
/// package something in it requires, so no first-party requirement is left for
/// crates.io to answer.
///
/// The patch table is read as the whole table rather than searched for entries.
/// A missing entry lets a first-party requirement resolve from the registry,
/// which is the failure this proof exists for; an extra one redirects a
/// requirement nothing states, which Cargo reports as an unused patch and the
/// proof refuses.
fn assert_archive_workspace_answers_for_every_inbound_edge(root: &RowRoot, label: &str) {
    let manifest = root.record().archive_manifest();
    for name in RELEASE_ORDER {
        assert!(
            manifest.contains(&format!("\"{name}-{STAGED_VERSION}\",")),
            "{label}: the archive workspace omits the {name} member"
        );
    }
    let patched: Box<[&str]> = manifest
        .lines()
        .filter_map(|line| line.split_once(" = { path = "))
        .map(|(name, _)| name)
        .collect();
    let inbound: Box<[&str]> = RELEASE_ORDER
        .iter()
        .copied()
        .filter(|name| {
            FIRST_PARTY_EDGES
                .iter()
                .any(|(_, dependency, _)| dependency == name)
        })
        .collect();
    assert_eq!(
        inbound.len(),
        PATCHED_PACKAGES,
        "{label}: {PATCHED_PACKAGES} released packages must carry an inbound first-party edge"
    );
    assert_eq!(
        patched, inbound,
        "{label}: the archive workspace patches the wrong set of first-party packages"
    );
    for name in inbound {
        assert!(
            manifest.contains(&format!(
                "{name} = {{ path = \"{name}-{STAGED_VERSION}\" }}"
            )),
            "{label}: {name} is patched to something other than its extracted archive"
        );
    }
}
