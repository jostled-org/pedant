//! Lexical shadowing, read through the claims a package makes about its own
//! identifiers.
//!
//! A receiver, a parameter, and a local all bind names into scopes an import
//! and a package declaration also reach. The occurrence a binding covers names
//! that binding, which is not a report entity, so the package and the import
//! make no claim on it at all.

use crate::resolution::go::fixture::resolve_default;
use crate::resolution::go::resolution_fixtures::SHADOWING;
use crate::resolution::go::resolution_views::unit_references;
use crate::resolution::go::views::borrowed;

/// The package unit whose bindings shadow its import.
const APP: &str = "x#production";

/// Every reference the shadowing package states.
///
/// `util` is written five times: once as an import path, three times as a name
/// a binding covers, and once where nothing covers it. Only the last one is a
/// claim on the imported package.
const APP_REFERENCES: &[&str] = &[
    "x#production|Import|x/util|shadow.go:2|resolved|x/util#production::util|",
    "x#production|Type|Counter|shadow.go:6|resolved|x#production::Counter|",
    "x#production|Type|Counter|shadow.go:6|resolved|x#production::Counter|",
    "x#production|Type|string|shadow.go:10|-||ExternalDefinition",
    "x#production|Type|string|shadow.go:10|-||ExternalDefinition",
    "x#production|Type|string|shadow.go:17|-||ExternalDefinition",
    "x#production|Call|Name|shadow.go:18|resolved|x/util#production::Name|",
];

/// 5.T2 (Invariant 13): a parameter, a receiver, and a local prevent the
/// package and the import from claiming the occurrences they cover.
#[test]
fn go_lexical_shadowing_blocks_package_and_import_claims() {
    let (tree, snapshot, resolution) = resolve_default(SHADOWING);

    let stated = unit_references(&resolution, APP);
    assert_eq!(
        &*borrowed(&stated),
        APP_REFERENCES,
        "only the unshadowed occurrence claims the imported package"
    );

    let claiming: Box<[&&str]> = APP_REFERENCES
        .iter()
        .filter(|line| line.contains("x/util#production"))
        .collect();
    assert_eq!(
        claiming.len(),
        2,
        "exactly the import specification and the unshadowed call name the imported package"
    );

    drop(resolution);
    drop(snapshot);
    drop(tree);
}
