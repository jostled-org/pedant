//! Lexical shadowing, read through the claims a package makes about its own
//! identifiers.
//!
//! A receiver, a parameter, and a local all bind names into scopes an import
//! and a package declaration also reach. The occurrence a binding covers names
//! that binding, which is not a report entity, so the package and the import
//! make no claim on it at all.
//!
//! Suppression alone would leave the rule half proven, because an occurrence
//! that nothing else could answer states no reference either way. Two locals
//! here therefore shadow a name that does answer: `util` in `Shadowed` covers
//! the qualifier the import binds, and `Label` in `Rebound` covers the bare
//! name the package declares.

use crate::resolution::go::fixture::resolve_default;
use crate::resolution::go::resolution_fixtures::SHADOWING;
use crate::resolution::go::resolution_views::unit_references;
use crate::resolution::go::views::borrowed;

/// The package unit whose bindings shadow its import.
const APP: &str = "x#production";

/// Every reference the shadowing package states.
///
/// `util` is written seven times: once as an import path, four times as a name
/// a binding covers, once where nothing covers it, and once as a covered
/// qualifier. Only the uncovered one is a claim on the imported package; the
/// covered qualifier enters the package's own `Helper` instead.
///
/// `Label` is written twice and stated never: the package declares it and the
/// local in `Rebound` covers the only read of it.
const APP_REFERENCES: &[&str] = &[
    "x#production|Import|x/util|shadow.go:2|resolved|x/util#production::util|",
    "x#production|Type|Counter|shadow.go:8|resolved|x#production::Counter|",
    "x#production|Type|Counter|shadow.go:8|resolved|x#production::Counter|",
    "x#production|Type|string|shadow.go:12|-||ExternalDefinition",
    "x#production|Type|string|shadow.go:12|-||ExternalDefinition",
    "x#production|Type|string|shadow.go:19|-||ExternalDefinition",
    "x#production|Call|Name|shadow.go:20|resolved|x/util#production::Name|",
    "x#production|Type|Helper|shadow.go:25|resolved|x#production::Helper|",
    "x#production|Type|string|shadow.go:25|-||ExternalDefinition",
    "x#production|Type|string|shadow.go:29|-||ExternalDefinition",
    "x#production|Type|Helper|shadow.go:30|resolved|x#production::Helper|",
    "x#production|Call|Name|shadow.go:31|resolved|x#production::Name|",
    "x#production|Type|string|shadow.go:34|-||ExternalDefinition",
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

    let claiming = stated
        .iter()
        .filter(|line| line.contains("x/util#production"))
        .count();
    assert_eq!(
        claiming, 2,
        "exactly the import specification and the unshadowed call name the imported package"
    );

    let named: Box<[&str]> = stated
        .iter()
        .filter(|line| line.contains("|Call|Name|"))
        .map(|line| &**line)
        .collect();
    assert_eq!(
        &*named,
        [
            "x#production|Call|Name|shadow.go:20|resolved|x/util#production::Name|",
            "x#production|Call|Name|shadow.go:31|resolved|x#production::Name|",
        ],
        "the import answers the uncovered qualifier and the local answers the covered one"
    );

    let package_claims: Box<[&str]> = stated
        .iter()
        .filter(|line| line.contains("x#production::Label"))
        .map(|line| &**line)
        .collect();
    assert!(
        package_claims.is_empty(),
        "the package declaration claims no occurrence its local covers: {package_claims:?}"
    );

    drop(resolution);
    drop(snapshot);
    drop(tree);
}
