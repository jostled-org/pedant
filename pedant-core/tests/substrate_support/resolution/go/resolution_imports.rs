//! File-scoped import bindings, and the exact names each import form binds.
//!
//! Go binds an import in the file that writes it, never in the package. Two
//! files of one package importing the same path therefore hold two bindings,
//! and a name one file aliases is not that name in the other.
//!
//! A dot import binds no name at all: it pulls the imported package's names into
//! the file. What that binds is decided by the corpus, so a dot import the
//! snapshot holds and one it does not answer differently for the same
//! unresolved name.

use crate::resolution::go::fixture::resolve_default;
use crate::resolution::go::resolution_fixtures::IMPORT_FORMS;
use crate::resolution::go::resolution_views::{unit_definitions, unit_references};
use crate::resolution::go::views::borrowed;

/// The package unit whose two files state every import form.
const APP: &str = "x#production";

/// Every definition the importing package states.
const APP_DEFINITIONS: &[&str] = &[
    "x#production|Package|app|aliased.go:0|",
    "x#production|Function|Aliased|aliased.go:8|app",
    "x#production|Function|Dotted|dotted.go:7|app",
    "x#production|Function|Outside|outside.go:4|app",
];

/// Every reference the importing package states, with the target each import
/// form binds.
///
/// The last two rows carry the dot import whose package is outside the snapshot.
/// `Elsewhere` is declared by no package the corpus holds, and the file that
/// reads it pulls unspelled names from a package the corpus cannot see, so the
/// answer is `ExternalDefinition` rather than `MissingDefinition`: the report
/// says the name is not here, not that it exists nowhere.
const APP_REFERENCES: &[&str] = &[
    "x#production|Import|x/util|aliased.go:3|resolved|x/util#production::util|",
    "x#production|Import|x/text|aliased.go:4|resolved|x/text#production::text|",
    "x#production|Import|x/blank|aliased.go:5|resolved|x/blank#production::blank|",
    "x#production|Type|string|aliased.go:8|-||ExternalDefinition",
    "x#production|Call|Name|aliased.go:9|resolved|x/util#production::Name|",
    "x#production|Call|Join|aliased.go:9|resolved|x/text#production::Join|",
    "x#production|Call|Join|aliased.go:9|-||MissingDefinition",
    "x#production|Import|x/text|dotted.go:3|resolved|x/text#production::text|",
    "x#production|Import|x/util|dotted.go:4|resolved|x/util#production::util|",
    "x#production|Type|string|dotted.go:7|-||ExternalDefinition",
    "x#production|Call|Join|dotted.go:8|resolved|x/text#production::Join|",
    "x#production|Call|Name|dotted.go:8|resolved|x/util#production::Name|",
    "x#production|Value|tx|dotted.go:8|-||MissingDefinition",
    "x#production|Call|Join|dotted.go:8|-||DynamicDispatch",
    "x#production|Import|example.com/outside|outside.go:2|-||ExternalDefinition",
    "x#production|Type|string|outside.go:4|-||ExternalDefinition",
    "x#production|Call|Elsewhere|outside.go:5|-||ExternalDefinition",
];

/// 5.T1 (Invariant 12): imports are file-scoped, and the default name, the
/// explicit alias, the dot import, and the blank import each bind exactly what
/// Go says they bind.
#[test]
fn go_import_bindings_are_file_scoped_and_form_exact() {
    let (tree, snapshot, resolution) = resolve_default(IMPORT_FORMS);

    assert_eq!(
        &*borrowed(&unit_definitions(&resolution, APP)),
        APP_DEFINITIONS,
        "the importing package states one package definition and its two functions"
    );
    assert_eq!(
        &*borrowed(&unit_references(&resolution, APP)),
        APP_REFERENCES,
        "each import form binds exactly the names Go gives it, in its own file"
    );

    drop(resolution);
    drop(snapshot);
    drop(tree);
}
