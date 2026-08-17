//! Which callable owns each non-Rust capability finding.
//!
//! One row per backend, keyed once by language and path extension, carrying the
//! three sub-cases the tests below select from: every detection family,
//! duplicate and nested callables, and module-scope evidence. One row per
//! backend is what pairs a source with its own language: three tables each
//! keyed by their own `language` field were three chances to key them apart.
//!
//! The sources and their written-down rows live in the `*_tables` modules beside
//! this one and the assertions in [`model`](super::model), so a case here reads
//! as the claim it makes rather than as the source it makes it about.

use pedant_types::Language;

use super::model::{LanguageCase, SubCase, assert_every_backend};
use super::{family_tables, module_tables, nesting_tables};

#[cfg(feature = "ts-python")]
const PYTHON: LanguageCase = LanguageCase {
    language: Language::Python,
    extension: "py",
    families: SubCase {
        source: family_tables::PYTHON_FAMILY_SOURCE,
        families: &family_tables::PYTHON_FAMILIES,
        rows: &family_tables::PYTHON_FAMILY_ROWS,
    },
    nesting: SubCase {
        source: nesting_tables::PYTHON_NESTED_SOURCE,
        families: &nesting_tables::NESTED_FAMILIES,
        rows: &nesting_tables::PYTHON_NESTED_ROWS,
    },
    module: SubCase {
        source: module_tables::PYTHON_MODULE_SOURCE,
        families: &module_tables::PYTHON_MODULE_FAMILIES,
        rows: &module_tables::PYTHON_MODULE_ROWS,
    },
};

#[cfg(feature = "ts-javascript")]
const JAVASCRIPT: LanguageCase = LanguageCase {
    language: Language::JavaScript,
    extension: "js",
    families: SubCase {
        source: family_tables::JAVASCRIPT_FAMILY_SOURCE,
        families: &family_tables::JS_FAMILIES,
        rows: &family_tables::JS_FAMILY_ROWS,
    },
    nesting: SubCase {
        source: nesting_tables::JAVASCRIPT_NESTED_SOURCE,
        families: &nesting_tables::NESTED_FAMILIES,
        rows: &nesting_tables::JS_NESTED_ROWS,
    },
    module: SubCase {
        source: module_tables::JAVASCRIPT_MODULE_SOURCE,
        families: &module_tables::JS_MODULE_FAMILIES,
        rows: &module_tables::JS_MODULE_ROWS,
    },
};

/// The TypeScript backend, on sources that differ from the JavaScript ones only
/// in type annotations: no annotation opens a declaration or moves a byte on any
/// line a row names, so the two share every row table.
#[cfg(feature = "ts-typescript")]
const TYPESCRIPT: LanguageCase = LanguageCase {
    language: Language::TypeScript,
    extension: "ts",
    families: SubCase {
        source: family_tables::TYPESCRIPT_FAMILY_SOURCE,
        families: &family_tables::JS_FAMILIES,
        rows: &family_tables::JS_FAMILY_ROWS,
    },
    nesting: SubCase {
        source: nesting_tables::JAVASCRIPT_NESTED_SOURCE,
        families: &nesting_tables::NESTED_FAMILIES,
        rows: &nesting_tables::JS_NESTED_ROWS,
    },
    module: SubCase {
        source: module_tables::JAVASCRIPT_MODULE_SOURCE,
        families: &module_tables::JS_MODULE_FAMILIES,
        rows: &module_tables::JS_MODULE_ROWS,
    },
};

#[cfg(feature = "ts-go")]
const GO: LanguageCase = LanguageCase {
    language: Language::Go,
    extension: "go",
    families: SubCase {
        source: family_tables::GO_FAMILY_SOURCE,
        families: &family_tables::GO_FAMILIES,
        rows: &family_tables::GO_FAMILY_ROWS,
    },
    nesting: SubCase {
        source: nesting_tables::GO_NESTED_SOURCE,
        families: &nesting_tables::NESTED_FAMILIES,
        rows: &nesting_tables::GO_NESTED_ROWS,
    },
    module: SubCase {
        source: module_tables::GO_MODULE_SOURCE,
        families: &module_tables::GO_MODULE_FAMILIES,
        rows: &module_tables::GO_MODULE_ROWS,
    },
};

#[cfg(feature = "ts-bash")]
const BASH: LanguageCase = LanguageCase {
    language: Language::Bash,
    extension: "sh",
    families: SubCase {
        source: family_tables::BASH_FAMILY_SOURCE,
        families: &family_tables::BASH_FAMILIES,
        rows: &family_tables::BASH_FAMILY_ROWS,
    },
    nesting: SubCase {
        source: nesting_tables::BASH_NESTED_SOURCE,
        families: &nesting_tables::NESTED_FAMILIES,
        rows: &nesting_tables::BASH_NESTED_ROWS,
    },
    module: SubCase {
        source: module_tables::BASH_MODULE_SOURCE,
        families: &module_tables::BASH_MODULE_FAMILIES,
        rows: &module_tables::BASH_MODULE_ROWS,
    },
};

/// Every backend this build links a grammar for.
///
/// One array with a `cfg` per element, so a disabled grammar drops its row at
/// compile time and the coverage guard reads this table's own length instead of
/// a second hand-written feature list.
fn enabled_cases() -> Box<[LanguageCase]> {
    [
        #[cfg(feature = "ts-python")]
        PYTHON,
        #[cfg(feature = "ts-javascript")]
        JAVASCRIPT,
        #[cfg(feature = "ts-typescript")]
        TYPESCRIPT,
        #[cfg(feature = "ts-go")]
        GO,
        #[cfg(feature = "ts-bash")]
        BASH,
    ]
    .into_iter()
    .collect()
}

/// 4.T3 (Invariants 1–3): every enabled backend's complete flat sequence is the
/// written-down one, and its symbol projection is exactly that sequence
/// filtered on callable ownership.
#[test]
fn non_rust_all_detection_families_have_exact_callable_ownership() {
    assert_every_backend(&enabled_cases(), "test", |backend| &backend.families);
}

/// 4.T4 (Invariants 4 and 5): equal names at different declarations are
/// different symbols, and the narrowest named callable owns the evidence.
#[test]
fn non_rust_duplicate_and_nested_callables_have_exact_ownership() {
    assert_every_backend(&enabled_cases(), "nested", |backend| &backend.nesting);
}

/// 4.T5 (Invariants 6 and 7): module-level evidence stays flat, and no callable
/// below it inherits the capability.
#[test]
fn non_rust_module_evidence_stays_flat_and_unpropagated() {
    assert_every_backend(&enabled_cases(), "module", |backend| &backend.module);
}
