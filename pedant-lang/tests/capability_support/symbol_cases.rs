//! Which callable owns each non-Rust capability finding.
//!
//! Three cases, one written-down table each: every detection family, duplicate
//! and nested callables, and module-scope evidence. The tables live beside this
//! file in `symbol_*_tables.rs` and the assertions in
//! [`symbol_model`](crate::symbol_model), so a case here reads as the claim it
//! makes rather than as the source it makes it about.

use pedant_types::Language;

use crate::symbol_model::{Case, assert_case, assert_covered};

/// 4.T3 (Invariants 1–3): every enabled backend's complete flat sequence is the
/// written-down one, and its symbol projection is exactly that sequence
/// filtered on callable ownership.
#[test]
fn non_rust_all_detection_families_have_exact_callable_ownership() {
    use crate::symbol_family_tables as tables;

    let mut reached = 0_usize;

    #[cfg(feature = "ts-python")]
    {
        assert_case(&Case {
            language: Language::Python,
            path: "test.py",
            source: tables::PYTHON_FAMILY_SOURCE,
            families: &tables::PYTHON_FAMILIES,
            rows: &tables::PYTHON_FAMILY_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-javascript")]
    {
        assert_case(&Case {
            language: Language::JavaScript,
            path: "test.js",
            source: tables::JAVASCRIPT_FAMILY_SOURCE,
            families: &tables::JS_FAMILIES,
            rows: &tables::JS_FAMILY_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-typescript")]
    {
        assert_case(&Case {
            language: Language::TypeScript,
            path: "test.ts",
            source: tables::TYPESCRIPT_FAMILY_SOURCE,
            families: &tables::JS_FAMILIES,
            rows: &tables::JS_FAMILY_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-go")]
    {
        assert_case(&Case {
            language: Language::Go,
            path: "test.go",
            source: tables::GO_FAMILY_SOURCE,
            families: &tables::GO_FAMILIES,
            rows: &tables::GO_FAMILY_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-bash")]
    {
        assert_case(&Case {
            language: Language::Bash,
            path: "test.sh",
            source: tables::BASH_FAMILY_SOURCE,
            families: &tables::BASH_FAMILIES,
            rows: &tables::BASH_FAMILY_ROWS,
        });
        reached += 1;
    }

    assert_covered(reached);
}

/// 4.T4 (Invariants 4 and 5): equal names at different declarations are
/// different symbols, and the narrowest named callable owns the evidence.
#[test]
fn non_rust_duplicate_and_nested_callables_have_exact_ownership() {
    use crate::symbol_nesting_tables as tables;

    let mut reached = 0_usize;

    #[cfg(feature = "ts-python")]
    {
        assert_case(&Case {
            language: Language::Python,
            path: "nested.py",
            source: tables::PYTHON_NESTED_SOURCE,
            families: &[],
            rows: &tables::PYTHON_NESTED_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-javascript")]
    {
        assert_case(&Case {
            language: Language::JavaScript,
            path: "nested.js",
            source: tables::JAVASCRIPT_NESTED_SOURCE,
            families: &[],
            rows: &tables::JS_NESTED_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-typescript")]
    {
        assert_case(&Case {
            language: Language::TypeScript,
            path: "nested.ts",
            source: tables::JAVASCRIPT_NESTED_SOURCE,
            families: &[],
            rows: &tables::JS_NESTED_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-go")]
    {
        assert_case(&Case {
            language: Language::Go,
            path: "nested.go",
            source: tables::GO_NESTED_SOURCE,
            families: &[],
            rows: &tables::GO_NESTED_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-bash")]
    {
        assert_case(&Case {
            language: Language::Bash,
            path: "nested.sh",
            source: tables::BASH_NESTED_SOURCE,
            families: &[],
            rows: &tables::BASH_NESTED_ROWS,
        });
        reached += 1;
    }

    assert_covered(reached);
}

/// 4.T5 (Invariants 6 and 7): module-level evidence stays flat, and no callable
/// below it inherits the capability.
#[test]
fn non_rust_module_evidence_stays_flat_and_unpropagated() {
    use crate::symbol_module_tables as tables;

    let mut reached = 0_usize;

    #[cfg(feature = "ts-python")]
    {
        assert_case(&Case {
            language: Language::Python,
            path: "module.py",
            source: tables::PYTHON_MODULE_SOURCE,
            families: &[],
            rows: &tables::PYTHON_MODULE_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-javascript")]
    {
        assert_case(&Case {
            language: Language::JavaScript,
            path: "module.js",
            source: tables::JAVASCRIPT_MODULE_SOURCE,
            families: &[],
            rows: &tables::JS_MODULE_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-typescript")]
    {
        assert_case(&Case {
            language: Language::TypeScript,
            path: "module.ts",
            source: tables::JAVASCRIPT_MODULE_SOURCE,
            families: &[],
            rows: &tables::JS_MODULE_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-go")]
    {
        assert_case(&Case {
            language: Language::Go,
            path: "module.go",
            source: tables::GO_MODULE_SOURCE,
            families: &[],
            rows: &tables::GO_MODULE_ROWS,
        });
        reached += 1;
    }

    #[cfg(feature = "ts-bash")]
    {
        assert_case(&Case {
            language: Language::Bash,
            path: "module.sh",
            source: tables::BASH_MODULE_SOURCE,
            families: &[],
            rows: &tables::BASH_MODULE_ROWS,
        });
        reached += 1;
    }

    assert_covered(reached);
}
