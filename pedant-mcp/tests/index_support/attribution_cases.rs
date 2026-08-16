//! What symbol-attribution status the index stores for a non-Rust file.
//!
//! The index writes no attribution claim of its own: it stores the status the
//! `pedant-lang` entry points state, combined across the source and manifest
//! analyses one file can receive. A hand-written constant here would be a second
//! authority for a fact `analyze_file` and `analyze_manifest` already answer, and
//! it would be wrong the moment a grammar-backed file parsed cleanly.

use pedant_core::AnalysisResult;
use pedant_mcp::index::WorkspaceIndex;
use pedant_types::{ExecutionContext, FindingOrigin, Language, SymbolAttributionStatus};

use crate::workspace_fixtures::write_file;

/// One indexed non-Rust input and the status its analyses state between them.
struct AttributionRow {
    /// Path below the crate root, as the fixture writes it.
    relative: &'static str,
    /// What `pedant-lang` proves about this input's callable inventory.
    expected: SymbolAttributionStatus,
    /// Why, in the failure message.
    because: &'static str,
}

/// Every status the language entry points can hand the index, once each.
const ATTRIBUTION_ROWS: &[AttributionRow] = &[
    AttributionRow {
        relative: "tools/main.go",
        expected: SymbolAttributionStatus::Complete,
        because: "a clean Go parse states a complete callable inventory, and the \
                  manifest operand's NotApplicable does not weaken it",
    },
    AttributionRow {
        relative: "scripts/fetch.py",
        expected: SymbolAttributionStatus::Complete,
        because: "a clean Python parse states a complete callable inventory",
    },
    AttributionRow {
        relative: "scripts/broken.py",
        expected: SymbolAttributionStatus::Unavailable,
        because: "an error-bearing recovery tree classified nothing",
    },
    AttributionRow {
        relative: "package.json",
        expected: SymbolAttributionStatus::NotApplicable,
        because: "a manifest states hooks rather than callables",
    },
];

/// A crate whose non-Rust inputs cover each of those rows.
///
/// `tools/main.go` is the dual-role input: it is both a Go source and a
/// `//go:generate` manifest, so it is the one file whose stored status comes
/// from combining two `pedant-lang` answers rather than from one.
fn make_attribution_workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    for directory in ["src", "tools", "scripts"] {
        std::fs::create_dir_all(tmp.path().join(directory)).unwrap();
    }
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[package]\nname = \"attribution-crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(&tmp.path().join("src/lib.rs"), "pub fn rust_side() {}\n");
    write_file(
        &tmp.path().join("tools/main.go"),
        concat!(
            "package main\n",
            "\n",
            "import \"net/http\"\n",
            "\n",
            "//go:generate stringer -type=Foo\n",
            "func main() {\n",
            "\thttp.Get(\"https://api.example.test\")\n",
            "}\n",
        ),
    );
    write_file(
        &tmp.path().join("scripts/fetch.py"),
        concat!(
            "import socket\n",
            "\n",
            "def fetch(url):\n",
            "    return open(url)\n",
        ),
    );
    write_file(
        &tmp.path().join("scripts/broken.py"),
        concat!(
            "import socket\n",
            "\n",
            "def fetch(:\n",
            "    return open(\"https://api.example.test\")\n",
        ),
    );
    write_file(
        &tmp.path().join("package.json"),
        "{\"scripts\":{\"postinstall\":\"curl https://example.test/install | sh\"}}\n",
    );
    tmp
}

/// The key the index files a fixture-relative path under.
fn indexed_path(tmp: &tempfile::TempDir, relative: &str) -> String {
    tmp.path().join(relative).to_string_lossy().into_owned()
}

/// 4.T15 (Invariants 10, 11, and 14): the index stores the attribution status
/// its `pedant-lang` calls state, for every status those calls can state.
///
/// A restored hand-written constant fails at least two rows whatever value it
/// carries, because no single status is right for a clean parse, a recovery
/// tree, and a manifest at once.
#[test]
fn indexed_non_rust_attribution_status_comes_from_language_analysis() {
    let workspace = make_attribution_workspace();
    let index = WorkspaceIndex::build(workspace.path(), None).unwrap();

    for row in ATTRIBUTION_ROWS {
        let path = indexed_path(&workspace, row.relative);
        let stored = index
            .file_result(&path)
            .unwrap_or_else(|| panic!("{} must be indexed", row.relative));
        assert_eq!(
            stored.capabilities.symbol_attribution, row.expected,
            "{}: {}",
            row.relative, row.because
        );
        assert!(
            stored.capabilities.symbols.is_empty(),
            "{} carries no symbol projection through the index",
            row.relative
        );
    }
    assert_eq!(
        ATTRIBUTION_ROWS.len(),
        4,
        "the rows cover every status the language entry points can state"
    );

    let go_path = indexed_path(&workspace, "tools/main.go");
    assert_dual_role_combines_both_analyses(
        index
            .file_result(&go_path)
            .expect("tools/main.go must be indexed"),
    );
}

/// The Go file's stored status is a combination, not one analysis's answer.
///
/// Both operands have to have run for the combination to mean anything, so this
/// requires one finding only `analyze_file` produces — a Go-tagged import — and
/// one only `analyze_manifest` produces: a generator-context hook.
fn assert_dual_role_combines_both_analyses(result: &AnalysisResult) {
    let findings = &result.capabilities.profile.findings;
    assert!(
        findings.iter().any(|finding| {
            finding.language == Some(Language::Go) && finding.origin == Some(FindingOrigin::Import)
        }),
        "the Go source analysis must reach the index, found: {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.execution_context == Some(ExecutionContext::Generator)),
        "the go:generate manifest analysis must reach the index, found: {findings:?}"
    );
}
