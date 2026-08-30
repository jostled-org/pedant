//! What each of the six admitted sources declares, one row at a time.
//!
//! These tables are this root's statement of the closed structure table, and
//! they are stated against the *published outline* rather than against any one
//! recognizer. Three producers reach them: `pedant-core`'s Rust site inventory
//! for the resolved Rust file, its Go fact projection for the Go module, and
//! `pedant-syntax`'s bound walk for everything else. A row that only one of
//! them can satisfy is exactly the drift this root exists to catch.

use pedant_snippet::StructureCoverage;
use pedant_types::StructureKind;

/// One expected structure: its kind, its declared name, and the position of the
/// structure that owns it *within the same file's outline*.
pub struct Expected {
    /// What it declares.
    pub kind: StructureKind,
    /// Its declared name, absent where its grammar states none.
    pub name: Option<&'static str>,
    /// The position of its owner in the same outline.
    pub owner: Option<usize>,
}

/// One admitted source and the complete outline it states.
///
/// The reaching projects and the evidence tier sit beside the rows rather than
/// in a table of their own. Both are per-file facts keyed by the same path, and
/// a second table keyed the same way is a second place a ninth admitted source,
/// or a reordering, has to be applied.
pub struct FileRows {
    /// The normalized repository path.
    pub path: &'static str,
    /// Every structure the source declares, in source order.
    pub rows: &'static [Expected],
    /// Every project that reached this source, as its unit, in listing order.
    pub projects: &'static [&'static str],
    /// What kind of evidence stands behind every structure it declares.
    pub coverage: StructureCoverage,
}

/// A structure of `kind` named `name`, owned by `owner`.
const fn row(kind: StructureKind, name: Option<&'static str>, owner: Option<usize>) -> Expected {
    Expected { kind, name, owner }
}

const RUST_LIBRARY_ROWS: &[Expected] = &[
    row(StructureKind::Module, Some("inner"), None),
    row(StructureKind::Struct, Some("Job"), Some(0)),
    row(StructureKind::Enum, Some("Mode"), Some(0)),
    row(StructureKind::Union, Some("Bits"), Some(0)),
    row(StructureKind::Trait, Some("Run"), Some(0)),
    row(StructureKind::TypeAlias, Some("Output"), Some(4)),
    row(StructureKind::Method, Some("run"), Some(4)),
    row(StructureKind::TypeAlias, Some("Alias"), Some(0)),
    row(StructureKind::Constant, Some("LIMIT"), Some(0)),
    row(StructureKind::Static, Some("NAME"), Some(0)),
    row(StructureKind::Impl, None, Some(0)),
    row(StructureKind::Constant, Some("ZERO"), Some(10)),
    row(StructureKind::Function, Some("new"), Some(10)),
    row(StructureKind::Method, Some("id"), Some(10)),
    row(StructureKind::Impl, None, Some(0)),
    row(StructureKind::TypeAlias, Some("Output"), Some(14)),
    row(StructureKind::Method, Some("run"), Some(14)),
    row(StructureKind::Function, Some("entry"), None),
    row(StructureKind::Function, Some("make"), None),
];

const RUST_BINARY_ROWS: &[Expected] = &[row(StructureKind::Function, Some("main"), None)];

const GO_MAIN_ROWS: &[Expected] = &[
    row(StructureKind::Package, Some("main"), None),
    row(StructureKind::Struct, Some("Job"), None),
    row(StructureKind::Field, Some("ID"), Some(1)),
    row(StructureKind::Field, Some("name"), Some(1)),
    row(StructureKind::Struct, Some("Special"), None),
    row(StructureKind::Field, Some("Job"), Some(4)),
    row(StructureKind::Interface, Some("Runner"), None),
    row(StructureKind::Method, Some("Run"), Some(6)),
    row(StructureKind::DefinedType, Some("Count"), None),
    row(StructureKind::TypeAlias, Some("Alias"), None),
    row(StructureKind::Constant, Some("Limit"), None),
    row(StructureKind::Variable, Some("Registry"), None),
    row(StructureKind::Function, Some("New"), None),
    row(StructureKind::Method, Some("Run"), None),
];

const GO_NESTED_ROWS: &[Expected] = &[
    row(StructureKind::Package, Some("nested"), None),
    row(StructureKind::Function, Some("Helper"), None),
];

const PYTHON_ROWS: &[Expected] = &[
    row(StructureKind::Module, None, None),
    row(StructureKind::Function, Some("build"), Some(0)),
    row(StructureKind::Function, Some("fetch"), Some(0)),
    row(StructureKind::Class, Some("Job"), Some(0)),
    row(StructureKind::Method, Some("run"), Some(3)),
    row(StructureKind::Method, Some("start"), Some(3)),
    row(StructureKind::Method, Some("make"), Some(3)),
];

const BASH_ROWS: &[Expected] = &[
    row(StructureKind::Function, Some("greet"), None),
    row(StructureKind::Function, Some("farewell"), None),
];

const JAVASCRIPT_ROWS: &[Expected] = &[
    row(StructureKind::Module, None, None),
    row(StructureKind::Function, Some("build"), Some(0)),
    row(StructureKind::Function, Some("counter"), Some(0)),
    row(StructureKind::Class, Some("Job"), Some(0)),
    row(StructureKind::Field, Some("limit"), Some(3)),
    row(StructureKind::Method, Some("run"), Some(3)),
    row(StructureKind::Method, Some("make"), Some(3)),
];

const TYPESCRIPT_ROWS: &[Expected] = &[
    row(StructureKind::Module, None, None),
    row(StructureKind::Interface, Some("Runner"), Some(0)),
    row(StructureKind::Method, Some("run"), Some(1)),
    row(StructureKind::TypeAlias, Some("Alias"), Some(0)),
    row(StructureKind::Enum, Some("Mode"), Some(0)),
    row(StructureKind::Module, Some("registry"), Some(0)),
    row(StructureKind::Function, Some("build"), Some(5)),
    row(StructureKind::Class, Some("Base"), Some(0)),
    row(StructureKind::Field, Some("limit"), Some(7)),
    row(StructureKind::Method, Some("run"), Some(7)),
    row(StructureKind::Method, Some("make"), Some(7)),
    row(StructureKind::Function, Some("counter"), Some(0)),
    row(StructureKind::Class, Some("Job"), Some(0)),
    row(StructureKind::Field, Some("id"), Some(12)),
];

/// Every admitted source of the mixed repository, in normalized path order,
/// with the complete outline each one states.
pub const OUTLINES: &[FileRows] = &[
    FileRows {
        path: "crate-a/src/lib.rs",
        rows: RUST_LIBRARY_ROWS,
        projects: &["crate-a::bin::crate-a", "crate-a::lib::crate_a"],
        coverage: StructureCoverage::Resolved,
    },
    FileRows {
        path: "crate-a/src/main.rs",
        rows: RUST_BINARY_ROWS,
        projects: &["crate-a::bin::crate-a"],
        coverage: StructureCoverage::Resolved,
    },
    FileRows {
        path: "main.go",
        rows: GO_MAIN_ROWS,
        projects: &["example.com/main"],
        coverage: StructureCoverage::Resolved,
    },
    FileRows {
        path: "nested/lib.go",
        rows: GO_NESTED_ROWS,
        projects: &["example.com/nested"],
        coverage: StructureCoverage::Resolved,
    },
    FileRows {
        path: "scripts/tool.py",
        rows: PYTHON_ROWS,
        projects: &[],
        coverage: StructureCoverage::SyntaxOnly,
    },
    FileRows {
        path: "scripts/tool.sh",
        rows: BASH_ROWS,
        projects: &[],
        coverage: StructureCoverage::SyntaxOnly,
    },
    FileRows {
        path: "web/app.js",
        rows: JAVASCRIPT_ROWS,
        projects: &[],
        coverage: StructureCoverage::SyntaxOnly,
    },
    FileRows {
        path: "web/app.ts",
        rows: TYPESCRIPT_ROWS,
        projects: &[],
        coverage: StructureCoverage::SyntaxOnly,
    },
];
