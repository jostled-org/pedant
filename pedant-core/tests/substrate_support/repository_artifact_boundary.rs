//! The boundary between Cargo tests and local lifecycle authority.
//!
//! GitHub checks out tracked repository files. Local plan tooling also creates
//! ignored manifests, documents, and logs. A Cargo test that reads one of those
//! files passes locally and fails only in CI, so test source must not name one
//! as a constant or direct file-read argument.

use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ItemConst, ItemStatic};

use crate::repository_artifact_literals::string_literals;
use crate::resolution::root_inventory::{workspace_members, workspace_root};

#[test]
fn cargo_tests_do_not_depend_on_local_lifecycle_artifacts() {
    let root = workspace_root();
    let violations: Vec<Box<str>> = test_sources(&root)
        .into_iter()
        .flat_map(|source| scan_source(&root, &source))
        .collect();
    assert!(
        violations.is_empty(),
        "Cargo tests must not name local lifecycle artifacts: {violations:?}"
    );
}

fn test_sources(root: &Path) -> Box<[PathBuf]> {
    workspace_members(root)
        .into_iter()
        .flat_map(|member| rust_sources(&root.join(member).join("tests")))
        .collect()
}

fn rust_sources(directory: &Path) -> Box<[PathBuf]> {
    match directory.is_dir() {
        false => Box::new([]),
        true => fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
            .flat_map(|entry| source_entry(directory, entry))
            .collect(),
    }
}

fn source_entry(directory: &Path, entry: std::io::Result<fs::DirEntry>) -> Vec<PathBuf> {
    let path = entry
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .path();
    match (
        path.is_dir(),
        path.extension().and_then(|value| value.to_str()),
    ) {
        (true, _) => rust_sources(&path).into_vec(),
        (false, Some("rs")) => vec![path],
        (false, _) => Vec::new(),
    }
}

fn scan_source(root: &Path, source: &Path) -> Box<[Box<str>]> {
    let text =
        fs::read_to_string(source).unwrap_or_else(|error| panic!("{}: {error}", source.display()));
    let syntax = syn::parse_file(&text)
        .unwrap_or_else(|error| panic!("{} should parse: {error}", source.display()));
    let relative = source.strip_prefix(root).unwrap_or_else(|error| {
        panic!(
            "{} is outside {}: {error}",
            source.display(),
            root.display()
        )
    });
    let mut scanner = LocalArtifactScanner::new(relative);
    scanner.visit_file(&syntax);
    scanner.violations.into_boxed_slice()
}

struct LocalArtifactScanner<'path> {
    source: &'path Path,
    violations: Vec<Box<str>>,
}

impl<'path> LocalArtifactScanner<'path> {
    fn new(source: &'path Path) -> Self {
        Self {
            source,
            violations: Vec::new(),
        }
    }

    fn inspect(&mut self, expression: &Expr, owner: &str) {
        self.violations.extend(
            string_literals(expression)
                .into_iter()
                .filter(|value| is_local_lifecycle_artifact(value))
                .map(|value| {
                    format!("{}: {owner} names {value}", self.source.display()).into_boxed_str()
                }),
        );
    }
}

impl<'ast> Visit<'ast> for LocalArtifactScanner<'_> {
    fn visit_item_const(&mut self, item: &'ast ItemConst) {
        self.inspect(&item.expr, &format!("const {}", item.ident));
        visit::visit_item_const(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast ItemStatic) {
        self.inspect(&item.expr, &format!("static {}", item.ident));
        visit::visit_item_static(self, item);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if is_file_reader(&call.func) {
            for argument in &call.args {
                self.inspect(argument, "direct file read");
            }
        }
        visit::visit_expr_call(self, call);
    }
}

fn is_file_reader(expression: &Expr) -> bool {
    match expression {
        Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "open" | "read" | "read_to_string" | "read_repository_file" | "tracked_text"
            )
        }),
        _ => false,
    }
}

fn is_local_lifecycle_artifact(value: &str) -> bool {
    let manifest = [".", "manifest", ".toml"].concat();
    let first = value.split('/').next();
    value == manifest || matches!(first, Some("docs" | "logs"))
}
