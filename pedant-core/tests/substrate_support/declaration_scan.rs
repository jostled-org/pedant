//! Helpers that read this crate's own declarations — its manifest, its `lib.rs`
//! module tree, and its test roots — and classify them by the `checks` gate.
//!
//! A submodule of `tests/substrate.rs`, reached through a `#[path]` attribute
//! and not a test root of its own: it holds no `#[test]`, and this directory
//! carries no `main.rs`, so cargo declares no test executable for it. Every test
//! module in `substrate.rs` derives its boundary from [`LibSurface::classify`]
//! here, which is what keeps the substrate-versus-judgment split defined once.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use pedant_core::capabilities::detect_capabilities;
use pedant_core::ir::extract;
use pedant_types::Capability;
use syn::punctuated::Punctuated;
use syn::visit::Visit;

/// The feature that selects pedant-core's judgment surface.
pub(crate) const CHECKS_FEATURE: &str = "checks";

/// The sole exclusion from every scanned parse-only source set, named by path
/// rather than derived. `ir/semantic` compiles in every configuration so
/// `extract` can accept `Option<&SemanticContext>` unconditionally, and
/// `ir/semantic/context.rs` names rust-analyzer's workspace loader, which
/// invokes the toolchain. Those items are `semantic`-gated, but this scanner
/// reads source text and evaluates no `cfg`, so it cannot tell a gated item
/// from a live one. That is also why `semantic` sits outside the claim.
pub(crate) const SEMANTIC_EXCLUSION: &str = "ir/semantic";

/// Absolute form of [`SEMANTIC_EXCLUSION`].
pub(crate) fn excluded_root() -> PathBuf {
    crate_path("src").join(SEMANTIC_EXCLUSION)
}

/// The process-capability evidence one source names, when it names any.
///
/// Both the whole-substrate scan and the narrower Tier 1 scan ask this one
/// question, so the production entry points it asks it through are named once.
pub(crate) fn process_evidence(path: &Path) -> Option<Box<str>> {
    let syntax = parse_rust_file(path);
    let ir = extract(&path.to_string_lossy(), &syntax, None);
    detect_capabilities(&ir, None)
        .findings
        .iter()
        .find(|finding| finding.capability == Capability::ProcessExec)
        .map(|finding| format!("{}: {}", path.display(), finding.evidence).into_boxed_str())
}

/// Prove the semantic exclusion removes something: `ir/semantic/context.rs` is
/// in the unfiltered expansion, so filtering it out is not a no-op.
pub(crate) fn assert_semantic_exclusion_is_not_vacuous() {
    assert!(
        module_files("ir")
            .iter()
            .any(|path| path.ends_with("ir/semantic/context.rs")),
        "the exclusion is not vacuous: context.rs is in the unfiltered expansion"
    );
}

/// Test roots that exercise the substrate only. They must carry no `checks`
/// gate, so they run in every configuration.
pub(crate) const SUBSTRATE_ROOTS: &[&str] = &["hash.rs", "pattern.rs", "substrate.rs"];

/// A path inside this crate, resolved against the manifest directory.
pub(crate) fn crate_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_file(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} should be readable: {error}", path.display()))
}

pub(crate) fn parse_rust_file(path: &Path) -> syn::File {
    syn::parse_file(&read_file(path))
        .unwrap_or_else(|error| panic!("{} should parse as Rust: {error}", path.display()))
}

pub(crate) fn manifest_table() -> toml::Table {
    let text = read_file(&crate_path("Cargo.toml"));
    toml::from_str(&text).expect("pedant-core/Cargo.toml should parse as TOML")
}

pub(crate) fn file_name(path: &Path) -> Box<str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| panic!("{} should have a UTF-8 file name", path.display()))
        .into()
}

fn is_rust_source(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "rs")
}

fn entry_path(entry: std::io::Result<fs::DirEntry>) -> PathBuf {
    entry.expect("directory entry should be readable").path()
}

/// Every top-level `tests/*.rs` root, including `substrate.rs`.
///
/// Top level only, and deliberately: a test root is what cargo builds into a
/// test executable, and cargo builds one per `tests/*.rs`. `tests/fixtures/`
/// holds fixture crates and `tests/substrate_support/` holds this module —
/// neither is a root, and a file-level gate on either would govern nothing. A
/// gate belongs on the root that declares them.
pub(crate) fn test_root_paths() -> Box<[PathBuf]> {
    let entries = fs::read_dir(crate_path("tests")).expect("pedant-core/tests should be readable");
    let mut roots: Vec<PathBuf> = entries
        .map(entry_path)
        .filter(|path| path.is_file() && is_rust_source(path))
        .collect();
    roots.sort();
    roots.into_boxed_slice()
}

/// Every Rust source this crate compiles, sorted — the whole `src/` tree, with
/// no module declaration and no `cfg` consulted.
///
/// A claim about the routes production code takes holds in every configuration,
/// so its subject is every file rather than the modules one feature set leaves
/// live. The parse-route scan is the one caller, and it observes counters only
/// the proof feature installs, so this follows that gate.
#[cfg(feature = "resolution-test-support")]
pub(crate) fn crate_sources() -> Box<[PathBuf]> {
    let mut files = Vec::new();
    collect_rust_files(&crate_path("src"), &mut files);
    files.sort();
    files.into_boxed_slice()
}

/// Files owned by the `lib.rs` module declaration `module`: the flat
/// `src/<module>.rs`, or the whole `src/<module>/` subtree, recursively.
pub(crate) fn module_files(module: &str) -> Box<[PathBuf]> {
    let source_root = crate_path("src");
    let mut files = Vec::new();
    let flat = source_root.join(format!("{module}.rs"));
    if flat.is_file() {
        files.push(flat);
    }
    let directory = source_root.join(module);
    if directory.is_dir() {
        collect_rust_files(&directory, &mut files);
    }
    files.into_boxed_slice()
}

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{} should be readable: {error}", directory.display()));
    for entry in entries {
        let path = entry_path(entry);
        match (path.is_dir(), is_rust_source(&path)) {
            (true, _) => collect_rust_files(&path, files),
            (false, true) => files.push(path),
            (false, false) => {}
        }
    }
}

pub(crate) fn has_checks_gate(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(is_checks_gate)
}

fn is_checks_gate(attr: &syn::Attribute) -> bool {
    match &attr.meta {
        syn::Meta::List(list) if list.path.is_ident("cfg") => list
            .parse_args::<syn::Meta>()
            .is_ok_and(|predicate| is_checks_predicate(&predicate)),
        _ => false,
    }
}

fn is_checks_predicate(predicate: &syn::Meta) -> bool {
    match predicate {
        syn::Meta::NameValue(pair) if pair.path.is_ident("feature") => {
            literal_is(&pair.value, CHECKS_FEATURE)
        }
        _ => false,
    }
}

fn literal_is(expr: &syn::Expr, expected: &str) -> bool {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) => text.value() == expected,
        _ => false,
    }
}

/// Names bound by a `use` tree: leaf names and rename targets, not path stems.
fn use_tree_names(tree: &syn::UseTree, names: &mut BTreeSet<Box<str>>) {
    match tree {
        syn::UseTree::Path(path) => use_tree_names(&path.tree, names),
        syn::UseTree::Name(name) => {
            names.insert(name.ident.to_string().into_boxed_str());
        }
        syn::UseTree::Rename(rename) => {
            names.insert(rename.rename.to_string().into_boxed_str());
        }
        syn::UseTree::Group(group) => group.items.iter().for_each(|it| use_tree_names(it, names)),
        syn::UseTree::Glob(_) => {}
    }
}

/// Every identifier a file names as a path segment or a use-tree entry.
///
/// An AST scan, not a substring scan: a judgment name inside a string literal
/// is not a reference. `tests/pattern.rs` holds the literal
/// `"/Users/jem/repos/project/src/main.rs"`, which a substring scan would read
/// as naming the `project` module.
///
/// Macro bodies are scanned too. `syn`'s visitor stops at a macro's token
/// stream, and test files are dense with macro calls, so a judgment path named
/// only inside `assert_eq!(…)` would otherwise be invisible.
#[derive(Default)]
pub(crate) struct PathIdents {
    idents: BTreeSet<Box<str>>,
}

impl PathIdents {
    pub(crate) fn scan(file: &syn::File) -> Self {
        let mut scan = Self::default();
        scan.visit_file(file);
        scan
    }

    /// Whether the file names any of `candidates` as a path segment or a
    /// use-tree entry. Gated with its one caller, the parse-route scan.
    #[cfg(feature = "resolution-test-support")]
    pub(crate) fn names_any(&self, candidates: &[&str]) -> bool {
        candidates
            .iter()
            .any(|candidate| self.idents.contains(*candidate))
    }

    /// Visit a macro body under the two shapes `syn` can re-parse: a
    /// comma-separated expression list, then a statement list. Trying both
    /// matters — `assert_eq!(a, b)` is only the first and `vec![a; 2]` only the
    /// second, so an expression-list scan alone loses every name a repeat
    /// expression holds. A body that parses as neither shape stays invisible
    /// here, which is why the compiler, not this test, is the authoritative
    /// enforcement of the gate.
    fn visit_macro_body(&mut self, node: &syn::Macro) {
        if let Ok(arguments) =
            node.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated)
        {
            arguments.iter().for_each(|it| self.visit_expr(it));
            return;
        }
        if let Ok(statements) = node.parse_body_with(syn::Block::parse_within) {
            statements.iter().for_each(|it| self.visit_stmt(it));
        }
    }
}

impl<'ast> Visit<'ast> for PathIdents {
    fn visit_path(&mut self, node: &'ast syn::Path) {
        let segments = node.segments.iter();
        self.idents
            .extend(segments.map(|it| it.ident.to_string().into_boxed_str()));
        syn::visit::visit_path(self, node);
    }

    fn visit_use_path(&mut self, node: &'ast syn::UsePath) {
        self.idents.insert(node.ident.to_string().into_boxed_str());
        syn::visit::visit_use_path(self, node);
    }

    fn visit_use_name(&mut self, node: &'ast syn::UseName) {
        self.idents.insert(node.ident.to_string().into_boxed_str());
    }

    fn visit_use_rename(&mut self, node: &'ast syn::UseRename) {
        self.idents.insert(node.ident.to_string().into_boxed_str());
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.visit_macro_body(node);
        syn::visit::visit_macro(self, node);
    }
}

/// `pedant-core/src/lib.rs`'s root declarations, split by the `checks` gate.
///
/// Both halves are derived from the file rather than hand-listed, so a module
/// that crosses the gate moves here without any test edit.
pub(crate) struct LibSurface {
    /// Module names declared without the gate — the substrate module set.
    pub(crate) ungated_modules: Box<[Box<str>]>,
    /// Gated module names, plus every name bound by a gated `pub use`.
    pub(crate) judgment_names: BTreeSet<Box<str>>,
}

impl LibSurface {
    pub(crate) fn classify() -> Self {
        let lib = parse_rust_file(&crate_path("src").join("lib.rs"));
        let mut ungated_modules = Vec::new();
        let mut judgment_names = BTreeSet::new();
        for item in &lib.items {
            match item {
                syn::Item::Mod(declaration) => {
                    classify_module(declaration, &mut ungated_modules, &mut judgment_names);
                }
                syn::Item::Use(reexport) => classify_reexport(reexport, &mut judgment_names),
                _ => {}
            }
        }
        Self {
            ungated_modules: ungated_modules.into_boxed_slice(),
            judgment_names,
        }
    }

    /// Judgment names that `scan` references.
    pub(crate) fn judgment_references(&self, scan: &PathIdents) -> Box<[Box<str>]> {
        self.judgment_names
            .intersection(&scan.idents)
            .cloned()
            .collect()
    }
}

fn classify_module(
    declaration: &syn::ItemMod,
    ungated_modules: &mut Vec<Box<str>>,
    judgment_names: &mut BTreeSet<Box<str>>,
) {
    let name = declaration.ident.to_string().into_boxed_str();
    match has_checks_gate(&declaration.attrs) {
        true => {
            judgment_names.insert(name);
        }
        false => ungated_modules.push(name),
    }
}

fn classify_reexport(reexport: &syn::ItemUse, judgment_names: &mut BTreeSet<Box<str>>) {
    if has_checks_gate(&reexport.attrs) {
        use_tree_names(&reexport.tree, judgment_names);
    }
}
