//! Who in this crate may build a parser, and what a bound session may do.
//!
//! A submodule of `tests/enclosing_unit.rs`, reached through a `#[path]`
//! attribute. It reads the crate's own tracked source rather than its behavior,
//! because "this analysis parsed the source once" is a claim about ownership: a
//! second parse can produce identical output and still be a second parse.
//!
//! Needs `rust` for the parser it scans with and `_ts` for the session it scans
//! about, so it compiles in the all-features configuration the plan proof
//! names.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

// ---------------------------------------------------------------------------
// The production module universe
// ---------------------------------------------------------------------------

/// Every production source `lib.rs` owns, written out rather than derived.
///
/// [`discover_closure`] finds the same set independently by resolving `mod`
/// declarations, and the two must agree, so a new or moved module fails here
/// instead of arriving unscanned.
const MODULE_INVENTORY: &[&str] = &[
    "classify.rs",
    "extract/dispatch.rs",
    "extract/index.rs",
    "extract/mod.rs",
    "extract/rust.rs",
    "extract/select.rs",
    "extract/ts.rs",
    "language.rs",
    "lib.rs",
    "location.rs",
    "span.rs",
    "tree_sitter/mod.rs",
    "tree_sitter/parser.rs",
    "tree_sitter/session.rs",
    "tree_sitter/traversal.rs",
    "unit.rs",
];

/// The sole parser owner.
const PARSER_MODULE: &str = "tree_sitter/parser.rs";

/// The sole session owner.
const SESSION_MODULE: &str = "tree_sitter/session.rs";

/// The tree-sitter parser type. Only [`PARSER_MODULE`] may name it.
const PARSER_TYPE: &str = "Parser";

/// The shared declaration recognizer a session delegates to.
const RECOGNIZER: &str = "offer_declarations";

/// The shared checked source index, reached through its selector.
const SELECTOR: &str = "UnitSelector";

/// The session method that answers a declaration question.
const ANCHOR_METHOD: &str = "enclosing_unit_anchor";

/// The two parse entry points a session must not call.
const PARSE_ROUTES: &[&str] = &["parse", "parse_bound"];

/// 4.T2 (Invariants 9 and 17): the production module universe is exactly the
/// hand-written inventory, one module constructs the parser, and the session
/// owner parses nothing and delegates to the shared recognizer and index.
#[test]
fn parsed_syntax_attribution_owner_inventory_is_exact() {
    let discovered = discover_closure();
    assert!(
        !discovered.is_empty(),
        "the production module universe must not be empty"
    );
    let relative: Box<[&str]> = discovered.iter().map(|member| &*member.label).collect();
    assert_eq!(
        &*relative, MODULE_INVENTORY,
        "the discovered module universe must equal the hand-written inventory"
    );

    assert_parser_is_owned_once(&discovered);
    assert_session_parses_nothing(&discovered);
    assert_session_delegates_once(&discovered);
}

/// One module builds parsers, and it builds exactly one.
fn assert_parser_is_owned_once(closure: &[Member]) {
    let naming: Box<[&str]> = closure
        .iter()
        .filter(|member| member.scan.names(PARSER_TYPE))
        .map(|member| member.label.as_ref())
        .collect();
    assert_eq!(
        &*naming,
        &[PARSER_MODULE],
        "only {PARSER_MODULE} may name `{PARSER_TYPE}`"
    );
    assert_eq!(
        member(closure, PARSER_MODULE)
            .scan
            .constructions(PARSER_TYPE),
        1,
        "{PARSER_MODULE} must hold exactly one `{PARSER_TYPE}::new` call"
    );
}

/// The session owner constructs no parser and calls no parse entry point.
fn assert_session_parses_nothing(closure: &[Member]) {
    let session = member(closure, SESSION_MODULE);
    assert_eq!(
        session.scan.constructions(PARSER_TYPE),
        0,
        "{SESSION_MODULE} must construct no parser"
    );
    for route in PARSE_ROUTES {
        assert_eq!(
            session.scan.calls(route),
            0,
            "{SESSION_MODULE} must not call `{route}`"
        );
    }
}

/// The session answers through the shared recognizer and the shared index once.
fn assert_session_delegates_once(closure: &[Member]) {
    let file = parse_rust_file(&member(closure, SESSION_MODULE).path);
    let anchor = impl_method(&file, ANCHOR_METHOD)
        .unwrap_or_else(|| panic!("{SESSION_MODULE} should declare `{ANCHOR_METHOD}`"));
    let scan = SourceScan::of_block(&anchor.block);

    assert_eq!(
        scan.calls(RECOGNIZER),
        1,
        "`{ANCHOR_METHOD}` must offer declarations through `{RECOGNIZER}` exactly once"
    );
    assert_eq!(
        scan.constructions(SELECTOR),
        1,
        "`{ANCHOR_METHOD}` must resolve its location through one `{SELECTOR}`"
    );
    assert!(
        scan.reads("tree"),
        "`{ANCHOR_METHOD}` must answer from the bound tree"
    );
    assert!(
        scan.reads("source"),
        "`{ANCHOR_METHOD}` must index the bound source"
    );
}

// ---------------------------------------------------------------------------
// 4.T7: parser failure propagates as absence
// ---------------------------------------------------------------------------

/// Ways a body could invent a tree instead of reporting absence.
const FALLBACK_ROUTES: &[&str] = &[
    "unwrap",
    "unwrap_or",
    "unwrap_or_else",
    "unwrap_or_default",
    "expect",
    "default",
];

/// 4.T7 (Invariant 10): `parse_bound` reports `Parser::parse` absence as `None`
/// and synthesizes no fallback tree.
///
/// A behavioral claim is not available here: production configures no
/// cancellation flag, timeout, or invalid included range, so nothing can force
/// `Parser::parse` to answer `None` deterministically. The ownership boundary
/// is where the propagation is decided, so it is proven where it is written.
#[test]
fn parse_bound_propagates_parser_failure_as_absence() {
    let parser_source = crate_path("src").join(PARSER_MODULE);
    let file = parse_rust_file(&parser_source);

    let bound = free_function(&file, "parse_bound")
        .unwrap_or_else(|| panic!("{PARSER_MODULE} should declare `parse_bound`"));
    let bound_scan = SourceScan::of_block(&bound.block);
    assert_eq!(
        bound_scan.calls("parse"),
        1,
        "`parse_bound` must take the one parse route exactly once"
    );
    assert_eq!(
        bound_scan.try_expressions, 1,
        "`parse_bound` must propagate that route's absence with `?`"
    );
    assert_no_fallback(&bound_scan, "parse_bound");

    let parse = free_function(&file, "parse")
        .unwrap_or_else(|| panic!("{PARSER_MODULE} should declare `parse`"));
    let parse_scan = SourceScan::of_block(&parse.block);
    assert_eq!(
        parse_scan.method_calls("parse"),
        1,
        "`parse` must call `Parser::parse` exactly once"
    );
    assert_no_fallback(&parse_scan, "parse");
}

/// No body on the absence path may invent a value in place of `None`.
fn assert_no_fallback(scan: &SourceScan, label: &str) {
    for route in FALLBACK_ROUTES {
        assert_eq!(
            scan.method_calls(route) + scan.calls(route),
            0,
            "`{label}` must not reach for `{route}` in place of absence"
        );
    }
}

// ---------------------------------------------------------------------------
// Module discovery
// ---------------------------------------------------------------------------

/// One discovered production source: where it lives, what it is called, and
/// what it names.
struct Member {
    path: PathBuf,
    label: Box<str>,
    scan: SourceScan,
}

impl Member {
    fn new(path: PathBuf) -> Self {
        let scan = SourceScan::of_file(&parse_rust_file(&path));
        let label = relative_to_source(&path).into_boxed_str();
        Self { path, label, scan }
    }
}

/// The member with one label, or a failure naming it.
fn member<'closure>(closure: &'closure [Member], label: &str) -> &'closure Member {
    closure
        .iter()
        .find(|member| &*member.label == label)
        .unwrap_or_else(|| panic!("{label} should be part of the discovered closure"))
}

/// Every production source `lib.rs` reaches, by resolving `mod` declarations.
///
/// A declaration that names no file is a refusal, not a skip: an unresolved
/// module would silently drop whatever it holds out of every scan below.
fn discover_closure() -> Box<[Member]> {
    let mut discovered: Vec<PathBuf> = Vec::new();
    let mut pending = vec![crate_path("src").join("lib.rs")];
    while let Some(path) = pending.pop() {
        if discovered.contains(&path) {
            continue;
        }
        for name in declared_modules(&path).iter() {
            let child = resolve_module(&path, name)
                .unwrap_or_else(|| panic!("`mod {name};` in {} names no file", path.display()));
            pending.push(child);
        }
        discovered.push(path);
    }
    discovered.sort();
    discovered.into_iter().map(Member::new).collect()
}

/// The names of every non-inline `mod` declaration in one source.
fn declared_modules(path: &Path) -> Box<[Box<str>]> {
    parse_rust_file(path)
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(declaration) if declaration.content.is_none() => {
                Some(declaration.ident.to_string().into_boxed_str())
            }
            _ => None,
        })
        .collect()
}

/// The file a `mod name;` declaration inside `owner` selects.
fn resolve_module(owner: &Path, name: &str) -> Option<PathBuf> {
    let directory = match owner.file_name().and_then(|name| name.to_str()) {
        Some("lib.rs" | "mod.rs") => owner.parent()?.to_path_buf(),
        _ => owner.with_extension(""),
    };
    let flat = directory.join(format!("{name}.rs"));
    let nested = directory.join(name).join("mod.rs");
    match (flat.is_file(), nested.is_file()) {
        (true, _) => Some(flat),
        (_, true) => Some(nested),
        _ => None,
    }
}

/// This crate's own directory, joined with `part`.
fn crate_path(part: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(part)
}

fn parse_rust_file(path: &Path) -> syn::File {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} should be readable: {error}", path.display()));
    syn::parse_file(&source)
        .unwrap_or_else(|error| panic!("{} should parse: {error}", path.display()))
}

fn relative_to_source(path: &Path) -> String {
    path.strip_prefix(crate_path("src"))
        .unwrap_or_else(|_| panic!("{} should sit under src/", path.display()))
        .to_string_lossy()
        .replace('\\', "/")
}

// ---------------------------------------------------------------------------
// Source scanning
// ---------------------------------------------------------------------------

/// What one parsed source names: identifiers, calls, method calls, field reads,
/// and `?` propagations.
///
/// One walk answers every question the claims above ask, so a subject is parsed
/// once rather than once per question.
#[derive(Default)]
struct SourceScan {
    idents: BTreeMap<Box<str>, usize>,
    calls: BTreeMap<Box<str>, usize>,
    method_calls: BTreeMap<Box<str>, usize>,
    constructions: BTreeMap<Box<str>, usize>,
    fields: BTreeMap<Box<str>, usize>,
    try_expressions: usize,
}

impl SourceScan {
    fn of_file(file: &syn::File) -> Self {
        let mut scan = Self::default();
        scan.visit_file(file);
        scan
    }

    fn of_block(block: &syn::Block) -> Self {
        let mut scan = Self::default();
        scan.visit_block(block);
        scan
    }

    fn names(&self, ident: &str) -> bool {
        self.idents.contains_key(ident)
    }

    /// How many call expressions name `function` as their last path segment.
    fn calls(&self, function: &str) -> usize {
        self.calls.get(function).copied().unwrap_or_default()
    }

    /// How many method calls name `method`.
    fn method_calls(&self, method: &str) -> usize {
        self.method_calls.get(method).copied().unwrap_or_default()
    }

    /// How many `Type::new(...)` calls name `type_name`.
    fn constructions(&self, type_name: &str) -> usize {
        self.constructions
            .get(type_name)
            .copied()
            .unwrap_or_default()
    }

    fn reads(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }

    /// Count one path call by its last segment, and the type it constructs when
    /// that segment is `new`.
    fn record_path_call(&mut self, path: &syn::Path) {
        let mut segments = path.segments.iter().rev();
        let Some(last) = segments.next() else {
            return;
        };
        let name = last.ident.to_string();
        *self.calls.entry(name.as_str().into()).or_default() += 1;
        if name == "new"
            && let Some(owner) = segments.next()
        {
            *self
                .constructions
                .entry(owner.ident.to_string().into_boxed_str())
                .or_default() += 1;
        }
    }
}

impl<'ast> Visit<'ast> for SourceScan {
    fn visit_ident(&mut self, node: &'ast proc_macro2::Ident) {
        *self
            .idents
            .entry(node.to_string().into_boxed_str())
            .or_default() += 1;
    }

    fn visit_member(&mut self, node: &'ast syn::Member) {
        if let syn::Member::Named(ident) = node {
            *self
                .fields
                .entry(ident.to_string().into_boxed_str())
                .or_default() += 1;
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(called) = node.func.as_ref() {
            self.record_path_call(&called.path);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        *self
            .method_calls
            .entry(node.method.to_string().into_boxed_str())
            .or_default() += 1;
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.try_expressions += 1;
        syn::visit::visit_expr_try(self, node);
    }
}

/// The free function one file declares under `name`.
fn free_function<'file>(file: &'file syn::File, name: &str) -> Option<&'file syn::ItemFn> {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    })
}

/// The inherent method one file declares under `name`.
fn impl_method<'file>(file: &'file syn::File, name: &str) -> Option<&'file syn::ImplItemFn> {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(block) => Some(block),
            _ => None,
        })
        .flat_map(|block| block.items.iter())
        .find_map(|member| match member {
            syn::ImplItem::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
}
