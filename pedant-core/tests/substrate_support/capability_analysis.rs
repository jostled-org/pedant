//! Rust symbol capability analysis on the substrate, and the exact ownership
//! of the attribution closure that produces it.
//!
//! A submodule of `tests/substrate.rs`, reached through a `#[path]` attribute
//! and not a test root of its own: it carries the substrate's own claims, so it
//! runs under `--no-default-features` as well as under the default set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use pedant_core::capabilities::detect_capabilities;
use pedant_core::ir::extract;
use pedant_types::{Capability, CapabilitySymbolKind, Language, SymbolAttributionStatus};
use syn::visit::Visit;

use crate::declaration_scan::{PathIdents, crate_path, parse_rust_file};

// ---------------------------------------------------------------------------
// 3.T6: the substrate answers the symbol question with no judgment code
// ---------------------------------------------------------------------------

const SUBSTRATE_FILE: &str = "substrate_symbols.rs";

/// One module import, one attributed import, one nested callable, and one
/// callable that owns nothing.
const SUBSTRATE_SOURCE: &str = r#"use std::process::Command;

pub fn download() {
    use std::net::TcpStream;
    fn retry() {
        let _ = "https://retry.test/again";
    }
}

pub fn idle() {}
"#;

/// 3.T6 (Invariant 15): the no-default substrate exposes complete Rust symbol
/// capability analysis, through the public `extract` plus `detect_capabilities`
/// pair and no configuration, violation, or gate type.
#[test]
fn rust_symbol_capability_analysis_runs_without_judgment() {
    let syntax = syn::parse_file(SUBSTRATE_SOURCE).expect("the fixture source should parse");
    let ir = extract(SUBSTRATE_FILE, &syntax, None);
    let analysis = detect_capabilities(&ir, None);

    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Complete,
        "the supplied IR states a complete callable inventory"
    );

    let flat: Vec<(Capability, &str, usize)> = analysis
        .profile
        .findings
        .iter()
        .map(|finding| {
            (
                finding.capability,
                &*finding.evidence,
                finding.location.line,
            )
        })
        .collect();
    assert_eq!(
        flat,
        [
            (Capability::ProcessExec, "std::process::Command", 1),
            (Capability::Network, "std::net::TcpStream", 4),
            (Capability::Network, "https://retry.test/again", 6),
        ],
        "the flat profile keeps every occurrence in detection order"
    );

    let symbols: Vec<(&str, CapabilitySymbolKind, usize, usize, Vec<&str>)> = analysis
        .symbols
        .iter()
        .map(|entry| {
            (
                &*entry.symbol.name,
                entry.symbol.kind,
                entry.symbol.declaration.line,
                entry.symbol.declaration.column,
                entry
                    .profile
                    .findings
                    .iter()
                    .map(|finding| &*finding.evidence)
                    .collect(),
            )
        })
        .collect();
    assert_eq!(
        symbols,
        [
            (
                "download",
                CapabilitySymbolKind::Function,
                3,
                8,
                vec!["std::net::TcpStream"],
            ),
            (
                "retry",
                CapabilitySymbolKind::Function,
                5,
                8,
                vec!["https://retry.test/again"],
            ),
        ],
        "the module import stays flat, the nested callable owns its own literal, \
         and a callable with no evidence owns no profile"
    );
    assert!(
        analysis
            .symbols
            .iter()
            .all(|entry| entry.symbol.language == Language::Rust)
    );
}

// ---------------------------------------------------------------------------
// 3.T7: the attribution closure's exact ownership
// ---------------------------------------------------------------------------

/// The module declaration this closure starts at, inside `capabilities/mod.rs`.
const ATTRIBUTION_MODULE: &str = "attribution";

/// The complete attribution closure, written out rather than derived. The scan
/// below discovers the same set independently and the two must agree, so a new
/// or moved member fails here instead of slipping in unproven.
const ATTRIBUTION_INVENTORY: &[&str] = &[
    "capabilities/attribution/draft.rs",
    "capabilities/attribution/mod.rs",
    "capabilities/attribution/projection.rs",
    "capabilities/attribution/source.rs",
];

/// The five Rust capability-source fact families that stamp a callable owner.
const STAMPED_FACTS: &[&str] = &[
    "AttributeFact",
    "ExternBlockFact",
    "StringLitFact",
    "UnsafeFact",
    "UsePathFact",
];

/// The trait through which the closure reads a stamped owner.
const OWNER_TRAIT: &str = "CapabilitySourceFact";

/// The stamped field itself.
const OWNER_FIELD: &str = "containing_fn";

/// The projection entry point `detect_capabilities` must enter exactly once.
const PROJECTION_ENTRY: &str = "project_analysis";

/// Routes the attribution closure must not name. Attribution reads facts that
/// already exist; anything here would mean it re-derived one.
const FORBIDDEN_ROUTES: &[&str] = &[
    // parser
    "parse_file",
    "parse_str",
    "parse2",
    "parse_bound",
    "Parser",
    "tree_sitter",
    // file read
    "fs",
    "File",
    "read_to_string",
    "read_dir",
    // project model
    "project",
    "project_shape",
    "RustProject",
    // process
    "Command",
    "process",
    // semantic
    "semantic",
    "SemanticContext",
    "check_reachability_batch",
    "enrich_reachability",
    // judgment
    "lint",
    "checks",
    "check_style",
    "CheckConfig",
    "Violation",
    "GateConfig",
];

/// 3.T7 (Invariant 17): the attribution closure is exactly the hand-written
/// inventory, reads all five stamped fact fields, is entered once, and reaches
/// no parser, file, project, process, semantic, or judgment route.
///
/// IR extraction and semantic reachability are explicit predecessors outside
/// this closure. 3.T4 proves one parse and one extraction; 3.T8 and 3.T9 prove
/// the existing semantic stage.
#[test]
fn rust_symbol_attribution_owner_inventory_is_exact() {
    let discovered = discover_closure();
    assert!(
        !discovered.is_empty(),
        "the attribution closure must not be empty"
    );
    let relative: Box<[String]> = discovered
        .iter()
        .map(|(path, _)| relative_to_source(path))
        .collect();
    assert_eq!(
        &*relative, ATTRIBUTION_INVENTORY,
        "the discovered attribution closure must equal the hand-written inventory"
    );

    assert_owner_reads_are_complete(&discovered);
    assert_projection_is_entered_once();
    assert_no_forbidden_route(&discovered);
}

/// Every source the `attribution` declaration owns, discovered by resolving
/// module declarations and refusing any that names no file. Each member is
/// returned as its path beside its single parse, so every assertion below reads
/// one parse per member rather than parsing the closure again per question.
///
/// Deliberately not `declaration_scan::module_files`, which expands a directory:
/// this walk follows the `mod` declarations themselves, so a submodule that a
/// `#[path]` attribute relocates outside `capabilities/attribution/` still
/// counts as a member, and a stray file inside that directory that no
/// declaration names does not.
fn discover_closure() -> Box<[(PathBuf, syn::File)]> {
    let capabilities = crate_path("src").join("capabilities");
    let root = resolve_module(&capabilities.join("mod.rs"), ATTRIBUTION_MODULE)
        .unwrap_or_else(|| panic!("`mod {ATTRIBUTION_MODULE};` should name a file"));

    let mut discovered: Vec<(PathBuf, syn::File)> = Vec::new();
    let mut pending = vec![root];
    while let Some(path) = pending.pop() {
        if discovered.iter().any(|(member, _)| *member == path) {
            continue;
        }
        let syntax = parse_rust_file(&path);
        for name in declared_modules(&syntax).iter() {
            let child = resolve_module(&path, name)
                .unwrap_or_else(|| panic!("`mod {name};` in {} names no file", path.display()));
            pending.push(child);
        }
        discovered.push((path, syntax));
    }
    discovered.sort_by(|(left, _), (right, _)| left.cmp(right));
    discovered.into_boxed_slice()
}

/// The names of every non-inline `mod` declaration in one parsed source.
///
/// An inline `mod` body is already part of this file, so it adds no member; a
/// declaration that names another file must resolve or the scan refuses.
fn declared_modules(file: &syn::File) -> Box<[Box<str>]> {
    file.items
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
    let directory = owner.parent()?;
    let flat = directory.join(format!("{name}.rs"));
    let nested = directory.join(name).join("mod.rs");
    match (flat.is_file(), nested.is_file()) {
        (true, _) => Some(flat),
        (_, true) => Some(nested),
        _ => None,
    }
}

fn relative_to_source(path: &Path) -> String {
    path.strip_prefix(crate_path("src"))
        .unwrap_or_else(|_| panic!("{} should sit under src/", path.display()))
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every fact family must read its stamped owner inside this closure.
fn assert_owner_reads_are_complete(closure: &[(PathBuf, syn::File)]) {
    let mut implemented: BTreeSet<Box<str>> = BTreeSet::new();
    for (_, syntax) in closure {
        for item in &syntax.items {
            let syn::Item::Impl(block) = item else {
                continue;
            };
            let Some(named) = implemented_owner(block) else {
                continue;
            };
            let scan = SourceScan::of_impl(block);
            assert!(
                scan.reads(OWNER_FIELD),
                "the {OWNER_TRAIT} implementation for {named} must read `{OWNER_FIELD}`"
            );
            implemented.insert(named);
        }
    }
    assert_eq!(
        implemented,
        STAMPED_FACTS
            .iter()
            .map(|name| Box::from(*name))
            .collect::<BTreeSet<Box<str>>>(),
        "the closure must consume the stamped owner of every capability-source fact family"
    );
}

/// The fact type one `impl CapabilitySourceFact for …` block names.
fn implemented_owner(block: &syn::ItemImpl) -> Option<Box<str>> {
    let (_, path, _) = block.trait_.as_ref()?;
    let named = path.segments.last()?;
    if named.ident != OWNER_TRAIT {
        return None;
    }
    let syn::Type::Path(self_type) = block.self_ty.as_ref() else {
        return None;
    };
    Some(
        self_type
            .path
            .segments
            .last()?
            .ident
            .to_string()
            .into_boxed_str(),
    )
}

/// `detect_capabilities` is the one production route into the projection, and
/// it takes it once.
fn assert_projection_is_entered_once() {
    let detection = crate_path("src").join("capabilities").join("detection.rs");
    let file = parse_rust_file(&detection);
    assert_eq!(
        SourceScan::of_file(&file).calls(PROJECTION_ENTRY),
        1,
        "detection.rs must hold exactly one call to `{PROJECTION_ENTRY}`"
    );

    let entry = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "detect_capabilities" => {
                Some(function)
            }
            _ => None,
        })
        .expect("detection.rs should declare `detect_capabilities`");
    assert_eq!(
        SourceScan::of_block(&entry.block).calls(PROJECTION_ENTRY),
        1,
        "`detect_capabilities` must enter the projection exactly once"
    );
}

/// A source that does take a forbidden route, so the matcher below is shown to
/// fire before it is asked to stay silent.
const FORBIDDEN_ROUTE_CONTROL: &str = "ir/extract/parse.rs";

fn assert_no_forbidden_route(closure: &[(PathBuf, syn::File)]) {
    let control = parse_rust_file(&crate_path("src").join(FORBIDDEN_ROUTE_CONTROL));
    assert!(
        !PathIdents::scan(&control)
            .names_among(FORBIDDEN_ROUTES)
            .is_empty(),
        "the route matcher is not vacuous: {FORBIDDEN_ROUTE_CONTROL} names a parser route"
    );

    let offenders: Box<[Box<str>]> = closure
        .iter()
        .flat_map(|(path, syntax)| {
            let named = PathIdents::scan(syntax).names_among(FORBIDDEN_ROUTES);
            let label = relative_to_source(path);
            named
                .into_iter()
                .map(move |route| format!("{label}: {route}").into_boxed_str())
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "the attribution closure names a parser, file, project, process, semantic, \
         or judgment route: {offenders:?}"
    );
}

/// What one parsed source names: the fields it reads and the functions it calls.
///
/// One scan answers both questions the ownership claim asks, so the closure is
/// parsed once per subject rather than once per question.
#[derive(Default)]
struct SourceScan {
    fields: BTreeSet<Box<str>>,
    calls: BTreeMap<Box<str>, usize>,
}

impl SourceScan {
    fn of_impl(block: &syn::ItemImpl) -> Self {
        let mut scan = Self::default();
        scan.visit_item_impl(block);
        scan
    }

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

    fn reads(&self, field: &str) -> bool {
        self.fields.contains(field)
    }

    /// How many call expressions name `function`. An import states a route, not
    /// an entry, so only a call counts.
    fn calls(&self, function: &str) -> usize {
        self.calls.get(function).copied().unwrap_or_default()
    }
}

impl<'ast> Visit<'ast> for SourceScan {
    fn visit_member(&mut self, node: &'ast syn::Member) {
        if let syn::Member::Named(ident) = node {
            self.fields.insert(ident.to_string().into_boxed_str());
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(called) = called_function(node) {
            *self.calls.entry(called).or_default() += 1;
        }
        syn::visit::visit_expr_call(self, node);
    }
}

/// The last path segment of a call's callee, when the callee is a plain path.
fn called_function(node: &syn::ExprCall) -> Option<Box<str>> {
    let syn::Expr::Path(called) = node.func.as_ref() else {
        return None;
    };
    let segment = called.path.segments.last()?;
    Some(segment.ident.to_string().into_boxed_str())
}
