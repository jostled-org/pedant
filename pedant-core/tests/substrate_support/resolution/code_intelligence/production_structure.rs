//! 10.T5 (Invariant 14): how the completed product is written, read from the
//! completed source.
//!
//! Every claim here is one a green build and a green behavioural suite are
//! consistent with. A second implementation of `search_symbols` answers the same
//! question until one of the two is fixed; a ceiling declared twice hashes into
//! one revision and is enforced by neither; a body that retains before it checks
//! refuses correctly on every input small enough to test. The tree is where all
//! three are visible.
//!
//! Qualitative single-responsibility judgement is not made here. It is a Step 10
//! proof-review question, because "one job" is a sentence about intent and what
//! a parser can answer is how deep a body nests and whether two bodies are the
//! same body.
//!
//! What the named owners are written *as* — duplication, nesting depth, and
//! refusal ordering — is [`super::production_bodies`], split off for the
//! source-file budget alone. It is driven from the case below, so both halves
//! read the one surface this case reads.

use crate::resolution::code_intelligence::error_model::ERROR_FAMILIES;
use crate::resolution::code_intelligence::graph_model::GRAPH_DELEGATIONS;
use crate::resolution::code_intelligence::limit_model::{
    BOUNDED_FAMILIES, CAPACITY_OWNER, CEILING_REGISTRY,
};
use crate::resolution::code_intelligence::operation_model::{
    DISPATCH_MODULE, OPERATIONS, STATE_MODULE, TRANSPORT_MODULES,
};
use crate::resolution::code_intelligence::product_model::{MODULE_ROOTS, REGISTRY_MODULES};
use crate::resolution::code_intelligence::product_surface::{
    ProductModule, ProductSurface, compact_tokens, declarations_of, occurrences, states,
};
use crate::resolution::code_intelligence::production_bodies::{
    assert_every_ceiling_is_checked_before_retention,
    assert_no_body_is_written_twice_or_nested_past_two_layers, product_bodies,
};
use crate::resolution::error_enums::error_enums;

/// The registry modules that answer no operation.
///
/// The listing, the argument decoding, and the schema shared by every row. Every
/// other module of that tree is one served tool, and which tools those are is
/// [`OPERATIONS`]' answer rather than a second list beside it.
const REGISTRY_SUPPORT_MODULES: [&str; 4] = ["entries.rs", "mod.rs", "params.rs", "schema.rs"];

/// 10.T5 (Invariant 14): one named module per error, limit, and counter family;
/// one registry module per operation; one implementation of every public
/// operation; transports that call into it; export-only module roots; no body
/// written twice; no body nested past two layers; no graph algorithm implemented
/// here; and every ceiling checked before the first excess is retained.
#[test]
fn code_intelligence_production_structure_error_and_limit_ownership_are_exact() {
    let surface = ProductSurface::read();
    assert!(
        surface.modules().len() > OPERATIONS.len() + ERROR_FAMILIES.len(),
        "the product must be wider than the families it is claimed by"
    );
    let bodies = product_bodies(surface.modules());
    assert_each_error_family_has_one_named_owner(surface.modules());
    assert_each_bounded_family_has_one_named_owner(&surface);
    assert_the_registry_states_one_module_per_operation();
    assert_every_operation_has_one_implementation(&surface);
    assert_documentation_answers_no_delegation();
    assert_both_transports_call_into_the_dispatcher(&surface);
    assert_module_roots_export_and_nothing_else(&surface);
    assert_no_body_is_written_twice_or_nested_past_two_layers(&bodies);
    assert_every_graph_answer_delegates(&surface);
    assert_missing_graph_nodes_are_refused(&surface);
    assert_every_ceiling_is_checked_before_retention(&bodies);
}

/// A graph identity with no graph record is refused, never rendered as evidence.
///
/// The public graph API mints only valid dense identities, so repository input
/// cannot manufacture this branch. Its source shape is the observable contract:
/// the branch must construct the existing typed graph error and must not build a
/// `GraphEntity` with invented file kind, empty name, or absent location.
fn assert_missing_graph_nodes_are_refused(surface: &ProductSurface) {
    let entity = compact_tokens(surface.module("pedant-snippet/src/navigation/graph/entity.rs"));
    assert!(
        entity.contains("None=>Err(CodeIntelligenceError::Graph{"),
        "an internal graph identity with no record must return the typed graph error"
    );
    assert!(
        !entity.contains("None=>GraphEntity{") && !entity.contains("name:Box::from(\"\")"),
        "an unknown graph identity must not fabricate an empty graph entity"
    );
}

/// A module that only documents a call does not satisfy either delegation
/// search.
///
/// Both searches below read a rendered token stream, and `syn` renders every
/// `///` and `//!` as a `#[doc = "..."]` attribute. Without the strip
/// [`compact_tokens`] applies, a graph module could stop calling the entry
/// point it projects — and a transport could start calling the operation it
/// must not — while the sentence written above the function answered for it.
fn assert_documentation_answers_no_delegation() {
    let documented = ProductModule::of_text(
        "documented.rs",
        "//! answers state.list_projects( for its caller\n\
         /// and reaches .neighbors( to do it\n\
         fn answer() {}\n",
    );
    let rendered = compact_tokens(&documented);
    for prose in ["state.list_projects(", ".neighbors("] {
        assert!(
            !rendered.contains(prose),
            "a doc comment stating {prose} must not answer a delegation claim: {rendered}"
        );
    }
    assert!(
        rendered.contains("fnanswer()"),
        "the strip must leave the code the module states: {rendered}"
    );
}

/// The product declares exactly the modelled error enums, each in its module,
/// each with the reach its seam needs and no untyped variant.
fn assert_each_error_family_has_one_named_owner(modules: &[ProductModule]) {
    let mut found: Vec<String> = Vec::new();
    for module in modules {
        for declared in error_enums(&module.parsed).iter() {
            found.push(format!("{}:{}", module.path, declared.name));
            let family = ERROR_FAMILIES
                .iter()
                .find(|family| family.name == &*declared.name)
                .unwrap_or_else(|| panic!("{} is an unmodelled error enum", declared.name));
            assert_eq!(
                family.module, &*module.path,
                "{} must be declared by its modelled owner",
                declared.name
            );
            assert_eq!(
                family.published, declared.published,
                "{} must leave its crate exactly as its seam requires",
                declared.name
            );
            assert!(
                declared.derives_thiserror,
                "{} must derive thiserror::Error, so every caller reads one cause chain",
                declared.name
            );
            assert!(
                !declared.variants.is_empty(),
                "{} states no variant, so the seam it belongs to can refuse nothing",
                declared.name
            );
            assert!(
                declared.untyped_variants.is_empty(),
                "{} states untyped variants: {:?}",
                declared.name,
                declared.untyped_variants
            );
        }
    }
    let mut modelled: Vec<String> = ERROR_FAMILIES
        .iter()
        .map(|family| format!("{}:{}", family.module, family.name))
        .collect();
    found.sort();
    modelled.sort();
    assert_eq!(
        found.into_boxed_slice(),
        modelled.into_boxed_slice(),
        "the product publishes exactly the modelled error families"
    );
}

/// Every ceiling, ceiling registry, and counter type is declared exactly once,
/// by the module modelled to own it.
fn assert_each_bounded_family_has_one_named_owner(surface: &ProductSurface) {
    assert!(
        !BOUNDED_FAMILIES.is_empty(),
        "a single-owner claim over no bounded family constrains nothing"
    );
    let mut offenders: Vec<String> = Vec::new();
    for family in BOUNDED_FAMILIES {
        let owner = surface.module(family.module);
        assert_eq!(
            declarations_of(owner, family.name),
            1,
            "{} must declare {} exactly once",
            family.module,
            family.name
        );
        offenders.extend(surface.others_declaring(&[family.module], family.name));
    }
    assert!(
        offenders.is_empty(),
        "every ceiling and counter is projected once to its named owner: {offenders:?}"
    );

    // Both spellings are asked of the code and not of the page. A registry that
    // dropped its only `stated_ceilings` declaration went on answering with the
    // sentence written above it, which is the exact failure
    // `assert_documentation_answers_no_delegation` forbids; and a module that
    // merely named the minting helper in prose read as a second minter.
    let registry = surface.module(CEILING_REGISTRY);
    assert!(
        states(registry, "stated_ceilings"),
        "{CEILING_REGISTRY} must state the ceiling registry every revision hashes"
    );
    let minters: Box<[&str]> = surface
        .modules()
        .iter()
        .filter(|module| states(module, "pub(crate) fn capacity("))
        .map(|module| &*module.path)
        .collect();
    assert_eq!(
        &*minters,
        &[CAPACITY_OWNER],
        "one module mints every capacity refusal"
    );
}

/// Each of the eight operations is declared once on the published state and
/// answered by exactly one module.
fn assert_every_operation_has_one_implementation(surface: &ProductSurface) {
    let state = surface.module(STATE_MODULE);
    let mut offenders: Vec<String> = Vec::new();
    for operation in OPERATIONS {
        assert_eq!(
            occurrences(state, &format!("pub fn {}(", operation.method)),
            1,
            "{STATE_MODULE} must declare {} exactly once",
            operation.method
        );
        let answering = surface.module(operation.module);
        assert_eq!(
            occurrences(answering, &format!("pub(crate) fn {}(", operation.answerer)),
            1,
            "{} must declare {} exactly once",
            operation.module,
            operation.answerer
        );
        let implementation = format!("fn {}(", operation.answerer);
        offenders.extend(surface.others_stating(
            &[operation.module],
            "also implements",
            &[implementation.as_str()],
        ));
    }
    assert!(
        offenders.is_empty(),
        "one public operation belongs to one implementation: {offenders:?}"
    );
}

/// The registry states one module per served operation, and nothing else beyond
/// the listing, the decoding, and the schema.
///
/// The eight per-tool names are derived from [`OPERATIONS`] rather than written
/// again. Hand-copied they were a second spelling of the same eight rows, and a
/// renamed operation would have left the module list naming a tool the product
/// no longer serves — the exact drift this file's sibling registry claim already
/// removed once.
fn assert_the_registry_states_one_module_per_operation() {
    let per_tool = OPERATIONS
        .iter()
        .map(|operation| format!("{}.rs", operation.method));
    let mut modelled: Vec<String> = REGISTRY_SUPPORT_MODULES
        .iter()
        .map(|module| (*module).to_owned())
        .chain(per_tool)
        .collect();
    let mut stated: Vec<String> = REGISTRY_MODULES
        .iter()
        .map(|module| (*module).to_owned())
        .collect();
    modelled.sort_unstable();
    stated.sort_unstable();
    assert_eq!(
        stated, modelled,
        "the registry tree states one module per operation, plus the listing, the decoding, \
         and the schema"
    );
}

/// Both transports reach the library through the one dispatcher.
fn assert_both_transports_call_into_the_dispatcher(surface: &ProductSurface) {
    let dispatch = compact_tokens(surface.module(DISPATCH_MODULE));
    let transports: Box<[(&str, Box<str>)]> = TRANSPORT_MODULES
        .iter()
        .map(|module| (*module, compact_tokens(surface.module(module))))
        .collect();
    // The negative half below reads only for offenders, so an emptied transport
    // list satisfies it having entered no module at all — while the positive
    // half beside it goes on passing over the dispatcher alone.
    assert!(
        !transports.is_empty(),
        "a claim that no transport asks the library directly must read a transport"
    );
    let mut offenders: Vec<String> = Vec::new();
    for operation in OPERATIONS {
        let call = format!("state.{}(", operation.method);
        assert!(
            dispatch.contains(&call),
            "{DISPATCH_MODULE} must answer {} through the library operation",
            operation.method
        );
        offenders.extend(
            transports
                .iter()
                .filter(|(_, rendered)| rendered.contains(&call))
                .map(|(module, _)| format!("{module} calls {call} itself")),
        );
    }
    assert!(
        offenders.is_empty(),
        "a transport states a question and serializes the answer; it asks through the \
         dispatcher: {offenders:?}"
    );
}

/// Every module root declares modules and re-exports, and holds no body of its
/// own.
///
/// Both floors are the ones every sibling claim here carries. An emptied
/// [`MODULE_ROOTS`] skips the loop, and a root that declared nothing at all
/// states no forbidden item either — so without them the one claim in this file
/// that reads only for offenders would pass over a tree it never entered.
fn assert_module_roots_export_and_nothing_else(surface: &ProductSurface) {
    assert!(
        !MODULE_ROOTS.is_empty(),
        "an export-only claim over no module root constrains nothing"
    );
    let mut offenders: Vec<String> = Vec::new();
    for path in MODULE_ROOTS {
        let root = surface.module(path);
        assert!(
            root.parsed
                .items
                .iter()
                .any(|item| matches!(item, syn::Item::Mod(_))),
            "{path} declares no module, so it exports nothing this claim can read"
        );
        for item in &root.parsed.items {
            let allowed = matches!(
                item,
                syn::Item::Mod(_) | syn::Item::Use(_) | syn::Item::Macro(_)
            );
            if !allowed {
                offenders.push(format!("{path} declares {}", item_kind(item)));
            }
        }
        if let Some(offender) = root.parsed.items.iter().find_map(module_with_body) {
            offenders.push(format!("{path} declares an inline module {offender}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "a module root exports; it does not implement: {offenders:?}"
    );
}

/// The kind of item a module root is not allowed to declare, as a failure names
/// it.
fn item_kind(item: &syn::Item) -> &'static str {
    match item {
        syn::Item::Fn(_) => "a function",
        syn::Item::Struct(_) => "a struct",
        syn::Item::Enum(_) => "an enum",
        syn::Item::Impl(_) => "an impl block",
        syn::Item::Trait(_) => "a trait",
        syn::Item::Const(_) | syn::Item::Static(_) => "a constant",
        syn::Item::Type(_) => "a type alias",
        _ => "an item that is neither a module nor a re-export",
    }
}

/// The name of an inline module a root declares with a body.
fn module_with_body(item: &syn::Item) -> Option<String> {
    match item {
        syn::Item::Mod(declared) if declared.content.is_some() => Some(declared.ident.to_string()),
        _ => None,
    }
}

/// Every graph answer calls the `pedant-graph` entry point it projects.
fn assert_every_graph_answer_delegates(surface: &ProductSurface) {
    // The row floor below rejects a delegation that names no entry point. This
    // one rejects the rank above it: a table with no row at all leaves `missing`
    // empty for the same reason, and every graph answer could stop delegating.
    assert!(
        !GRAPH_DELEGATIONS.is_empty(),
        "a delegation claim over no answering module constrains nothing"
    );
    let mut missing: Vec<String> = Vec::new();
    for delegation in GRAPH_DELEGATIONS {
        // A row that states no entry point constrains nothing: the filter below
        // selects no line, `missing` stays empty, and the module could stop
        // delegating with its row still sitting in the table.
        assert!(
            !delegation.entries.is_empty(),
            "{} is modelled as delegating and names no entry point",
            delegation.module
        );
        let module = surface.module(delegation.module);
        let rendered = compact_tokens(module);
        missing.extend(
            delegation
                .entries
                .iter()
                .filter(|entry| !rendered.contains(**entry))
                .map(|entry| format!("{} no longer calls {entry}", delegation.module)),
        );
    }
    assert!(
        missing.is_empty(),
        "graph algorithms are published by pedant-graph, and this crate projects them: {missing:?}"
    );
}
