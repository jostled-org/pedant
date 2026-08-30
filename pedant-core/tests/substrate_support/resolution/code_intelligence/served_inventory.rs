//! What the navigation product serves, read from the product's own sources.
//!
//! The other half of [`super::operator_documentation`], which reads the
//! document. This half reads the two declarations that document is checked
//! against: the `clap` command tree and the MCP registry table. Splitting them
//! is the seam the case already had — one side is a repository document nobody
//! compiles, the other is source the compiler owns — and each side needs none of
//! the other's readers.
//!
//! Both readers parse source text, and `syn` evaluates no `cfg`, so both
//! inventories are the fully-featured surface in every configuration. What each
//! conditional withholds from a narrower build is carried on the row it stands
//! over and stated by
//! [`assert_the_graph_gate_withholds_exactly_the_documented_extras`].

use quote::ToTokens;
use syn::{Attribute, Expr, ExprLit, Item, ItemEnum, Lit, Member};

use crate::resolution::authority_scan::read_text;
use crate::resolution::code_intelligence::product_surface::{ProductModule, compact};

/// Where the product declares the commands it serves.
pub(crate) const CLI_SOURCE: &str = "pedant-snippet/src/cli.rs";

/// Where the product declares the tools it serves.
pub(crate) const REGISTRY_SOURCE: &str = "pedant-snippet/src/registry/entries.rs";

/// The `clap` enums whose variants are the command tree, in the order the
/// source declares them.
///
/// Two, because the outer enum states the transport and flattens the questions
/// out of the inner one. Read alone, the outer enum yields `answer` — the
/// spelling of a flattened variant, which is a name no operator types and no
/// tool answers.
///
/// The order is part of the table: the pairing this inventory feeds drops the
/// transport and compares what is left against the README's rows in listing
/// order, so the enum that states the transport has to be read first.
const COMMAND_ENUMS: [&str; 2] = ["Command", "Question"];

/// The attribute saying a variant is not a command, and that the variants of
/// the enum it holds stand in its place.
///
/// Written as the source writes it and compared with the spaces removed, the
/// way [`GRAPH_GATE`] is, so the renderer's line breaks decide nothing.
const FLATTENED_VARIANT: &str = "#[command(flatten)]";

/// The one conditional the product writes over a served command or tool.
///
/// Written as the source writes it and compared with the spaces removed, so the
/// renderer's line breaks decide nothing.
const GRAPH_GATE: &str = "#[cfg(any(feature = \"graph-rust\", feature = \"graph-go\"))]";

/// The commands a build without a graph feature does not serve.
const GATED_COMMANDS: [&str; 3] = ["relations", "path", "graph"];

/// The tools a build without a graph feature does not serve.
const GATED_TOOLS: [&str; 3] = ["query_relations", "find_path", "analyze_graph"];

/// One served name, with the conditional written over it.
pub(crate) struct Served {
    /// The spelling an operator types, or a client asks for.
    name: Box<str>,
    /// The `#[cfg(...)]` standing over the declaration, spaces removed, when one
    /// stands over it.
    gate: Option<Box<str>>,
}

/// The names one inventory serves, in the order it serves them.
pub(crate) fn names(served: &[Served]) -> Box<[&str]> {
    served.iter().map(|entry| &*entry.name).collect()
}

/// The documented surface is the fully-featured one, and exactly six entries sit
/// behind exactly one conditional.
///
/// Both inventories are the all-features surface in every configuration this
/// case runs in. That is the surface the README is checked against, and it is
/// the right one to check — the document tells an operator which features to
/// select. What it is not is a claim about what an arbitrary build serves, so
/// the gate is read from the declaration's own attribute and stated here. A
/// fourth gated entry, or a second conditional written over one of these six,
/// fails rather than joining a surface nobody checked.
pub(crate) fn assert_the_graph_gate_withholds_exactly_the_documented_extras(
    commands: &[Served],
    tools: &[Served],
) {
    let gate = compact(GRAPH_GATE);
    for (source, served, withheld) in [
        (CLI_SOURCE, commands, &GATED_COMMANDS),
        (REGISTRY_SOURCE, tools, &GATED_TOOLS),
    ] {
        let gated: Box<[(&str, &str)]> = served
            .iter()
            .filter_map(|entry| entry.gate.as_deref().map(|written| (&*entry.name, written)))
            .collect();
        let modelled: Box<[(&str, &str)]> = withheld.iter().map(|name| (*name, &*gate)).collect();
        assert_eq!(
            gated, modelled,
            "{source} must withhold exactly the modelled entries, behind exactly the one gate"
        );
    }
}

/// Every command the product's `clap` enums declare, in declaration order.
///
/// The variant identifiers are converted the way `clap` converts them, so the
/// list is the spelling an operator types rather than the spelling the source
/// declares. A flattened variant is dropped rather than spelled, because `clap`
/// never publishes its name: the tree an operator meets holds the variants of
/// the enum it carries, and those are read from that enum's own row in
/// [`COMMAND_ENUMS`].
///
/// Each variant carries whatever conditional stands over it. The gate travels
/// with the variants it withholds, whichever of the two enums states them, so
/// flattening moved neither the commands nor their conditionals out of reach.
pub(crate) fn served_commands() -> Box<[Served]> {
    let module = product_module(CLI_SOURCE);
    let declared: Box<[&ItemEnum]> = module
        .parsed
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Enum(enumeration)
                if COMMAND_ENUMS.iter().any(|name| enumeration.ident == *name) =>
            {
                Some(enumeration)
            }
            _ => None,
        })
        .collect();
    let found: Box<[Box<str>]> = declared
        .iter()
        .map(|enumeration| enumeration.ident.to_string().into_boxed_str())
        .collect();
    let modelled: Box<[Box<str>]> = COMMAND_ENUMS.iter().map(|name| Box::from(*name)).collect();
    assert_eq!(
        found, modelled,
        "{CLI_SOURCE} must declare exactly these enums, in this order, for the pairing that \
         reads this inventory to see the served commands in listing order"
    );
    declared
        .iter()
        .flat_map(|enumeration| enumeration.variants.iter())
        .filter(|variant| !flattened(&variant.attrs))
        .map(|variant| Served {
            name: kebab_case(&variant.ident.to_string()),
            gate: conditional(&variant.attrs),
        })
        .collect()
}

/// Every tool name the product's registry declares, in listing order.
///
/// Read from the one table listing and dispatch both consume, so a README
/// checked against it is checked against the rows a client is served from.
///
/// Cfg-blind for the same reason [`served_commands`] is, and answered the same
/// way: each row carries its own conditional, and three of the eight carry the
/// graph gate.
pub(crate) fn served_tools() -> Box<[Served]> {
    let module = product_module(REGISTRY_SOURCE);
    let tools: Box<[Served]> = module
        .parsed
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Static(declared) => Some(&*declared.expr),
            _ => None,
        })
        .flat_map(entry_rows)
        .collect();
    assert!(
        !tools.is_empty(),
        "{REGISTRY_SOURCE} must declare the served entries this claim reads"
    );
    tools
}

/// The conditional written over one declaration, spaces removed.
///
/// Rendered from the tree rather than matched against the page: an attribute
/// broken across lines and the same attribute on one line are the same
/// conditional, and only the rendering makes them compare equal.
fn conditional(attributes: &[Attribute]) -> Option<Box<str>> {
    attributes
        .iter()
        .find(|attribute| attribute.path().is_ident("cfg"))
        .map(|attribute| compact(&attribute.to_token_stream().to_string()))
}

/// Whether one variant flattens another enum into the tree rather than naming a
/// command of its own.
///
/// Rendered from the tree for the same reason [`conditional`] is: the attribute
/// written on one line and the same attribute broken across two are the same
/// attribute, and only the rendering makes them compare equal.
fn flattened(attributes: &[Attribute]) -> bool {
    let flatten = compact(FLATTENED_VARIANT);
    attributes
        .iter()
        .any(|attribute| compact(&attribute.to_token_stream().to_string()) == flatten)
}

/// One product source, read and parsed.
///
/// Read through the product surface's own constructor rather than a second
/// read-and-parse-or-panic beside it. There were two copies of that pair here,
/// one per source, and the type that already owns it is one import away.
fn product_module(relative: &str) -> ProductModule {
    ProductModule::of_text(relative, &read_text(relative))
}

/// Every `name: "…"` a registry entry states, in source order, with the
/// conditional written over the row that states it.
fn entry_rows(expression: &Expr) -> Box<[Served]> {
    match expression {
        Expr::Reference(referenced) => entry_rows(&referenced.expr),
        Expr::Array(entries) => entries.elems.iter().flat_map(entry_rows).collect(),
        Expr::Struct(entry) => entry
            .fields
            .iter()
            .filter(|field| matches!(&field.member, Member::Named(name) if name == "name"))
            .filter_map(|field| string_literal(&field.expr))
            .map(|name| Served {
                name,
                gate: conditional(&entry.attrs),
            })
            .collect(),
        _ => Box::default(),
    }
}

/// One string literal's value, where the expression is one.
fn string_literal(expression: &Expr) -> Option<Box<str>> {
    match expression {
        Expr::Lit(ExprLit {
            lit: Lit::Str(text),
            ..
        }) => Some(text.value().into_boxed_str()),
        _ => None,
    }
}

/// One `UpperCamel` identifier as `clap` spells it on the command line.
fn kebab_case(identifier: &str) -> Box<str> {
    let mut spelled = String::with_capacity(identifier.len() + 2);
    for (position, letter) in identifier.char_indices() {
        match (position, letter.is_uppercase()) {
            (0, _) | (_, false) => spelled.push(letter.to_ascii_lowercase()),
            (_, true) => {
                spelled.push('-');
                spelled.push(letter.to_ascii_lowercase());
            }
        }
    }
    spelled.into_boxed_str()
}
