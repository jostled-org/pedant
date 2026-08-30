//! 11.T3: what an operator is told to install, and what they are shown to run.
//!
//! Three products ship from this workspace, and the README is the one place a
//! reader learns which is which. It is also the one artifact no compiler reads:
//! a command renamed, a tool withdrawn, or a whole product retired leaves the
//! README describing something that no longer answers, and every test in the
//! repository still passes.
//!
//! So every example is compared with the source that serves it. The command
//! spellings come out of the product's own `clap` enums, the tool names out of
//! its own registry table, and the README is required to state exactly those and
//! nothing retired. What the spawned journeys prove is that those names work;
//! what this proves is that the README names them.
//!
//! It reads tracked files only — the README and three manifests, plus the two
//! product sources [`super::served_inventory`] reads — so it holds in every
//! configuration, including the one a release is cut from.

use std::collections::BTreeSet;

use crate::resolution::authority_scan::read_text;
use crate::resolution::code_intelligence::installation_model::PRODUCTS;
use crate::resolution::code_intelligence::served_inventory::{
    CLI_SOURCE, REGISTRY_SOURCE, Served,
    assert_the_graph_gate_withholds_exactly_the_documented_extras, names, served_commands,
    served_tools,
};
use crate::resolution::manifest_reader::manifest_table;

/// The operator-facing document every claim below is about.
const README: &str = "README.md";

/// The heading of the README table that pairs a command with its tool.
const NAVIGATION_TABLE_HEADING: &str = "| Command | Tool | Answers |";

/// The command the product serves that answers no navigation question.
///
/// It is the transport for the other eight, so it has no tool beside it in the
/// README's table and is excluded from the pairing below rather than left to
/// fail it.
const TRANSPORT_COMMAND: &str = "mcp";

/// Route spellings the cutover withdrew.
///
/// A README that still shows one of these is telling an operator to run a
/// command the installed binary refuses. Each is checked against the whole
/// document, because a retired route in prose is as wrong as one in a fence.
const RETIRED_ROUTES: [&str; 4] = [
    "pedant-snippet extract",
    "extract_path",
    "enclosing_unit",
    "SnippetError",
];

/// 11.T3: the README installs three products, shows only served commands and
/// tools, documents the fully-featured surface, and shows no retired route.
#[test]
fn code_intelligence_readme_examples_use_one_navigation_product() {
    let readme = read_text(README);
    let commands = served_commands();
    let tools = served_tools();

    assert_three_products_are_installed(&readme);
    assert_every_product_states_its_own_role();
    assert_the_graph_gate_withholds_exactly_the_documented_extras(&commands, &tools);
    assert_the_command_and_tool_table_is_the_served_inventory(&readme, &commands, &tools);
    assert_every_example_names_a_served_command(&readme, &commands);
    assert_no_retired_route_is_shown(&readme);
}

/// The README tells an operator to install each product exactly once, and no
/// fourth one.
fn assert_three_products_are_installed(readme: &str) {
    for product in &PRODUCTS {
        let install = format!("cargo install {}\n", product.package);
        assert_eq!(
            readme.matches(&install).count(),
            1,
            "{README} states `cargo install {}` exactly once",
            product.package
        );
    }
    let installed = readme.matches("cargo install ").count();
    assert_eq!(
        installed,
        PRODUCTS.len() + 1,
        "{README} states {installed} install lines; the three products plus the one \
         feature-selecting repeat are expected"
    );
}

/// Each manifest publishes its own role, so a registry listing tells the three
/// apart.
fn assert_every_product_states_its_own_role() {
    for product in &PRODUCTS {
        let manifest = manifest_table(product.manifest);
        let description = manifest
            .get("package")
            .and_then(|package| package.get("description"))
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("{} publishes a description", product.manifest));
        assert!(
            description.contains(product.role),
            "{}'s description must name its role ({}): {description}",
            product.package,
            product.role
        );
    }
}

/// The README's table is the served inventory, pair for pair and in order.
///
/// Both halves matter. A table row naming a command the binary does not serve is
/// an instruction that fails; a served command with no row is a question an
/// operator never learns to ask.
///
/// The two inventories are counted against each other before they are paired. A
/// `zip` stops at the shorter side and reports the truncation as a match, so a
/// ninth tool with no command beside it left eight matching pairs and a README
/// documenting fewer tools than the server serves. The set comparisons beneath
/// answer that in one direction only: a set drops duplicates, so a registry
/// serving one tool name twice against a three-row table satisfied all three
/// claims at once.
fn assert_the_command_and_tool_table_is_the_served_inventory(
    readme: &str,
    commands: &[Served],
    tools: &[Served],
) {
    let rows = table_rows(readme);
    let command_names = names(commands);
    let tool_names = names(tools);
    let navigable: Box<[&str]> = command_names
        .iter()
        .copied()
        .filter(|command| *command != TRANSPORT_COMMAND)
        .collect();
    assert_eq!(
        tool_names.len(),
        navigable.len(),
        "{CLI_SOURCE} serves {} commands that answer a navigation question and \
         {REGISTRY_SOURCE} serves {} tools, so no pairing of the two is exact",
        navigable.len(),
        tool_names.len()
    );
    let paired: Box<[(Box<str>, Box<str>)]> = tool_names
        .iter()
        .zip(navigable.iter())
        .map(|(tool, command)| (Box::from(*command), Box::from(*tool)))
        .collect();
    assert_eq!(
        rows, paired,
        "{README} must pair every served command with the tool that answers it"
    );

    let documented: BTreeSet<&str> = rows
        .iter()
        .map(|(command, _)| &**command)
        .chain([TRANSPORT_COMMAND])
        .collect();
    let served: BTreeSet<&str> = command_names.iter().copied().collect();
    assert_eq!(
        documented, served,
        "{README} documents exactly the commands {CLI_SOURCE} serves"
    );

    let documented: BTreeSet<&str> = rows.iter().map(|(_, tool)| &**tool).collect();
    let served: BTreeSet<&str> = tool_names.iter().copied().collect();
    assert_eq!(
        documented, served,
        "{README} documents exactly the tools {REGISTRY_SOURCE} serves"
    );
}

/// Every `pedant-snippet` invocation in a fenced example names a served command.
///
/// An option rather than a command — `pedant-snippet --version` — states no
/// question and is skipped; a bare mention with nothing after it is the install
/// line, which the product claim above already owns.
fn assert_every_example_names_a_served_command(readme: &str, commands: &[Served]) {
    let served: BTreeSet<&str> = names(commands).iter().copied().collect();
    let mut examined = 0;
    for line in fenced_lines(readme) {
        let mut words = line.split_whitespace().peekable();
        while let Some(word) = words.next() {
            if word != "pedant-snippet" {
                continue;
            }
            let Some(next) = words.peek() else { continue };
            if next.starts_with('-') {
                continue;
            }
            examined += 1;
            assert!(
                served.contains(*next),
                "{README} shows `pedant-snippet {next}`, which {CLI_SOURCE} does not serve"
            );
        }
    }
    assert!(
        examined > 0,
        "{README} shows no `pedant-snippet` invocation, so this claim read nothing"
    );
}

/// No retired route survives anywhere in the document.
fn assert_no_retired_route_is_shown(readme: &str) {
    for route in RETIRED_ROUTES {
        assert!(
            !readme.contains(route),
            "{README} still shows the withdrawn route {route}"
        );
    }
}

/// Every `| command | tool | …` row of the README's navigation table.
///
/// The table is found by its own heading rather than by row shape. This document
/// holds a gate-rule table whose first two cells are backticked names too, and a
/// scan by shape read its four rows as navigation commands — which is the
/// failure this claim is about, one document up.
///
/// A row beneath the heading that this reader cannot turn into a pair stops
/// here. Dropping it left a row naming a route the binary does not serve
/// invisible whenever it was written in a shape the reader could not name, which
/// is the one document the pairing below can say nothing about.
fn table_rows(readme: &str) -> Box<[(Box<str>, Box<str>)]> {
    let rows: Box<[(Box<str>, Box<str>)]> = readme
        .lines()
        .skip_while(|line| line.trim() != NAVIGATION_TABLE_HEADING)
        .skip(2)
        .take_while(|line| line.trim_start().starts_with('|'))
        .map(|line| {
            let cells: Box<[&str]> = line.split('|').map(str::trim).collect();
            match &*cells {
                [_, command, tool, _, _] => (backticked(command, line), backticked(tool, line)),
                _ => panic!(
                    "{README} states the navigation row [{line}], which this reader cannot turn \
                     into a command and tool pair"
                ),
            }
        })
        .collect();
    assert!(
        !rows.is_empty(),
        "{README} must state the navigation table under `{NAVIGATION_TABLE_HEADING}`"
    );
    rows
}

/// One table cell's backticked name.
fn backticked(cell: &str, row: &str) -> Box<str> {
    cell.strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
        .map(Box::from)
        .unwrap_or_else(|| {
            panic!("{README} states the navigation row [{row}], whose cell [{cell}] names nothing")
        })
}

/// Every line inside a fenced block, which is where an example lives.
fn fenced_lines(readme: &str) -> Box<[&str]> {
    let mut fenced = false;
    readme
        .lines()
        .filter(|line| match line.starts_with("```") {
            true => {
                fenced = !fenced;
                false
            }
            false => fenced,
        })
        .collect()
}
