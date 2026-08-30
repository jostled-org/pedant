//! 9.T1: the spawned CLI serves exactly nine commands, under exactly nine
//! names.
//!
//! Its own module beside [`crate::journeys::cli_navigation`], which proves what
//! the same binary answers. What a binary serves and what it says are two
//! claims, and only this one is stated without a repository to ask about.
//!
//! The command tree is written down here rather than derived, for the reason
//! [`crate::journeys::mcp_registry`] writes its tool names down: an inventory
//! read from the surface under test would agree with a tenth command as readily
//! as with these nine, and "exactly nine commands and eight tools" is one claim
//! served by two transports.

use crate::command::{self, Output};
use crate::failure::Failure;
use crate::journeys::outcome::{assert_answered, assert_usage_error, run as at_root};

/// Every command this binary serves, in the order its help states them.
const COMMANDS: [&str; 9] = [
    "list-projects",
    "search",
    "outline",
    "read",
    "at",
    "relations",
    "path",
    "graph",
    "mcp",
];

/// The one row clap contributes to the tree it renders.
///
/// Named rather than filtered away. `help` is a command an operator can run, so
/// a listing missing it is as wrong as one carrying a tenth of ours.
const BUILT_IN: &str = "help";

/// The heading the published command tree sits under.
const COMMANDS_HEADING: &str = "Commands:";

/// What a listed row states when its command answers to a second *listed* name.
///
/// A visible alias is a command by another name that clap prints beside the row
/// it belongs to rather than in the name column. An inventory that read the name
/// column alone would count ten accepted spellings as nine commands.
const ALIASES: &str = "[aliases:";

/// An unambiguous abbreviation of one served command, which must be refused.
///
/// Named rather than derived from [`COMMANDS`], for the reason the command tree
/// itself is written down: a prefix taken from the surface under test would
/// abbreviate a tenth command as readily as one of these nine.
///
/// `list-p` is no command's name and exactly one command's prefix, so clap
/// answers it only under `infer_subcommands`. The command it abbreviates takes
/// no required argument, which is what makes the run state the difference: a
/// binary that inferred it would answer and exit zero, where one that does not
/// exits two and names the spelling it never served. An abbreviation of a
/// command with a required argument would exit two either way.
const ABBREVIATION: &str = "list-p";

/// Both runs this claim makes, collected before either is asserted.
pub(crate) struct Inventory {
    /// The command tree the binary publishes.
    published: Output,
    /// What it does with an unambiguous abbreviation of one of its commands.
    abbreviated: Output,
}

/// Ask the binary what it serves, and what it answers to.
pub(crate) async fn inventory(root: &str) -> Result<Inventory, Failure> {
    Ok(Inventory {
        // Without a root, because the tree a binary publishes is not a fact
        // about any repository and asking under one would say it was.
        published: command::run(&["--help"]).await?,
        abbreviated: at_root(root, &[ABBREVIATION], "an abbreviated command").await?,
    })
}

/// The binary serves exactly nine commands, under exactly nine names.
pub(crate) fn assert_the_inventory_is_exactly_the_nine(inventory: &Inventory) {
    assert_the_command_tree_is_exactly_the_nine(&inventory.published);
    assert_no_command_answers_to_a_second_spelling(&inventory.abbreviated);
}

/// The binary publishes exactly the nine commands, and clap's own `help`.
///
/// The listing is the seam, because clap renders it from the same command tree
/// it parses: a tenth variant is a tenth row here, and a tenth *visible*
/// spelling of one of these nine is an alias stated on the row it belongs to. A
/// build that hid a command from its own help would hide it from this, and from
/// the operator — which is the boundary of what a published listing can be held
/// to. The spelling a build hides but still answers to is held instead by
/// [`assert_no_command_answers_to_a_second_spelling`].
fn assert_the_command_tree_is_exactly_the_nine(published: &Output) {
    assert_answered(published, "--help");
    let listed: Vec<&str> = rows(&published.stdout)
        .map(|row| {
            row.split_whitespace()
                .next()
                .expect("a listed row names its command")
        })
        .collect();
    let expected: Vec<&str> = COMMANDS.iter().copied().chain([BUILT_IN]).collect();
    assert_eq!(
        listed, expected,
        "the binary serves exactly its nine commands and clap's help: {}",
        published.stdout
    );

    let aliased: Vec<&str> = rows(&published.stdout)
        .filter(|row| row.contains(ALIASES))
        .collect();
    assert!(
        aliased.is_empty(),
        "and answers to no name beside them: {aliased:?}"
    );
}

/// No command answers to a second name, published or not.
///
/// The listing rejects visible aliases. This spawned abbreviation probes Clap's
/// inference behavior through the real parser.
fn assert_no_command_answers_to_a_second_spelling(abbreviated: &Output) {
    assert_usage_error(
        abbreviated,
        "an unambiguous abbreviation of a command this binary serves",
        ABBREVIATION,
    );
}

/// Every row of the command tree one help listing publishes.
fn rows(published: &str) -> impl Iterator<Item = &str> {
    published
        .lines()
        .skip_while(|line| line.trim() != COMMANDS_HEADING)
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
}
