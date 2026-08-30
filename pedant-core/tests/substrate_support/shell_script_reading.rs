//! How a tracked shell script is read, and the three shared assertions its
//! readings are held to.
//!
//! Split out of [`crate::packaged_workspace_claims`] for the source-file budget
//! alone. Every prover imports these readers from here rather than through that
//! module: a re-export would be a second path to each name, which is the thing
//! the single owner is for. A second copy of any reader here is a second answer
//! to what a shell command, a function definition, or a function body is, and
//! the two would drift on the first script that wrapped an opening brace.
//!
//! Where the workspace root is, and how a tracked file is read, are not here.
//! Those are the same two questions every structural claim in this repository
//! asks, so they belong to [`crate::resolution::root_inventory::workspace_root`]
//! and [`crate::resolution::authority_scan::read_text`]; this module held a
//! second copy of each, and one of the two scripts read through them was already
//! being read both ways.
//!
//! The emptiness guards on the two table assertions are the reason they are
//! shared at all. A `for` loop over a table that lost its entries asserts
//! nothing and reports success, which is the one failure a structural prover
//! cannot afford.

use crate::resolution::tracked_index::tracked_paths;

/// Every shell script this repository tracks, in Git's own order.
///
/// Git is asked rather than the filesystem walked, because `tracked` is the
/// whole claim: `docs/` holds ignored lifecycle adapters that this repository
/// does not own and must not lint, and a filesystem walk would sweep them in.
pub(crate) fn tracked_shell_scripts() -> Box<[Box<str>]> {
    tracked_paths("*.sh")
}

/// One logical shell command per line, so a fragment states a whole command
/// rather than whichever slice of it survived the author's line wrapping.
///
/// Two provers take it — the release reading and the journey reading — and a
/// second copy of a joiner is a second answer to what a command is.
pub(crate) fn joined_lines(source: &str) -> Box<str> {
    let continued = source.replace("\\\n", " ");
    let lines: Box<[Box<str>]> = continued
        .lines()
        .map(|line| {
            let words: Box<[&str]> = line.split_whitespace().collect();
            words.join(" ").into()
        })
        .collect();
    lines.join("\n").into()
}

/// Every shell function one script defines, in the order the file states them.
///
/// Two provers take it — the packaged-workspace stage inventory and the tracked
/// classifier's API — and each compares the answer against a different table. A
/// second copy of the reader is a second answer to what a definition looks like,
/// and the two would drift on the first script that wrapped an opening brace.
pub(crate) fn defined_functions(source: &str) -> Box<[Box<str>]> {
    source
        .lines()
        .filter_map(|line| line.strip_suffix("() {"))
        .map(Box::from)
        .collect()
}

/// One shell function's body, between its opening line and its closing brace.
pub(crate) fn function_body(source: &str, name: &str) -> Box<str> {
    let opening: Box<str> = format!("\n{name}() {{\n").into();
    let start = source
        .find(&*opening)
        .unwrap_or_else(|| panic!("{name} should be defined"))
        + opening.len();
    let length = source[start..]
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{name} should have a closing brace"));
    source[start..start + length].into()
}

/// Where one required fragment starts in the text one subject is read from.
///
/// The subject travels with the fragment because half of these readings are
/// taken over a single function body and half over the whole script, and a
/// panic that named neither would leave the reader guessing which text was
/// searched and which claim wanted it.
pub(crate) fn offset_of(text: &str, fragment: &str, subject: &str) -> usize {
    text.find(fragment)
        .unwrap_or_else(|| panic!("{subject}: the text read holds no [{fragment}]"))
}

/// One text holds every fragment of a table, and the table holds something.
///
/// The emptiness check is the point of sharing this. A `for` loop over a table
/// that lost its entries asserts nothing and reports success, which is the one
/// failure a structural prover cannot afford.
pub(crate) fn assert_contains_all(text: &str, table: &[&str], subject: &str) {
    assert!(
        !table.is_empty(),
        "{subject}: an empty table requires nothing"
    );
    for fragment in table {
        assert!(text.contains(fragment), "{subject} is missing [{fragment}]");
    }
}

/// One text holds every step of a table, each after the one before it.
pub(crate) fn assert_in_order(text: &str, steps: &[&str], subject: &str) {
    assert!(
        !steps.is_empty(),
        "{subject}: an empty sequence requires nothing"
    );
    let mut previous: Option<usize> = None;
    for step in steps {
        let offset = offset_of(text, step, subject);
        if let Some(earlier) = previous {
            assert!(offset > earlier, "{subject}: [{step}] runs out of order");
        }
        previous = Some(offset);
    }
}

/// One text states a fragment once, so a second statement of it cannot answer
/// for the first.
pub(crate) fn assert_exactly_once(text: &str, fragment: &str, subject: &str) {
    assert_eq!(
        text.matches(fragment).count(),
        1,
        "{subject} must be stated exactly once [{fragment}]"
    );
}
