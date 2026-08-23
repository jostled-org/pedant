//! Who may state a guarded-process ceiling, read from the gate CLI support
//! tree's own tracked source.
//!
//! The literal comparisons in the Tier 2 journey read the shared default and
//! the widened constant. Both stay true when a second support module hands the
//! same guard a wider ceiling of its own: the default is still 120 seconds
//! while an ordinary journey is no longer bound by it. The scans here read the
//! tree instead, so a second override fails rather than passing unseen.

use crate::source::{collapsed, support_tree_sites};

/// Every gate CLI support site that binds a guarded-process ceiling, in tree
/// order, each as its module and the value it states.
///
/// The plumbing sites come first because the fixture declares the option, fills
/// it from the shared default, and hands it to the guard; the one localized
/// widening follows.
const BUDGET_SITES: &[&str] = &[
    "fixture.rs -> Duration",
    "fixture.rs -> BUDGET",
    "fixture.rs -> options.budget",
    "semantic.rs -> SEMANTIC_BUDGET",
];

/// Every guard item the gate CLI support tree reaches, in tree order, each as
/// its module and the item it names.
///
/// A ceiling can also be stated with no `budget` token anywhere on the line, by
/// handing `Guard::finish` a duration directly. Such a site would bind no
/// ceiling for the scan above to find, and would bypass the containment and
/// stated-ceiling assertions the fixture makes on every spawn as well. The run
/// vocabulary that reaches the guard at all — `Run`, `execute`, and `Guard`
/// itself — is therefore stated as a whole set here, and the fixture is its
/// only holder.
const GUARD_ITEMS: &[&str] = &[
    "fixture.rs -> BUDGET",
    "fixture.rs -> Completed",
    "fixture.rs -> Run",
    "fixture.rs -> execute",
    "output.rs -> Completed",
    "project.rs -> Completed",
    "semantic.rs -> BUDGET",
    "semantic.rs -> Completed",
];

/// The guard module segment, spelled in parts so this scanner is not itself a
/// reference site.
///
/// A scan that had to exempt its own module would leave that module free to
/// reach the guard unseen, which is the hole this scan closes.
const GUARD_MODULE: &str = concat!("process", "_guard");

/// Every path segment an import may place before the module it names.
///
/// A support module is a child of the crate root, so the same import compiles
/// under any of these and under none. A needle anchored to one of them would
/// admit the rest unseen.
const IMPORT_QUALIFIERS: &[&str] = &["", "crate", "super", "self"];

/// The Tier 2 module is the only gate CLI journey with a ceiling of its own,
/// and the fixture is the only module that can reach the guard to state one.
pub(crate) fn the_semantic_journey_is_the_only_budget_override() {
    assert_eq!(
        support_tree_sites(bound_budgets),
        BUDGET_SITES,
        "one module states a guarded ceiling of its own, and it is the Tier 2 journey"
    );
    assert_eq!(
        support_tree_sites(guard_items),
        GUARD_ITEMS,
        "one module reaches the guard's run vocabulary, and it is the fixture"
    );
}

/// Every ceiling one line binds, which is every occurrence rather than the
/// first: a line may read one ceiling and bind another.
fn bound_budgets(code: &str) -> Vec<String> {
    code.match_indices("budget")
        .filter_map(|(at, name)| bound_value(&code[at + name.len()..]))
        .collect()
}

/// The value one occurrence binds, when it binds one at all.
///
/// An occurrence that reads a ceiling — comparing it, printing it, passing it
/// on — states no ceiling of its own, so only a field declaration, a
/// struct-literal field, or an assignment counts.
fn bound_value(after_name: &str) -> Option<String> {
    let tail = after_name.trim_start();
    let assigned = tail.strip_prefix('=').filter(|rest| !rest.starts_with('='));
    let value = tail.strip_prefix(':').or(assigned)?;
    Some(value.trim().trim_end_matches([',', ';']).to_owned())
}

/// Every guard item one line names, at every occurrence rather than the first.
///
/// Rust admits one way to reach the guard: name its module, in an import or in
/// a qualified path. The needle is the module segment alone, so every prefix a
/// caller may write is seen, and what follows the segment says which form the
/// occurrence takes. A longer identifier that merely ends in the segment names
/// a different module and reaches nothing.
fn guard_items(code: &str) -> Vec<String> {
    code.match_indices(GUARD_MODULE)
        .filter(|(at, _)| !continues_identifier(&code[..*at]))
        .flat_map(|(at, name)| reached_items(&code[..at], &code[at + name.len()..], code))
        .collect()
}

/// Whether the text before one occurrence makes it the tail of a longer name.
fn continues_identifier(before: &str) -> bool {
    before
        .chars()
        .next_back()
        .is_some_and(|last| last.is_alphanumeric() || last == '_')
}

/// The items one occurrence reaches, when it reaches the module at all.
///
/// An import that names a path states its items. Any other reach — a
/// `Guard::spawn` call through a qualified path, or an import of the whole
/// module under its own name or a rename — states the whole line, which the
/// inventory above does not admit. A segment followed by neither a path nor an
/// import tail, such as the `.rs` of a written file name, names no module.
fn reached_items(before: &str, after: &str, code: &str) -> Vec<String> {
    let tail = after.trim_start();
    match (tail.strip_prefix("::"), is_import_prefix(before)) {
        (Some(items), true) => imported_items(items),
        (Some(_), false) => vec![collapsed(code)],
        (None, true) if imports_module_itself(tail) => vec![collapsed(code)],
        (None, _) => Vec::new(),
    }
}

/// Whether the text before the module segment is an import's path prefix and
/// nothing else.
fn is_import_prefix(before: &str) -> bool {
    before.trim().strip_prefix("use").is_some_and(|path| {
        path.trim()
            .trim_end_matches("::")
            .split("::")
            .all(|segment| IMPORT_QUALIFIERS.contains(&segment.trim()))
    })
}

/// Whether an import that names no path after the module brings in the whole
/// module, under its own name or a rename.
fn imports_module_itself(tail: &str) -> bool {
    tail.starts_with("as ") || tail.starts_with(';')
}

/// Every item one import declaration brings in.
fn imported_items(after_path: &str) -> Vec<String> {
    after_path
        .trim_end_matches(';')
        .trim_matches(['{', '}'])
        .split(',')
        .map(|item| item.trim().to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}
