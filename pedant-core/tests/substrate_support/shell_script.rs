//! Reading a proof runner's declarations back out of its committed text.
//!
//! Two runners now state fixed inventories in shell arrays, and nothing in a
//! cargo build reads either. The modules that hold them to a written-down model
//! parse the same shapes — a `case` arm, a fixed-model section of quoted
//! scalars, an array literal, and a `<config>|<predicates>` registration row —
//! so the parsing lives here once. Reading the script rather than running it is
//! deliberate: executing it would need a build, and the claim is about what the
//! committed text declares.

use std::collections::{BTreeMap, BTreeSet};

/// The `case` statement both runners dispatch their mode argument through.
const DISPATCH: &str = "case \"${1:-}\" in";

/// The heading opening the section both runners state their fixed model in.
const MODEL_HEADING: &str = "# Fixed model";

/// The mode names a runner's dispatch answers, taken from its `case` arms.
///
/// Only the dispatch statement is read. A runner's inner `case` arms — the ones
/// that tell a zero count from a broken matcher — are arms too, and a scan over
/// every `;;` in the file would report them as modes the script accepts.
pub fn mode_arms(source: &str) -> BTreeSet<String> {
    let dispatch = source
        .split_once(DISPATCH)
        .expect("a proof runner dispatches its mode argument")
        .1;
    let dispatch = dispatch
        .split_once("\nesac")
        .expect("the dispatch statement is closed")
        .0;
    dispatch
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_suffix(";;"))
        .filter_map(|arm| arm.split_once(')'))
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, _)| name.to_owned())
        .collect()
}

/// Whether a line is one of the banners a runner's sections are ruled off with.
fn is_banner(line: &str) -> bool {
    line.starts_with("# ---") && line.trim_end_matches('-') == "# "
}

/// The lines of a runner's fixed-model section.
///
/// The section is where a runner writes down what it proves, so it is where a
/// model's set comparison has to range. Reading the whole file instead would
/// sweep in `PROOF_WORK_DIR` and every other value the runner computes for
/// itself, none of which a model states.
fn model_block<'a>(path: &str, source: &'a str) -> Vec<&'a str> {
    let mut lines = source.lines();
    assert!(
        lines.any(|line| line == MODEL_HEADING),
        "{path} must state a {MODEL_HEADING} section"
    );
    assert!(
        lines.next().is_some_and(is_banner),
        "{path}: the {MODEL_HEADING} heading must close with its banner"
    );
    let mut block = Vec::new();
    let mut closed = false;
    for line in lines {
        if is_banner(line) {
            closed = true;
            break;
        }
        block.push(line);
    }
    assert!(
        closed,
        "{path}: the {MODEL_HEADING} section is never closed"
    );
    assert!(
        !block.is_empty(),
        "{path}: the {MODEL_HEADING} section is empty"
    );
    block
}

/// Every `NAME="…"` assignment a runner's fixed model declares.
///
/// A set, so the comparison runs in both directions. Naming each scalar the
/// model expects would prove only that the runner still declares those; a
/// scalar the runner added, or one it re-declared further down, would be
/// invisible — and a lookup that took the first match could not have seen the
/// second declaration even if it had been asked. A duplicate is refused here
/// rather than resolved, because a runner with two answers for one name has no
/// value a model can compare.
///
/// Only double-quoted assignments are collected. Both runners hold their jq
/// programs and regular expressions in single quotes precisely so the shell
/// cannot expand them, and those are read by the rejection models rather than
/// this one.
pub fn model_scalars(path: &str, source: &str) -> BTreeMap<String, String> {
    let mut scalars = BTreeMap::new();
    for line in model_block(path, source) {
        let Some((name, rest)) = line.split_once("=\"") else {
            continue;
        };
        if !is_scalar_name(name) {
            continue;
        }
        let Some(value) = rest.strip_suffix('"') else {
            continue;
        };
        assert!(
            scalars.insert(name.to_owned(), value.to_owned()).is_none(),
            "{path} declares {name} twice in its fixed model"
        );
    }
    scalars
}

/// Whether this text is a shell scalar name a runner's model may declare.
fn is_scalar_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// The entries of a `NAME=(` … `)` array literal, one per line.
///
/// An entry spelled `${SCALAR}` resolves through `scalars`, so a model compares
/// predicate names rather than shell spellings.
pub fn array_entries(
    path: &str,
    source: &str,
    name: &str,
    scalars: &[(&str, &str)],
) -> Vec<String> {
    let opening = format!("{name}=(");
    let body = source
        .split_once(&opening)
        .unwrap_or_else(|| panic!("{path} must declare the array {name}"))
        .1;
    let body = body
        .split_once("\n)")
        .unwrap_or_else(|| panic!("{path}: the array {name} is never closed"))
        .0;
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| expand(path, line.trim_matches('"'), scalars))
        .collect()
}

/// Every `<config>|<predicates>` row of `array`, split and compared with a model.
///
/// The row is the pairing, and the pairing is the claim: a cargo configuration
/// decides what a predicate name proves, so the same name under two feature sets
/// proves two different trees. A runner that declared one array of
/// configurations beside one array of predicates stated both halves and bound
/// them nowhere — the binding lived in hardcoded call sites nothing read, and
/// deleting one stopped a whole inventory being proved while both declarations
/// survived and the model still passed.
///
/// The array is required to be expanded too. An inventory a runner declares and
/// never reads is an inventory a model can equal while the runner proves none
/// of it.
pub fn assert_registration_rows(
    path: &str,
    source: &str,
    array: &str,
    scalars: &[(&str, &str)],
    expected: &[(&str, &[&str])],
) {
    let rows = array_entries(path, source, array, scalars);
    assert_eq!(
        rows.len(),
        expected.len(),
        "{path}: {array} declares {} rows, not the modelled {}",
        rows.len(),
        expected.len()
    );
    for (found, (config, predicates)) in rows.iter().zip(expected) {
        let (declared, declared_predicates) = found
            .split_once('|')
            .unwrap_or_else(|| panic!("{path}: {found:?} is not `<config>|<predicates>`"));
        assert_eq!(
            declared, *config,
            "{path}: a registration row runs an unmodelled configuration"
        );
        assert_eq!(
            declared_predicates
                .split_whitespace()
                .collect::<Vec<&str>>(),
            *predicates,
            "{path}: {declared} must register exactly its modelled predicates"
        );
    }
    assert!(
        source.contains(&format!("${{{array}[@]}}")),
        "{path} must expand {array}; an inventory nothing reads is proved nowhere"
    );
}

/// Resolve the one `${…}` reference an array entry may hold.
fn expand(path: &str, entry: &str, scalars: &[(&str, &str)]) -> String {
    match entry.strip_prefix("${").and_then(|it| it.strip_suffix('}')) {
        Some(name) => scalars
            .iter()
            .find(|(declared, _)| *declared == name)
            .unwrap_or_else(|| panic!("{path} expands {name}, which the model omits"))
            .1
            .to_owned(),
        None => entry.to_owned(),
    }
}
