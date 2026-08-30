//! What a `--exact` filter selects, and where a predicate is declared.
//!
//! `--exact` matches the whole libtest name, and that name is the module path
//! the test executable registers the function under. A written filter is
//! therefore a selection only while every segment of it resolves through
//! declarations the target root actually makes. When one stops resolving nothing
//! fails: cargo prints `0 filtered out`, exits 0, and whatever read that exit
//! status reports a predicate that never ran.
//!
//! Shared rather than copied. The Go registration case asks where a predicate is
//! declared, and the code-intelligence hosted-filter case asks whether a written
//! filter reaches it; the second is the first plus a module walk, and two
//! implementations would let one go on selecting after the other stopped.
//!
//! Reads tracked text and runs nothing, so every configuration can prove it.
//!
//! Two written forms are deliberately not read, and both refuse rather than
//! pass: an attribute and its `mod` on one line, and an attribute spread over
//! several. This repository writes neither, and a walk that guessed at them
//! would be guessing about the one thing the caller needs to be exact.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::resolution::authority_scan::{Source, read_text};
use crate::resolution::comment_scan::{CodeLine, code_index};
use crate::resolution::module_scan::{Candidate, declarations_of};
use crate::resolution::production_tree::{nested_sources, tree_relative};
use crate::resolution::root_inventory::{INTEGRATION_ROOTS, workspace_members, workspace_root};

/// How few sources mean the workspace test scan is not reading the tree.
const MINIMUM_TEST_SOURCES: usize = 100;

/// One conditional standing between a target root and a declaration.
///
/// Reported rather than judged. Whether a gate is open is a question about the
/// feature profile a filter runs under, which this walk does not know and its
/// caller does.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Gate {
    /// A row of a `complete_profile*` macro, whose feature list is written in
    /// one place the caller can read.
    Profile,
    /// A `#[cfg(...)]` attribute, kept whole so its caller can price it against
    /// the profile the filter runs under.
    Cfg(Box<str>),
}

/// One resolved filter.
pub(crate) struct Selection {
    /// The file that declares the selected predicate, relative to the root the
    /// walk started from.
    pub(crate) file: Box<str>,
    /// The predicate the filter's last segment names, which is the function
    /// libtest registers.
    ///
    /// Carried rather than re-derived. The walk has already split the filter on
    /// `::` to resolve it, and a caller that split it again to reach the leaf
    /// was a second reading of the one thing this walk is for.
    pub(crate) leaf: Box<str>,
    /// Each gate a segment of the path was declared behind, in walk order.
    pub(crate) gates: Box<[Gate]>,
}

/// The file one `--exact` filter selects a registered test from, or why it
/// selects nothing.
///
/// `root` is the tree the walk starts in — the workspace for a live claim, a
/// fixture for a refusal row — and `target_root` is the cargo test executable's
/// source file inside it.
pub(crate) fn filter_selection(
    root: &Path,
    target_root: &str,
    filter: &str,
) -> Result<Selection, String> {
    let segments: Box<[&str]> = filter.split("::").collect();
    let (leaf, modules) = segments
        .split_last()
        .ok_or_else(|| format!("{filter} names no predicate"))?;
    let mut file = root.join(target_root);
    let mut gates: Vec<Gate> = Vec::new();
    let mut is_root = true;
    for module in modules {
        let child = declared_child(&file, module, is_root)?;
        gates.extend(child.gate);
        file = child.file;
        is_root = false;
    }
    let text = read_file(&file)?;
    let relative = tree_relative(root, &file);
    let declarations = registered_declarations(&text, leaf);
    match &*declarations {
        [only] => {
            gates.extend(only.iter().cloned());
            Ok(Selection {
                file: relative.into(),
                leaf: (*leaf).into(),
                gates: gates.into_boxed_slice(),
            })
        }
        [] => Err(format!(
            "{relative} registers no test named {leaf}, so an exact filter naming it selects nothing"
        )),
        many => Err(format!("{relative} declares {leaf} {} times", many.len())),
    }
}

/// Every tracked test file that declares one predicate, once per declaration.
///
/// Once per declaration rather than once per file, because two copies inside one
/// support module are the same duplicate as two copies across two roots, and a
/// set would report them as one.
///
/// A declaration is read from a code line by [`declares_function`], which is
/// also how the filter walk above reads one. This used to count `fn NAME(`
/// across the raw text, so a fixture literal — `"fn main() {}"`, `"fn broken( {"`
/// — and a doc comment naming the predicate each counted as a site. The trees it
/// runs over are full of both, so three "declared exactly once in the whole
/// workspace" claims were decided by prose, and any short predicate name would
/// have broken them outright.
pub(crate) fn declaration_sites<'read>(sources: &'read [Source], name: &str) -> Box<[&'read str]> {
    let signature = declaration_signature(name);
    sources
        .iter()
        .flat_map(|source| {
            std::iter::repeat_n(&*source.path, declarations_in(&source.path, &signature))
        })
        .collect()
}

/// How many code lines of one tracked test source open with `signature`.
fn declarations_in(path: &str, signature: &str) -> usize {
    test_source_code()
        .get(path)
        .unwrap_or_else(|| panic!("{path} is not one of the tracked test sources this walk read"))
        .iter()
        .filter(|(_, line)| declares_function(line, signature))
        .count()
}

/// Every tracked test source's code lines, comments removed, keyed by path and
/// read once for the process.
///
/// Derived from [`workspace_test_sources`] rather than from the slice a caller
/// hands in, and keyed by path so a source this reading never saw refuses
/// instead of answering from a universe it does not cover. Read once for the
/// same reason the sources themselves are: eighty-odd rows ask where a
/// predicate is declared, and the comment strip is four megabytes of the answer
/// each of them would otherwise pay for.
fn test_source_code() -> &'static BTreeMap<&'static str, Box<[CodeLine]>> {
    static CODE: OnceLock<BTreeMap<&'static str, Box<[CodeLine]>>> = OnceLock::new();
    CODE.get_or_init(|| {
        workspace_test_sources()
            .iter()
            .map(|source| (&*source.path, code_index(&source.text)))
            .collect()
    })
}

/// Every `.rs` file beneath every workspace member's `tests/` directory, read
/// once, as its repository-relative path and its text.
///
/// Read once per process rather than once per caller: five hundred sources is a
/// walk two registration claims would otherwise each pay for, and the answer
/// does not change between them.
pub(crate) fn workspace_test_sources() -> &'static [Source] {
    static SOURCES: OnceLock<Box<[Source]>> = OnceLock::new();
    SOURCES.get_or_init(scan_workspace_test_sources)
}

fn scan_workspace_test_sources() -> Box<[Source]> {
    let root = workspace_root();
    let owed = members_owing_a_tests_tree();
    let mut sources: Vec<Source> = Vec::new();
    let mut answered: BTreeSet<&str> = BTreeSet::new();
    for member in workspace_members(&root) {
        let tests = root.join(&member).join("tests");
        // A member with no integration root carries no `tests/` directory, and
        // that is a shape. A member the root inventory names and whose `tests/`
        // this cannot enter is the other fact, and `is_dir` answers false to
        // both — so one unreadable tree used to narrow the Go registration
        // claim, the lifecycle boundary, and the hosted-filter claim at once,
        // with only a workspace-wide floor between it and a silent pass.
        let held = match (tests.is_dir(), owed.contains(member.as_str())) {
            (true, _) => nested_sources(&tests),
            (false, false) => Default::default(),
            (false, true) => panic!("{member} declares an integration root and no readable tests/"),
        };
        answered.extend(owed.get(member.as_str()));
        sources.extend(held.into_iter().map(|path| {
            let relative = format!("{member}/tests/{path}");
            let text = read_text(&relative);
            Source {
                path: relative.into_boxed_str(),
                text: text.into_boxed_str(),
            }
        }));
    }
    assert_eq!(
        answered, owed,
        "every member the root inventory names must be a workspace member this scan reached"
    );
    assert!(
        sources.len() >= MINIMUM_TEST_SOURCES,
        "the workspace test scan found {} sources, so it is not reading the tree",
        sources.len()
    );
    sources.into_boxed_slice()
}

/// Every member the root inventory says holds an integration executable.
///
/// Its `tests/` tree is not optional: the roots named there are the universe
/// three separate registration claims are made over, and a member that dropped
/// out of this reading narrowed all three at once.
fn members_owing_a_tests_tree() -> BTreeSet<&'static str> {
    INTEGRATION_ROOTS
        .iter()
        .copied()
        .map(|root| beneath_tests(root, "an integration root").0)
        .collect()
}

/// One path split into the member that owns it and its path inside that
/// member's `tests/` tree.
///
/// Published beside the source reading it belongs to, because both readers of
/// this split feed the same integration-root inventory: the walk above asks it
/// of a modelled root, and the completed-product inventory asks it of a scanned
/// source. Two copies were two spellings of one refusal.
///
/// The subject noun is the caller's for that reason — a failure has to name
/// what it was reading, and a helper that hid the noun in its own name could
/// not be given a third caller.
pub(crate) fn beneath_tests<'path>(path: &'path str, subject: &str) -> (&'path str, &'path str) {
    path.split_once("/tests/")
        .unwrap_or_else(|| panic!("{path} is {subject} outside every tests directory"))
}

/// One child module a declaring file names.
struct Child {
    file: PathBuf,
    gate: Option<Gate>,
}

/// The file one declaring file gives to one child module.
fn declared_child(declaring: &Path, module: &str, is_root: bool) -> Result<Child, String> {
    let text = read_file(declaring)?;
    let candidates = declarations_of(&text, module);
    let candidate = match &*candidates {
        [only] => only,
        [] => {
            return Err(format!(
                "{} declares no module {module}, so a filter naming it selects nothing",
                declaring.display()
            ));
        }
        many => {
            return Err(format!(
                "{} declares the module {module} {} times",
                declaring.display(),
                many.len()
            ));
        }
    };
    Ok(Child {
        file: candidate_file(declaring, is_root, module, candidate)?,
        gate: candidate.gate.clone(),
    })
}

/// Where one declaration's module actually sits on disk.
fn candidate_file(
    declaring: &Path,
    is_root: bool,
    module: &str,
    candidate: &Candidate,
) -> Result<PathBuf, String> {
    let directory = parent_of(declaring)?;
    let base = module_directory(declaring, is_root)?;
    let places: Box<[PathBuf]> = match &candidate.path {
        Some(path) => Box::new([directory.join(&**path)]),
        None => Box::new([
            base.join(format!("{module}.rs")),
            base.join(module).join("mod.rs"),
        ]),
    };
    places
        .iter()
        .find(|place| place.is_file())
        .cloned()
        .ok_or_else(|| {
            format!(
                "{} declares {module}, and no file backs it: {places:?}",
                declaring.display()
            )
        })
}

/// The directory a declaring file resolves its unqualified child modules in.
///
/// A crate root and a `mod.rs` own the directory they sit in; every other module
/// owns the directory named after it.
fn module_directory(declaring: &Path, is_root: bool) -> Result<PathBuf, String> {
    let parent = parent_of(declaring)?;
    let stem = declaring
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has no readable file name", declaring.display()))?;
    let owns_its_directory = is_root || declaring.file_name().is_some_and(|name| name == "mod.rs");
    match owns_its_directory {
        true => Ok(parent),
        false => Ok(parent.join(stem)),
    }
}

fn parent_of(path: &Path) -> Result<PathBuf, String> {
    path.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("{} sits in no directory", path.display()))
}

/// Every declaration of one name libtest would register, with the conditionals
/// written over each.
///
/// A declaration is registered when a test attribute stands over it. Whether the
/// conditionals beside that attribute are satisfied is the caller's question: a
/// predicate behind a feature the run line selects is live, and the same
/// predicate behind one it does not is as unselectable as a renamed module —
/// and reports the same success.
fn registered_declarations(text: &str, leaf: &str) -> Box<[Box<[Gate]>]> {
    let signature = declaration_signature(leaf);
    let lines: Box<[&str]> = text.lines().map(str::trim).collect();
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| declares_function(line, &signature))
        .filter_map(|(index, _)| registered_gates(&lines[..index]))
        .collect()
}

/// The text a declaration of one predicate opens with.
///
/// Built once per reading, never once per line. Both walks below test every
/// code line of every tracked test source against a fixed name, and formatting
/// the name inside the filter turned one question about eighty predicates into
/// several million allocations.
fn declaration_signature(leaf: &str) -> Box<str> {
    format!("fn {leaf}(").into_boxed_str()
}

/// Whether one line opens a declaration matching `signature`, in any
/// visibility, at any indentation.
///
/// The indentation is stripped here rather than by each caller. The filter walk
/// reads trimmed lines and the site count reads the code index, which keeps a
/// line's leading whitespace so a failure can quote it — so one predicate was
/// asked of two line shapes, and a declaration one level inside a module
/// counted for the walk and not for the count. That is the silent half: a
/// second copy of a predicate written inside a `mod` left the "declared exactly
/// once in the whole workspace" claims reading one site and passing.
fn declares_function(line: &str, signature: &str) -> bool {
    line.trim_start()
        .trim_start_matches("pub(crate) ")
        .trim_start_matches("pub ")
        .trim_start_matches("async ")
        .starts_with(signature)
}

/// The conditionals over one declaration, when a test attribute registers it.
///
/// The attribute block is every attribute and comment line directly above the
/// declaration. An attribute written across several lines closes the block early
/// and leaves the declaration unregistered, which is a loud refusal rather than
/// a quiet pass; this workspace writes none.
fn registered_gates(preceding: &[&str]) -> Option<Box<[Gate]>> {
    let attributes: Box<[&str]> = preceding
        .iter()
        .rev()
        .take_while(|line| line.starts_with('#') || line.starts_with("//"))
        .copied()
        .collect();
    let registered = attributes.iter().any(|line| is_test_attribute(line));
    registered.then(|| {
        attributes
            .iter()
            .filter(|line| line.starts_with("#[cfg("))
            .map(|line| Gate::Cfg((*line).into()))
            .collect()
    })
}

/// Whether one attribute is a test attribute, however its path is spelled.
///
/// `#[test]` and `#[tokio::test]` both register a row, and both are written in
/// this workspace. `#[cfg(test)]` does not, and names `test` in a position this
/// must not read as one.
fn is_test_attribute(line: &str) -> bool {
    line.strip_prefix("#[")
        .and_then(|rest| rest.strip_suffix(']'))
        .map(|body| body.split('(').next().unwrap_or(body))
        .map(|path| path.rsplit("::").next().unwrap_or(path) == "test")
        .unwrap_or(false)
}

fn read_file(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}
