//! The production module universe, discovered from `lib.rs` and parsed once.
//!
//! Every claim above is asked of this closure, so the closure is what holds the
//! trees: a source read here is read once, and the tree that answered "what does
//! this file declare" is the same one every later question is asked of.

use std::path::{Path, PathBuf};

use super::modules::{declared_modules, resolve_module};
use super::scan::SourceScan;

/// One discovered production source: what it is called, its syntax tree, and
/// what that tree names.
///
/// The tree is held rather than the path, because every question below is asked
/// of the tree and re-reading the file to ask another one would be a second
/// parse of the same subject.
pub(super) struct Member {
    pub(super) label: Box<str>,
    pub(super) file: syn::File,
    pub(super) scan: SourceScan,
}

impl Member {
    fn new(path: &Path, file: syn::File) -> Self {
        let scan = SourceScan::of_file(&file);
        let label = relative_to_source(path).into_boxed_str();
        Self { label, file, scan }
    }
}

/// The member with one label, or a failure naming it.
pub(super) fn member<'closure>(closure: &'closure [Member], label: &str) -> &'closure Member {
    closure
        .iter()
        .find(|member| &*member.label == label)
        .unwrap_or_else(|| panic!("{label} should be part of the discovered closure"))
}

/// Every member whose label opens with `prefix`.
///
/// The sibling of [`member`], for a claim about one owner family rather than one
/// owner: a second descent, a second insertion, or a second check would hide in
/// some module of the family, so the family is asked as a set. Beside `member`
/// because both answer from the same discovered closure.
#[cfg(feature = "ts-go")]
pub(super) fn members_under<'closure>(
    closure: &'closure [Member],
    prefix: &str,
) -> Box<[&'closure Member]> {
    closure
        .iter()
        .filter(|member| member.label.starts_with(prefix))
        .collect()
}

/// Every production source `lib.rs` reaches, by resolving `mod` declarations.
///
/// Each source is read and parsed exactly once: the tree that answers "what
/// does this file declare" is the same one every later claim is asked of.
///
/// A declaration that names no file is a refusal, not a skip: an unresolved
/// module would silently drop whatever it holds out of every scan below.
pub(super) fn discover_closure() -> Box<[Member]> {
    let mut discovered: Vec<(PathBuf, syn::File)> = Vec::new();
    let mut pending = vec![crate_path("src").join("lib.rs")];
    while let Some(path) = pending.pop() {
        if discovered.iter().any(|(held, _)| *held == path) {
            continue;
        }
        let file = parse_rust_file(&path);
        for name in declared_modules(&file).iter() {
            let child = resolve_module(&path, name)
                .unwrap_or_else(|| panic!("`mod {name};` in {} names no file", path.display()));
            pending.push(child);
        }
        discovered.push((path, file));
    }
    discovered.sort_by(|(left, _), (right, _)| left.cmp(right));
    discovered
        .into_iter()
        .map(|(path, file)| Member::new(&path, file))
        .collect()
}

/// This crate's own directory, joined with `part`.
pub(super) fn crate_path(part: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(part)
}

pub(super) fn parse_rust_file(path: &Path) -> syn::File {
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
