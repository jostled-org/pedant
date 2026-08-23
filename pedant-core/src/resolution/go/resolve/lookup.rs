//! Go name lookup over the definition inventory.
//!
//! A bare name is answered by the file's own scope first — the package's
//! declarations, then the packages it dot-imports — and by the universe block
//! last. A qualified name is answered by the package its qualifier binds. What
//! neither answers is missing, and what the universe answers is external:
//! `len` is declared outside every corpus, so no snapshot can hold it.

use super::imports::{FileImports, ImportTarget};
use super::index::Index;
use super::universe;

/// What a lookup found, or why it found nothing.
pub(super) enum Outcome {
    /// The corpus holds these definitions under the name.
    Found(Box<[usize]>),
    /// The name is declared outside the corpus.
    External,
    /// No package the name could come from declares it.
    Missing,
}

impl Outcome {
    /// The found definitions, or an outcome that names why there are none.
    fn of(found: Box<[usize]>, absent: Outcome) -> Self {
        match found.is_empty() {
            true => absent,
            false => Self::Found(found),
        }
    }
}

/// What one bare name denotes in the file that wrote it.
pub(super) fn bare(index: &Index, scope: (usize, &FileImports<'_>), name: &str) -> Outcome {
    let (unit, imports) = scope;
    let mut found: Vec<usize> = declared(index, unit, name).to_vec();
    for dotted in imports.dotted() {
        found.extend(pulled(index, *dotted, name));
    }
    found.sort_unstable();
    found.dedup();
    Outcome::of(found.into_boxed_slice(), absent(imports, name))
}

/// What one package-qualified name denotes.
pub(super) fn qualified(index: &Index, target: ImportTarget<'_>, name: &str) -> Outcome {
    match target.unit {
        None => Outcome::External,
        Some(unit) => Outcome::of(Box::from(declared(index, unit, name)), Outcome::Missing),
    }
}

/// Every definition one package declares under a name.
pub(super) fn declared<'a>(index: &'a Index, unit: usize, name: &str) -> &'a [usize] {
    index
        .unit(unit)
        .map(|found| found.named(name))
        .unwrap_or_default()
}

/// Every definition one dot-imported package contributes under a name.
fn pulled(index: &Index, target: ImportTarget<'_>, name: &str) -> Box<[usize]> {
    match target.unit {
        None => Box::from([]),
        Some(unit) => Box::from(declared(index, unit, name)),
    }
}

/// Why a name the corpus does not declare is not in the corpus.
///
/// A file that dot-imports a package outside the snapshot could be reading a
/// name from it, so the answer is external rather than missing: the report says
/// "not here" instead of "nowhere".
fn absent(imports: &FileImports<'_>, name: &str) -> Outcome {
    let outside = imports.dotted().iter().any(|dotted| dotted.unit.is_none());
    match universe::is_predeclared(name) || outside {
        true => Outcome::External,
        false => Outcome::Missing,
    }
}
