//! Which child modules one Rust source declares, and how.
//!
//! Split from [`super::test_identity`] for the source-file budget alone, the way
//! `fingerprint_claims` sits beside `fingerprint`. That file asks what a filter
//! selects; this one answers the single question it asks of each declaring file.
//!
//! Four written forms are read, because this workspace writes four: a plain
//! `mod name;` in any visibility, a `#[path = "..."]` attribute above one, and
//! the two `complete_profile*` macros a test root declares its gated support
//! modules through. Anything else is no declaration, which refuses upstream
//! rather than resolving to a guess.
//!
//! The per-line classification is published, not private. A second reader of
//! the same four forms — the repository inventory asks which support modules a
//! root declares, where this asks where one of them resolves — is the drift this
//! module was split out to prevent, and it can only be prevented by being
//! callable.

use crate::resolution::test_identity::Gate;

/// The macro a test root declares gated support modules through by path.
const GATED_PATH_MACRO: &str = "complete_profile_path_modules!(";

/// The macro a support module declares gated sibling modules through by name.
const GATED_NAME_MACRO: &str = "complete_profile_modules!(";

/// One declaration of a child module, before its file is resolved.
#[derive(Default)]
pub(crate) struct Candidate {
    /// The path an attribute or a gated row named, when either did.
    pub(crate) path: Option<Box<str>>,
    /// The conditional the declaration stood behind, when it stood behind one.
    pub(crate) gate: Option<Gate>,
}

/// Which gated block a line opens, when it opens one.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Block {
    /// Outside every gated block.
    None,
    /// Inside `complete_profile_path_modules!`, whose rows name a path.
    GatedPath,
    /// Inside `complete_profile_modules!`, whose rows name a module.
    GatedName,
}

/// What one line of a declaring file says about a module declaration.
pub(crate) enum Line<'read> {
    /// A gated block opens here.
    Opens(Block),
    /// The line closing whichever block is open.
    Closes,
    /// `#[path = "..."]`, which the next `mod` line consumes.
    Path(&'read str),
    /// `#[cfg(...)]`, carried whole, which the next `mod` line stands behind.
    Conditional(Gate),
    /// `mod name;`, in any visibility.
    Declares(&'read str),
    /// `"..." => name,`, one row of the gated path macro: the module it names,
    /// and the declaration it would contribute inside that block.
    GatedPathRow(&'read str, Candidate),
    /// `name,`, one row of the gated name macro, in the same two parts.
    GatedNameRow(&'read str, Candidate),
    /// Anything else, including every doc comment and every other attribute.
    Other,
}

/// Every declaration one file makes of one child module.
///
/// Both gated forms are read as well as the attribute, because the macros expand
/// to the attribute under a feature gate: a walk that read only the attribute
/// would stop resolving the moment a root moved a module behind that gate, and
/// would report a filter as unselectable while cargo still selected it.
///
/// An attribute reaches only the declaration directly beneath it. Every other
/// line clears the pending path and conditional, so a `cfg` written over one
/// item is never charged to a `mod` further down the file. The two block lines
/// clear it as well: a line beginning with `)` is the commonest way a multi-line
/// item ends, and leaving the pending conditional standing over it charged a
/// `cfg` to whatever `mod` came next — reporting a gate the caller then had to
/// price against a profile it was never written under.
pub(crate) fn declarations_of(text: &str, module: &str) -> Box<[Candidate]> {
    let mut found: Vec<Candidate> = Vec::new();
    let mut block = Block::None;
    let mut pending = Candidate::default();
    for line in text.lines().map(str::trim) {
        match (block, classify(line)) {
            (Block::None, Line::Opens(opened)) => {
                block = opened;
                pending = Candidate::default();
            }
            (_, Line::Closes) => {
                block = Block::None;
                pending = Candidate::default();
            }
            (Block::None, Line::Path(path)) => pending.path = Some(path.into()),
            (Block::None, Line::Conditional(gate)) => pending.gate = Some(gate),
            (Block::None, Line::Declares(name)) => {
                found.extend(matching(name, module, std::mem::take(&mut pending)));
            }
            (Block::GatedPath, Line::GatedPathRow(name, row)) => {
                found.extend(matching(name, module, row));
            }
            (Block::GatedName, Line::GatedNameRow(name, row)) => {
                found.extend(matching(name, module, row));
            }
            _ => pending = Candidate::default(),
        }
    }
    found.into_boxed_slice()
}

/// The candidate a row contributes, when the row names the module being walked.
fn matching(name: &str, module: &str, candidate: Candidate) -> Option<Candidate> {
    (name == module).then_some(candidate)
}

/// What one trimmed line of a declaring file says about a module declaration.
pub(crate) fn classify(line: &str) -> Line<'_> {
    if line.starts_with(GATED_PATH_MACRO) {
        return Line::Opens(Block::GatedPath);
    }
    if line.starts_with(GATED_NAME_MACRO) {
        return Line::Opens(Block::GatedName);
    }
    if line.starts_with(')') {
        return Line::Closes;
    }
    if let Some(path) = path_attribute(line) {
        return Line::Path(path);
    }
    if line.starts_with("#[cfg(") {
        return Line::Conditional(Gate::Cfg(line.into()));
    }
    if let Some(name) = declared_module(line) {
        return Line::Declares(name);
    }
    if let Some((path, name)) = gated_path_row(line) {
        return Line::GatedPathRow(
            name,
            Candidate {
                path: Some(path.into()),
                gate: Some(Gate::Profile),
            },
        );
    }
    if let Some(name) = gated_name_row(line) {
        return Line::GatedNameRow(
            name,
            Candidate {
                path: None,
                gate: Some(Gate::Profile),
            },
        );
    }
    Line::Other
}

/// The path one `#[path = "..."]` attribute names.
fn path_attribute(line: &str) -> Option<&str> {
    line.strip_prefix("#[path = \"")?.split('"').next()
}

/// The module one `mod name;` line declares, in any visibility.
fn declared_module(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("pub(crate) mod ")
        .or_else(|| line.strip_prefix("pub mod "))
        .or_else(|| line.strip_prefix("mod "))?;
    let name = rest.strip_suffix(';')?;
    is_identifier(name).then_some(name)
}

/// The path and module one `"..." => name,` row names.
fn gated_path_row(line: &str) -> Option<(&str, &str)> {
    let (path, tail) = line.strip_prefix('"')?.split_once("\" => ")?;
    let name = tail.strip_suffix(',')?;
    is_identifier(name).then_some((path, name))
}

/// The module one `name,` row names.
fn gated_name_row(line: &str) -> Option<&str> {
    let name = line.strip_suffix(',')?;
    is_identifier(name).then_some(name)
}

fn is_identifier(name: &str) -> bool {
    let first = name.chars().next();
    first.is_some_and(|start| start.is_ascii_alphabetic() || start == '_')
        && name
            .chars()
            .all(|it| it.is_ascii_alphanumeric() || it == '_')
}
