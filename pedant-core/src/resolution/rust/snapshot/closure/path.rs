//! Filesystem candidates and lookup directories for module declarations.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::super::error::{ClosureSite, SourceClosureFailure, SourceClosureFailureKind};
use super::super::failure::failure;
use super::super::store::SourceStore;
use super::walk::ChildContext;

/// Every directory an inline module's own `mod` items resolve from.
pub(super) fn inline_directories(context: &ChildContext<'_>) -> Box<[PathBuf]> {
    match &*context.declaration.declared_paths {
        [] => Box::from([context
            .frame
            .directory
            .join(module_file_name(&context.declaration.name))]),
        [first, rest @ ..] => declared_directories(context, (&**first, rest)),
    }
}

/// The declared directories this package actually ships, or the first
/// declared one when it ships none.
fn declared_directories(
    context: &ChildContext<'_>,
    declared: (&str, &[Arc<str>]),
) -> Box<[PathBuf]> {
    let (first, rest) = declared;
    let shipped: Box<[PathBuf]> = std::iter::once(first)
        .chain(rest.iter().map(|path| &**path))
        .map(|path| context.frame.directory.join(path))
        .filter(|directory| directory.is_dir())
        .collect();
    match shipped.is_empty() {
        true => Box::from([context.frame.directory.join(first)]),
        false => shipped,
    }
}

pub(super) fn candidate_paths(
    store: &SourceStore,
    context: &ChildContext<'_>,
    site: &ClosureSite,
) -> Result<Box<[PathBuf]>, SourceClosureFailure> {
    match &*context.declaration.declared_paths {
        [] => standard_candidate(store, context, site).map(|path| Box::from([path])),
        [declared] => {
            declared_candidate(store, context, (site, declared)).map(|path| Box::from([path]))
        }
        alternatives => declared_alternatives(store, context, (site, alternatives)),
    }
}

fn declared_candidate(
    store: &SourceStore,
    context: &ChildContext<'_>,
    request: (&ClosureSite, &str),
) -> Result<PathBuf, SourceClosureFailure> {
    let (site, declared) = request;
    let candidate = context.frame.declared_directory.join(declared);
    match candidate.is_file() {
        true => Ok(candidate),
        false => Err(missing(store, site, &candidate)),
    }
}

/// Every conditional alternative this package can reach within its root.
fn declared_alternatives(
    store: &SourceStore,
    context: &ChildContext<'_>,
    request: (&ClosureSite, &[Arc<str>]),
) -> Result<Box<[PathBuf]>, SourceClosureFailure> {
    let (site, alternatives) = request;
    let reachable: Box<[PathBuf]> = alternatives
        .iter()
        .map(|declared| context.frame.declared_directory.join(&**declared))
        .filter(|candidate| reachable_alternative(store, candidate, site))
        .collect();
    match reachable.first() {
        Some(_) => Ok(reachable),
        None => Err(missing(
            store,
            site,
            &context.frame.declared_directory.join(&*alternatives[0]),
        )),
    }
}

fn reachable_alternative(store: &SourceStore, candidate: &Path, site: &ClosureSite) -> bool {
    candidate.is_file() && store.canonical_inside(candidate, site).is_ok()
}

fn standard_candidate(
    store: &SourceStore,
    context: &ChildContext<'_>,
    site: &ClosureSite,
) -> Result<PathBuf, SourceClosureFailure> {
    let name = module_file_name(&context.declaration.name);
    let flat = context.frame.directory.join(format!("{name}.rs"));
    let nested = context.frame.directory.join(name).join("mod.rs");
    match (flat.is_file(), nested.is_file()) {
        (true, true) => Err(ambiguous(store, site, &flat)),
        (true, false) => Ok(flat),
        (false, true) => Ok(nested),
        (false, false) => Err(missing(store, site, &flat)),
    }
}

fn missing(store: &SourceStore, site: &ClosureSite, attempted: &Path) -> SourceClosureFailure {
    failure(
        SourceClosureFailureKind::MissingModule,
        (site, store.relative_of(attempted)),
        format!("{site}: no source exists for the declared module"),
    )
}

fn ambiguous(store: &SourceStore, site: &ClosureSite, attempted: &Path) -> SourceClosureFailure {
    failure(
        SourceClosureFailureKind::AmbiguousModule,
        (site, store.relative_of(attempted)),
        format!("{site}: both name.rs and name/mod.rs exist"),
    )
}

/// The directory a source file lives in.
pub(super) fn file_directory(file: &Path) -> PathBuf {
    file.parent().map(Path::to_path_buf).unwrap_or_default()
}

/// The directory a module's external children are looked up in.
pub(super) fn child_directory(file: &Path, crate_root: bool) -> PathBuf {
    let parent = file_directory(file);
    let stem = file.file_stem().and_then(OsStr::to_str).unwrap_or_default();
    match crate_root || stem == "mod" {
        true => parent,
        false => parent.join(stem),
    }
}

/// Strip the raw-identifier prefix that is syntax rather than a file name.
fn module_file_name(name: &str) -> &str {
    name.strip_prefix("r#").unwrap_or(name)
}
