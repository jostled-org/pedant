//! How one directory's sources become up to three package units.
//!
//! Go compiles a directory's non-test sources, then those sources together with
//! the same-package `_test.go` sources, then the `_test.go` sources declaring
//! the external test package. A source two of those contexts hold is stored
//! once and named by both, exactly as a Rust source shared by two targets is.
//! A clause that fits none of the three is refused: guessing which package a
//! stray file belongs to would publish a report about a build Go would reject.

use std::path::Path;
use std::sync::Arc;

use crate::resolution::supply::SourceSupply;

use super::condition::is_test_source;
use super::discovery::GoPackageDirectory;
use super::fault::GoSourceFault;
use super::inventory::GoFileInventory;
use super::paths::file_name;
use super::snapshot_error::GoSnapshotError;
use super::store::GoSourceStore;
use super::unit::GoPackageContext;

/// The suffix an external test package's clause adds to its directory's
/// package name.
const EXTERNAL_SUFFIX: &str = "_test";

/// Where one directory sits, before the snapshot mints the identities it names.
pub(super) struct PackageSite<'a> {
    /// The canonical repository root every path is named against.
    pub(super) root: &'a Path,
    /// The project-local index of the module whose tree holds the directory.
    pub(super) module: u32,
    /// That module's declared path, which opens every import path beneath it.
    pub(super) module_path: &'a Arc<str>,
}

/// One package unit, before the snapshot mints its identity.
pub(super) struct UnitDraft {
    pub(super) module: u32,
    pub(super) context: GoPackageContext,
    pub(super) import_path: Arc<str>,
    pub(super) package_name: Box<str>,
    pub(super) directory: Arc<str>,
    pub(super) sources: Box<[Arc<str>]>,
}

/// One admitted source and the context its package clause puts it in.
struct ClassifiedSource {
    path: Arc<str>,
    package: Box<str>,
    test: bool,
}

/// Every unit one package directory states, in context order.
pub(super) fn directory_units<P: SourceSupply<GoFileInventory, GoSourceFault>>(
    store: &mut GoSourceStore,
    provider: &mut P,
    site: &PackageSite<'_>,
    directory: &GoPackageDirectory,
) -> Result<Box<[UnitDraft]>, GoSnapshotError> {
    let relative = super::paths::relative_shared(site.root, &directory.canonical)?;
    let classified = classify(store, provider, directory)?;
    let package = declared_package(&classified, &relative)?;
    let contexts = assign_contexts(&classified, &package, &relative)?;
    let import_path = import_path(site.module_path, &directory.within_module);
    Ok(drafts(
        site,
        &Placement {
            import_path,
            package,
            directory: relative,
        },
        (&classified, &contexts),
    ))
}

/// Where one directory's units sit, stated once for all three contexts.
struct Placement {
    import_path: Arc<str>,
    package: Box<str>,
    directory: Arc<str>,
}

/// Read every source the directory admits and record the clause it declares.
///
/// The store answers with the position it retained each source at, so the
/// clause is read directly from that position.
fn classify<P: SourceSupply<GoFileInventory, GoSourceFault>>(
    store: &mut GoSourceStore,
    provider: &mut P,
    directory: &GoPackageDirectory,
) -> Result<Box<[ClassifiedSource]>, GoSnapshotError> {
    let mut classified = Vec::with_capacity(directory.sources.len());
    for source in directory.sources.iter() {
        let (path, index) = store.intern(provider, source)?;
        let package =
            store
                .package_name_at(index)
                .ok_or_else(|| GoSnapshotError::MissingStoredSource {
                    path: Box::from(&*path),
                })?;
        classified.push(ClassifiedSource {
            test: is_test_source(file_name(&path)),
            package: Box::from(package),
            path,
        });
    }
    Ok(classified.into_boxed_slice())
}

/// The package name one directory declares.
///
/// A directory's non-test sources name it. A directory holding only test
/// sources still names one: either a same-package test file states it directly,
/// or the external test clause states it with the suffix removed.
fn declared_package(
    classified: &[ClassifiedSource],
    directory: &str,
) -> Result<Box<str>, GoSnapshotError> {
    let production = classified
        .iter()
        .find(|source| !source.test)
        .map(|source| Box::from(&*source.package));
    production
        .or_else(|| internal_package(classified))
        .or_else(|| suffixless_package(classified))
        .ok_or_else(|| GoSnapshotError::MissingPackageClause {
            path: Box::from(directory),
        })
}

/// The name a same-package test file states directly.
fn internal_package(classified: &[ClassifiedSource]) -> Option<Box<str>> {
    classified
        .iter()
        .find(|source| source.test && !source.package.ends_with(EXTERNAL_SUFFIX))
        .map(|source| Box::from(&*source.package))
}

/// The name an external test clause states, with its suffix removed.
fn suffixless_package(classified: &[ClassifiedSource]) -> Option<Box<str>> {
    classified
        .iter()
        .filter(|source| source.test)
        .find_map(|source| source.package.strip_suffix(EXTERNAL_SUFFIX).map(Box::from))
}

/// The context every classified source belongs to, or the clause that fits
/// none.
fn assign_contexts(
    classified: &[ClassifiedSource],
    package: &str,
    directory: &str,
) -> Result<Box<[GoPackageContext]>, GoSnapshotError> {
    let mut contexts = Vec::with_capacity(classified.len());
    for source in classified {
        let context = context_of(source, package).ok_or_else(|| {
            GoSnapshotError::ConflictingPackageClause {
                directory: Box::from(directory),
                first: Box::from(package),
                second: Box::from(&*source.package),
            }
        })?;
        contexts.push(context);
    }
    Ok(contexts.into_boxed_slice())
}

/// Which context one source's clause puts it in, if any does.
fn context_of(source: &ClassifiedSource, package: &str) -> Option<GoPackageContext> {
    match (source.test, &*source.package == package) {
        (false, true) => Some(GoPackageContext::Production),
        (true, true) => Some(GoPackageContext::InternalTest),
        (true, false) => source
            .package
            .strip_suffix(EXTERNAL_SUFFIX)
            .filter(|base| *base == package)
            .map(|_| GoPackageContext::ExternalTest),
        (false, false) => None,
    }
}

/// The units one classified directory states, each with the sources Go would
/// compile it from.
fn drafts(
    site: &PackageSite<'_>,
    placement: &Placement,
    assigned: (&[ClassifiedSource], &[GoPackageContext]),
) -> Box<[UnitDraft]> {
    let (_, contexts) = assigned;
    [
        GoPackageContext::Production,
        GoPackageContext::InternalTest,
        GoPackageContext::ExternalTest,
    ]
    .into_iter()
    .filter(|context| contexts.contains(context))
    .map(|context| {
        let sources = selected(assigned, compiled_by(context));
        draft(site, placement, (context, sources))
    })
    .collect()
}

/// Which contexts' sources Go compiles one unit from.
///
/// Asked only for a context the directory states, so a directory with no test
/// files never selects and sorts the sources of the two test units it does not
/// have.
fn compiled_by(context: GoPackageContext) -> &'static [GoPackageContext] {
    match context {
        GoPackageContext::Production => &[GoPackageContext::Production],
        GoPackageContext::InternalTest => {
            &[GoPackageContext::Production, GoPackageContext::InternalTest]
        }
        GoPackageContext::ExternalTest => &[GoPackageContext::ExternalTest],
    }
}

/// One unit, named against its module and directory.
fn draft(
    site: &PackageSite<'_>,
    placement: &Placement,
    unit: (GoPackageContext, Box<[Arc<str>]>),
) -> UnitDraft {
    let (context, sources) = unit;
    UnitDraft {
        module: site.module,
        context,
        import_path: Arc::clone(&placement.import_path),
        package_name: external_package(&placement.package, context),
        directory: Arc::clone(&placement.directory),
        sources,
    }
}

/// The clause one context's sources declare.
fn external_package(package: &str, context: GoPackageContext) -> Box<str> {
    match context {
        GoPackageContext::ExternalTest => format!("{package}{EXTERNAL_SUFFIX}").into_boxed_str(),
        GoPackageContext::Production | GoPackageContext::InternalTest => Box::from(package),
    }
}

/// The sorted sources whose contexts are among `wanted`.
fn selected(
    assigned: (&[ClassifiedSource], &[GoPackageContext]),
    wanted: &[GoPackageContext],
) -> Box<[Arc<str>]> {
    let (classified, contexts) = assigned;
    let mut sources: Vec<Arc<str>> = classified
        .iter()
        .zip(contexts)
        .filter(|(_, context)| wanted.contains(context))
        .map(|(source, _)| Arc::clone(&source.path))
        .collect();
    sources.sort();
    sources.into_boxed_slice()
}

/// The import path one directory has inside its module.
fn import_path(module: &Arc<str>, within: &str) -> Arc<str> {
    match within.is_empty() {
        true => Arc::clone(module),
        false => Arc::from(format!("{module}/{within}")),
    }
}
