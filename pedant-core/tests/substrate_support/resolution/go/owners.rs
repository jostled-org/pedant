//! The written-down inventory of Go project production owners.
//!
//! The set is stated, never discovered: a discovered set agrees with whatever
//! the tree happens to contain, so it could not reject a module that appeared
//! beside the loader and read outside the root. The comparison below runs the
//! other way too — a file on disk that this list does not name fails the same
//! assertion.

use std::path::{Path, PathBuf};

use crate::declaration_scan::crate_path;
use crate::resolution::production_tree::assert_directory_holds_exactly;

/// Every module of the Go resolution surface, relative to `src/resolution/go`.
pub const GO_MODULES: &[&str] = &[
    "binding_fact.rs",
    "condition.rs",
    "declaration_fact.rs",
    "directive.rs",
    "discovery.rs",
    "error.rs",
    "exclusion.rs",
    "facts.rs",
    "fault.rs",
    "fingerprint.rs",
    "identity.rs",
    "import_fact.rs",
    "inventory.rs",
    "limits.rs",
    "load.rs",
    "manifest.rs",
    "mod.rs",
    "module.rs",
    "packages.rs",
    "paths.rs",
    "project.rs",
    "provider.rs",
    "reference_fact.rs",
    "replacement.rs",
    "requirement.rs",
    "signature_fact.rs",
    "snapshot.rs",
    "snapshot_error.rs",
    "snapshot_module.rs",
    "source.rs",
    "store.rs",
    "test_support.rs",
    "unit.rs",
    "unit_table.rs",
    "written_type_fact.rs",
];

/// Every module of the Go resolution stage, relative to `src/resolution/go`.
///
/// A directory of its own, because the loader and the snapshot answer what a
/// repository holds while these answer what its names denote, and only the
/// second set may read a report vocabulary.
pub const RESOLVE_MODULES: &[&str] = &[
    "resolve/answer.rs",
    "resolve/corpus.rs",
    "resolve/definitions.rs",
    "resolve/denotation.rs",
    "resolve/dispatch.rs",
    "resolve/error.rs",
    "resolve/implementations.rs",
    "resolve/imports.rs",
    "resolve/index.rs",
    "resolve/interfaces.rs",
    "resolve/lookup.rs",
    "resolve/methods.rs",
    "resolve/mod.rs",
    "resolve/pipeline.rs",
    "resolve/records.rs",
    "resolve/references.rs",
    "resolve/relations.rs",
    "resolve/resolver.rs",
    "resolve/scopes.rs",
    "resolve/signatures.rs",
    "resolve/target.rs",
    "resolve/types.rs",
    "resolve/universe.rs",
];

/// The subdirectories `src/resolution/go` holds, so the exactness check counts
/// them beside the files rather than reporting them as absent owners.
const GO_DIRECTORIES: &[&str] = &["resolve"];

/// The Go modules the snapshot stage owns, relative to `src/resolution/go`.
///
/// A subset of [`GO_MODULES`], because a claim about what a snapshot may do has
/// to exclude the loader: the project stage opens manifests, and a single-site
/// claim over the whole surface would report that read as the snapshot's.
pub const SNAPSHOT_MODULES: &[&str] = &[
    "binding_fact.rs",
    "condition.rs",
    "declaration_fact.rs",
    "discovery.rs",
    "facts.rs",
    "fault.rs",
    "fingerprint.rs",
    "import_fact.rs",
    "inventory.rs",
    "packages.rs",
    "provider.rs",
    "reference_fact.rs",
    "signature_fact.rs",
    "snapshot.rs",
    "snapshot_error.rs",
    "snapshot_module.rs",
    "source.rs",
    "store.rs",
    "test_support.rs",
    "unit.rs",
    "unit_table.rs",
    "written_type_fact.rs",
];

/// The shared resolution owners the Go loader reaches, relative to
/// `src/resolution`.
///
/// They are language-neutral and compile in every configuration, so a claim
/// about what the Go loader may read has to include them: an escape or an
/// environment read hidden here would answer for Go too. The record cache is
/// the sharpest case — it is the body that opens a Go source, so a boundary
/// claim that stopped at the Go tree would no longer cover the read at all. The
/// snapshot store is the second: it now owns the interning table, the byte
/// charge, and the retention every Go source is admitted through.
pub const SHARED_MODULES: &[&str] = &[
    "binding.rs",
    "capacity.rs",
    "digest.rs",
    "identity.rs",
    "line_index.rs",
    "path_normalization.rs",
    "paths.rs",
    "read.rs",
    "record_cache.rs",
    "sites.rs",
    "snapshot_rules.rs",
    "snapshot_store.rs",
    "source_language.rs",
    "supply.rs",
];

/// The crate-level modules a Go load reaches outside the resolution tree,
/// relative to `src`.
///
/// `load.rs` mints its project authority through `crate::hash::digest_bytes`
/// and `store.rs` digests each source the same way, while `manifest.rs` and
/// `store.rs` both announce their reads through `crate::observe`.
/// Those calls run on every load, so a boundary claim that skipped them would
/// leave the newly wired modules unscanned: a process launch or an environment
/// read placed in the observation hook would answer for Go without changing a
/// single manifest count.
pub const REACHED_MODULES: &[&str] = &[
    "hash.rs",
    "observe/event.rs",
    "observe/mod.rs",
    "observe/probe.rs",
];

/// The directory `REACHED_MODULES` claims whole, relative to `src`.
const REACHED_DIRECTORY: &str = "observe";

/// The complete source closure a Go project load runs through: the Go owners,
/// the shared resolution owners beneath them, and the crate modules they reach.
pub fn source_closure() -> Box<[PathBuf]> {
    // The Go tree and the observation directory are held to their listings by
    // the exactness walks below, so an owner deleted from either fails there.
    // Nothing anchors the other two lists: an entry dropped from them would
    // leave every boundary claim reading a narrower closure and still passing.
    assert!(
        !SHARED_MODULES.is_empty() && !REACHED_MODULES.is_empty(),
        "the shared and reached owners are part of what a Go load runs through, so a claim \
         over the closure that stopped at the Go tree would cover neither"
    );
    let shared = crate_path("src/resolution");
    let source = crate_path("src");
    let mut paths: Vec<PathBuf> = go_module_paths()
        .iter()
        .map(|(_, path)| path.clone())
        .collect();
    paths.extend(SHARED_MODULES.iter().map(|name| shared.join(name)));
    paths.extend(REACHED_MODULES.iter().map(|name| source.join(name)));
    for path in &paths {
        assert!(path.is_file(), "{} is modelled but absent", path.display());
    }
    assert_directory_holds_exactly(&source.join(REACHED_DIRECTORY), &reached_directory());
    paths.into_boxed_slice()
}

/// Every Go owner, as the label a report names it by and the path it sits at.
///
/// One walk, two subjects: the closure claims need the paths and the ownership
/// claims need the labels, and a module reachable under one and not the other
/// would be a hole in whichever list it was missing from.
pub fn go_module_paths() -> Box<[(Box<str>, PathBuf)]> {
    let go = crate_path("src/resolution/go");
    let named: Box<[(Box<str>, PathBuf)]> = GO_MODULES
        .iter()
        .chain(RESOLVE_MODULES.iter())
        .map(|name| (Box::from(*name), go.join(name)))
        .collect();
    assert_directory_holds_exactly(&go, &top_level_entries());
    assert_directory_holds_exactly(&go.join("resolve"), &nested_entries("resolve/"));
    named
}

/// Everything `src/resolution/go` holds directly: its own modules and the
/// subdirectories it opens.
fn top_level_entries() -> Box<[&'static str]> {
    let mut entries: Vec<&'static str> = GO_MODULES
        .iter()
        .copied()
        .chain(GO_DIRECTORIES.iter().copied())
        .collect();
    entries.sort_unstable();
    entries.into_boxed_slice()
}

/// The files [`RESOLVE_MODULES`] names inside one Go subdirectory.
fn nested_entries(prefix: &str) -> Box<[&'static str]> {
    RESOLVE_MODULES
        .iter()
        .filter_map(|name| name.strip_prefix(prefix))
        .collect()
}

/// The files [`REACHED_MODULES`] names inside [`REACHED_DIRECTORY`].
///
/// Derived rather than written twice: one list states the closure, and a module
/// added beside the observation hook has to join it or fail the exactness check.
fn reached_directory() -> Box<[&'static str]> {
    let prefix = format!("{REACHED_DIRECTORY}/");
    REACHED_MODULES
        .iter()
        .filter_map(|name| name.strip_prefix(&prefix))
        .collect()
}

/// Every closure owner that names one of the given markers, reported as
/// `<owner> names <marker>`.
///
/// One scan, two subjects: the project boundary asks which authorities a load
/// may consult, and the host-state claim asks which selection state a snapshot
/// or a resolver may read. Each states its own table; neither restates the
/// walk.
pub fn text_offenders(markers: &[(&str, &[&str])]) -> Box<[Box<str>]> {
    assert!(
        !markers.is_empty(),
        "a marker scan over no marker reports nothing whatever the closure holds"
    );
    let mut offenders: Vec<Box<str>> = Vec::new();
    for path in source_closure().iter() {
        let text = crate::declaration_scan::read_source(path);
        let name = file_label(path);
        offenders.extend(
            markers
                .iter()
                .filter(|(marker, allowed)| text.contains(marker) && !allowed.contains(&&*name))
                .map(|(marker, _)| format!("{name} names {marker}").into_boxed_str()),
        );
    }
    offenders.into_boxed_slice()
}

/// One closure owner's name, relative to `src`.
///
/// Relative rather than bare: the closure holds three `mod.rs` files, and an
/// offender report that named only the file would not say which module it came
/// from.
pub fn file_label(path: &Path) -> Box<str> {
    path.strip_prefix(crate_path("src"))
        .unwrap_or_else(|_| panic!("{} is a closure owner beneath src", path.display()))
        .to_string_lossy()
        .into_owned()
        .into_boxed_str()
}
