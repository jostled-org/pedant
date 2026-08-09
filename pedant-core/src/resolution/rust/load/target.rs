//! Cargo target discovery: declared tables plus the automatic layout rules.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::resolution::rust::error::RustProjectError;
use crate::resolution::rust::paths;
use crate::resolution::rust::target::CargoTargetKind;
use crate::resolution::rust::toml_view;

use super::entry::ScannedEntry;

/// Cargo's name for the build-script target.
const BUILD_SCRIPT_NAME: &str = "build-script-build";

/// The declared-table key, automatic directory, and kind of each target family
/// that follows the `<dir>/*.rs` plus `<dir>/*/main.rs` layout.
const AUTO_FAMILIES: &[(&str, &str, CargoTargetKind)] = &[
    ("example", "examples", CargoTargetKind::Example),
    ("test", "tests", CargoTargetKind::Test),
    ("bench", "benches", CargoTargetKind::Benchmark),
];

/// One target before the project can issue it an identity.
pub(super) struct TargetDraft {
    pub(super) name: Arc<str>,
    pub(super) kind: CargoTargetKind,
    pub(super) entry: Arc<str>,
}

/// What target discovery reads for one package.
pub(super) struct TargetContext<'a> {
    pub(super) root: &'a Path,
    pub(super) directory: &'a Path,
    pub(super) manifest: &'a toml::Table,
    pub(super) manifest_path: &'a str,
    pub(super) package: &'a toml::Table,
    pub(super) package_name: &'a str,
}

/// Every target a package declares or implies, ordered by kind then name.
pub(super) fn discover_targets(
    context: &TargetContext<'_>,
) -> Result<Box<[TargetDraft]>, RustProjectError> {
    let mut drafts = Vec::new();
    push_library(context, &mut drafts)?;
    push_binaries(context, &mut drafts)?;
    for (key, directory, kind) in AUTO_FAMILIES {
        push_family(context, (key, directory, *kind), &mut drafts)?;
    }
    push_build_script(context, &mut drafts)?;
    drafts.sort_by(|left, right| {
        (left.kind, left.name.as_ref()).cmp(&(right.kind, right.name.as_ref()))
    });
    drafts.dedup_by(|left, right| left.kind == right.kind && left.name == right.name);
    Ok(drafts.into_boxed_slice())
}

fn push_library(
    context: &TargetContext<'_>,
    drafts: &mut Vec<TargetDraft>,
) -> Result<(), RustProjectError> {
    let declared = toml_view::table(context.manifest, "lib");
    let name = declared
        .and_then(|table| toml_view::string(table, "name"))
        .map(Arc::from)
        .unwrap_or_else(|| Arc::from(context.package_name.replace('-', "_").as_str()));
    let declared_path = declared.and_then(|table| toml_view::string(table, "path"));
    let entry = library_entry(context, declared_path);
    push_optional_draft(context, entry, (name, CargoTargetKind::Library), drafts)
}

/// A declared library path is authoritative; otherwise `src/lib.rs` must exist.
fn library_entry(context: &TargetContext<'_>, declared: Option<&str>) -> Option<PathBuf> {
    let default = context.directory.join("src/lib.rs");
    let inferred = toml_view::flag(context.package, "autolib", true) && default.is_file();
    match declared {
        Some(path) => Some(context.directory.join(path)),
        None => inferred.then_some(default),
    }
}

fn push_binaries(
    context: &TargetContext<'_>,
    drafts: &mut Vec<TargetDraft>,
) -> Result<(), RustProjectError> {
    for declared in toml_view::tables(context.manifest, "bin") {
        push_declared_binary(context, declared, drafts)?;
    }
    match toml_view::flag(context.package, "autobins", true) {
        true => push_auto_binaries(context, drafts),
        false => Ok(()),
    }
}

fn push_declared_binary(
    context: &TargetContext<'_>,
    declared: &toml::Table,
    drafts: &mut Vec<TargetDraft>,
) -> Result<(), RustProjectError> {
    let name = declared_name(context, declared, "bin")?;
    let inferred = toml_view::string(declared, "path")
        .map(|path| context.directory.join(path))
        .or_else(|| inferred_binary_entry(context, name));
    let entry = declared_entry(context, inferred, ("bin", name))?;
    push_draft(
        context,
        entry,
        (Arc::from(name), CargoTargetKind::Binary),
        drafts,
    )
}

/// Cargo looks for `src/bin/<name>.rs`, `src/bin/<name>/main.rs`, and — for the
/// binary named after the package — `src/main.rs`.
fn inferred_binary_entry(context: &TargetContext<'_>, name: &str) -> Option<PathBuf> {
    let package_main =
        (name == context.package_name).then(|| context.directory.join("src/main.rs"));
    [
        Some(context.directory.join(format!("src/bin/{name}.rs"))),
        Some(context.directory.join(format!("src/bin/{name}/main.rs"))),
        package_main,
    ]
    .into_iter()
    .flatten()
    .find(|path| path.is_file())
}

fn push_auto_binaries(
    context: &TargetContext<'_>,
    drafts: &mut Vec<TargetDraft>,
) -> Result<(), RustProjectError> {
    let package_main = context.directory.join("src/main.rs");
    if package_main.is_file() {
        push_draft(
            context,
            package_main,
            (Arc::from(context.package_name), CargoTargetKind::Binary),
            drafts,
        )?;
    }
    push_scanned(context, "src/bin", CargoTargetKind::Binary, drafts)
}

fn push_family(
    context: &TargetContext<'_>,
    family: (&str, &str, CargoTargetKind),
    drafts: &mut Vec<TargetDraft>,
) -> Result<(), RustProjectError> {
    let (key, directory, kind) = family;
    for declared in toml_view::tables(context.manifest, key) {
        push_declared_family(context, declared, family, drafts)?;
    }
    match toml_view::flag(context.package, &format!("auto{directory}"), true) {
        true => push_scanned(context, directory, kind, drafts),
        false => Ok(()),
    }
}

fn push_declared_family(
    context: &TargetContext<'_>,
    declared: &toml::Table,
    family: (&str, &str, CargoTargetKind),
    drafts: &mut Vec<TargetDraft>,
) -> Result<(), RustProjectError> {
    let (key, directory, kind) = family;
    let name = declared_name(context, declared, key)?;
    let inferred = toml_view::string(declared, "path")
        .map(|path| context.directory.join(path))
        .or_else(|| inferred_family_entry(context, directory, name));
    let entry = declared_entry(context, inferred, (key, name))?;
    push_draft(context, entry, (Arc::from(name), kind), drafts)
}

fn inferred_family_entry(
    context: &TargetContext<'_>,
    directory: &str,
    name: &str,
) -> Option<PathBuf> {
    [
        context.directory.join(format!("{directory}/{name}.rs")),
        context
            .directory
            .join(format!("{directory}/{name}/main.rs")),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

/// Add every `<directory>/*.rs` and `<directory>/*/main.rs` entry point.
fn push_scanned(
    context: &TargetContext<'_>,
    directory: &str,
    kind: CargoTargetKind,
    drafts: &mut Vec<TargetDraft>,
) -> Result<(), RustProjectError> {
    for (name, entry) in scan_entry_directory(&context.directory.join(directory))? {
        push_draft(context, entry, (Arc::from(name), kind), drafts)?;
    }
    Ok(())
}

fn push_build_script(
    context: &TargetContext<'_>,
    drafts: &mut Vec<TargetDraft>,
) -> Result<(), RustProjectError> {
    let entry = build_script_entry(context);
    push_optional_draft(
        context,
        entry,
        (Arc::from(BUILD_SCRIPT_NAME), CargoTargetKind::BuildScript),
        drafts,
    )
}

fn build_script_entry(context: &TargetContext<'_>) -> Option<PathBuf> {
    let default = context.directory.join("build.rs");
    match context.package.get("build") {
        Some(toml::Value::String(path)) => Some(context.directory.join(path)),
        Some(toml::Value::Boolean(false)) => None,
        _ => default.is_file().then_some(default),
    }
}

/// Cargo refuses a declared target table that carries no `name`.
fn declared_name<'a>(
    context: &TargetContext<'_>,
    declared: &'a toml::Table,
    key: &str,
) -> Result<&'a str, RustProjectError> {
    toml_view::string(declared, "name").ok_or_else(|| RustProjectError::ManifestParse {
        path: Box::from(context.manifest_path),
        message: format!("[[{key}]] declares no name").into_boxed_str(),
    })
}

/// A declared target states its entry point or Cargo infers one from the layout.
/// When neither holds, the manifest names a target that has no source.
fn declared_entry(
    context: &TargetContext<'_>,
    entry: Option<PathBuf>,
    target: (&str, &str),
) -> Result<PathBuf, RustProjectError> {
    let (key, name) = target;
    entry.ok_or_else(|| RustProjectError::ManifestParse {
        path: Box::from(context.manifest_path),
        message: format!("[[{key}]] target {name} declares no path and none was found")
            .into_boxed_str(),
    })
}

/// Automatic discovery may find no entry point, which is not a manifest fault.
fn push_optional_draft(
    context: &TargetContext<'_>,
    entry: Option<PathBuf>,
    target: (Arc<str>, CargoTargetKind),
    drafts: &mut Vec<TargetDraft>,
) -> Result<(), RustProjectError> {
    match entry {
        Some(path) => push_draft(context, path, target, drafts),
        None => Ok(()),
    }
}

fn push_draft(
    context: &TargetContext<'_>,
    entry: PathBuf,
    target: (Arc<str>, CargoTargetKind),
    drafts: &mut Vec<TargetDraft>,
) -> Result<(), RustProjectError> {
    let (name, kind) = target;
    drafts.push(TargetDraft {
        name,
        kind,
        entry: paths::relative_text(context.root, &entry)?,
    });
    Ok(())
}

/// Entry points directly inside one automatic target directory, sorted.
fn scan_entry_directory(directory: &Path) -> Result<Box<[ScannedEntry]>, RustProjectError> {
    if !directory.is_dir() {
        return Ok(Box::new([]));
    }
    let mut found = Vec::new();
    for entry in paths::read_directory(directory)? {
        push_entry_candidate(&entry.path(), &mut found);
    }
    found.sort();
    Ok(found.into_boxed_slice())
}

fn push_entry_candidate(path: &Path, found: &mut Vec<ScannedEntry>) {
    let nested_main = path.join("main.rs");
    match (path.is_file(), nested_main.is_file()) {
        (true, _) if path.extension() == Some(OsStr::new("rs")) => {
            found.extend(file_stem(path).map(|name| (name, path.to_path_buf())));
        }
        (false, true) => {
            found.extend(file_stem(path).map(|name| (name, nested_main)));
        }
        _ => {}
    }
}

fn file_stem(path: &Path) -> Option<Box<str>> {
    path.file_stem()
        .and_then(OsStr::to_str)
        .map(Box::<str>::from)
}
