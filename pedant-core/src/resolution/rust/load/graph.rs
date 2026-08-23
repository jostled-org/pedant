//! Bounded manifest traversal and deterministic project assembly.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::hash::digest_bytes;
use crate::observe::{self, Observation};
use crate::resolution::capacity::admits_one_more;
use crate::resolution::rust::dependency::RustDependency;
use crate::resolution::rust::edition::CargoEdition;
use crate::resolution::rust::error::RustProjectError;
use crate::resolution::rust::identity::{PackageId, ProjectAuthority, TargetId, index_of};
use crate::resolution::rust::limits::ResolutionLimits;
use crate::resolution::rust::manifest::ManifestDocument;
use crate::resolution::rust::members;
use crate::resolution::rust::package::RustPackage;
use crate::resolution::rust::paths;
use crate::resolution::rust::project::RustProject;
use crate::resolution::rust::target::RustTarget;
use crate::resolution::rust::toml_view;

use super::dependency::{DeclaredEdge, EdgeContext, declared_edges};
use super::package::{WorkspaceSource, package_facts};
use super::target::{TargetContext, TargetDraft, discover_targets};

/// One manifest, the dependency edges it declares, and whether the workspace
/// declares it as a member.
///
/// The edges are read once, when the manifest is read: traversal needs the
/// in-repository manifest each edge selects, and assembly needs the whole edge,
/// so reading the dependency tables a second time would repeat every
/// canonicalization the first read already paid for.
struct ManifestEntry {
    document: ManifestDocument,
    edges: Box<[DeclaredEdge]>,
    member: bool,
}

/// Every manifest the project reaches, plus the one workspace that owns
/// inherited package fields.
struct LoadedManifests {
    entries: Box<[ManifestEntry]>,
    workspace: Option<toml::Table>,
    workspace_manifest: Arc<str>,
}

/// Identity and inheritance state shared by every assembly step.
struct AssemblyContext<'a> {
    root: &'a Path,
    authority: ProjectAuthority,
    workspace: WorkspaceSource<'a>,
}

/// Views under construction, with the lookup tables that bind edges to targets.
#[derive(Default)]
struct ProjectDraft {
    packages: Vec<RustPackage>,
    targets: Vec<RustTarget>,
    libraries: Vec<Option<TargetId>>,
    manifests: BTreeMap<PathBuf, PackageId>,
    next_package: u32,
    next_target: u32,
}

impl ProjectDraft {
    /// The library target of one package, when it declares or implies one.
    fn library_of(&self, package: PackageId) -> Option<TargetId> {
        self.libraries
            .get(index_of(package.index()))
            .copied()
            .flatten()
    }
}

/// Read every manifest beneath `root` and assemble the project index.
pub(in crate::resolution::rust) fn load_project(
    root: &Path,
    limits: ResolutionLimits,
) -> Result<RustProject, RustProjectError> {
    observe::record(Observation::ProjectLoad);
    let root_path = paths::canonical_root(root)?;
    let loaded = collect_manifests(&root_path, limits)?;
    assemble(&root_path, limits, &loaded)
}

fn collect_manifests(
    root: &Path,
    limits: ResolutionLimits,
) -> Result<LoadedManifests, RustProjectError> {
    let root_manifest =
        paths::canonical_manifest(root)?.ok_or_else(|| RustProjectError::InvalidRoot {
            path: paths::path_text(root),
            reason: Box::from("the project root holds no Cargo.toml"),
        })?;
    let root_document = ManifestDocument::read(root, &root_manifest)?;
    let workspace = root_document.workspace().cloned();
    let workspace_manifest = Arc::clone(root_document.relative());
    let members = member_manifests(root, &root_document, limits)?;

    let root_entry = read_entry(root, root_document, (&members, workspace.as_ref()))?;
    let mut pending: VecDeque<PathBuf> = members.iter().cloned().collect();
    pending.extend(edge_manifests(&root_entry));
    let mut seen = BTreeSet::from([root_manifest]);
    let mut entries = vec![root_entry];

    while let Some(path) = pending.pop_front() {
        if seen.contains(&path) {
            continue;
        }
        check_manifest_limit(entries.len(), limits)?;
        let document = ManifestDocument::read(root, &path)?;
        let entry = read_entry(root, document, (&members, workspace.as_ref()))?;
        pending.extend(edge_manifests(&entry));
        entries.push(entry);
        seen.insert(path);
    }

    entries.sort_by(|left, right| left.document.relative().cmp(right.document.relative()));
    Ok(LoadedManifests {
        entries: entries.into_boxed_slice(),
        workspace,
        workspace_manifest,
    })
}

/// Bind one manifest to the dependency edges it declares.
fn read_entry(
    root: &Path,
    document: ManifestDocument,
    inheritance: (&BTreeSet<PathBuf>, Option<&toml::Table>),
) -> Result<ManifestEntry, RustProjectError> {
    let (members, workspace) = inheritance;
    let context = EdgeContext {
        root,
        directory: document.directory(),
        workspace,
    };
    let edges = declared_edges(&context, document.table())?;
    Ok(ManifestEntry {
        member: members.contains(document.path()),
        edges,
        document,
    })
}

/// The in-repository manifests one entry's edges reach.
fn edge_manifests(entry: &ManifestEntry) -> impl Iterator<Item = PathBuf> + '_ {
    entry.edges.iter().filter_map(|edge| edge.manifest.clone())
}

fn check_manifest_limit(held: usize, limits: ResolutionLimits) -> Result<(), RustProjectError> {
    match admits_one_more(held, limits.max_manifests) {
        true => Ok(()),
        false => Err(RustProjectError::LimitExceeded {
            limit: limits.max_manifests,
        }),
    }
}

/// The manifests the root workspace declares as members. A root manifest with a
/// `[package]` section is a member of its own workspace.
fn member_manifests(
    root: &Path,
    document: &ManifestDocument,
    limits: ResolutionLimits,
) -> Result<BTreeSet<PathBuf>, RustProjectError> {
    let mut manifests = BTreeSet::new();
    if document.package().is_some() {
        manifests.extend(paths::canonical_manifest(root)?);
    }
    let workspace = match document.workspace() {
        Some(workspace) => workspace,
        None => return Ok(manifests),
    };
    let directories = members::member_directories(
        root,
        (
            &toml_view::strings(workspace, "members"),
            &toml_view::strings(workspace, "exclude"),
        ),
        limits,
    )?;
    for directory in directories.iter() {
        manifests.extend(paths::canonical_manifest(directory)?);
    }
    Ok(manifests)
}

fn assemble(
    root: &Path,
    limits: ResolutionLimits,
    loaded: &LoadedManifests,
) -> Result<RustProject, RustProjectError> {
    let context = AssemblyContext {
        root,
        authority: ProjectAuthority::new(
            root_fingerprint(root)?,
            manifest_revision(&loaded.entries),
        ),
        workspace: WorkspaceSource {
            package: loaded
                .workspace
                .as_ref()
                .and_then(|workspace| toml_view::table(workspace, "package")),
            manifest_path: &loaded.workspace_manifest,
        },
    };

    let mut draft = ProjectDraft::default();
    for entry in loaded.entries.iter() {
        add_package(&mut draft, &context, entry)?;
    }
    let dependencies = build_dependencies(loaded, &draft);

    Ok(RustProject {
        root: Box::from(root),
        limits,
        authority: context.authority,
        manifests: loaded
            .entries
            .iter()
            .map(|entry| entry.document.fingerprint())
            .collect(),
        packages: draft.packages.into_boxed_slice(),
        targets: draft.targets.into_boxed_slice(),
        dependencies,
    })
}

/// Index one manifest's package and every target it declares or implies.
fn add_package(
    draft: &mut ProjectDraft,
    context: &AssemblyContext<'_>,
    entry: &ManifestEntry,
) -> Result<(), RustProjectError> {
    let table = match entry.document.package() {
        Some(table) => table,
        None => return Ok(()),
    };
    let facts = package_facts(table, entry.document.relative(), &context.workspace)?;
    let id = PackageId::new(context.authority, draft.next_package);
    draft.next_package = draft.next_package.saturating_add(1);

    let drafts = discover_targets(&TargetContext {
        root: context.root,
        directory: entry.document.directory(),
        manifest: entry.document.table(),
        manifest_path: entry.document.relative(),
        package: table,
        package_name: &facts.name,
    })?;
    let library = push_targets(draft, context.authority, id, facts.edition, &drafts);

    draft.packages.push(RustPackage {
        id,
        name: facts.name,
        version: facts.version,
        rust_version: facts.rust_version,
        edition: facts.edition,
        manifest_path: Arc::clone(entry.document.relative()),
        relative_directory: relative_directory(entry.document.relative()),
        directory: entry.document.directory().into(),
        workspace_member: entry.member,
    });
    draft.libraries.push(library);
    draft
        .manifests
        .insert(entry.document.path().to_path_buf(), id);
    Ok(())
}

/// Issue an identity for every target draft, reporting the library target.
fn push_targets(
    draft: &mut ProjectDraft,
    authority: ProjectAuthority,
    package: PackageId,
    edition: CargoEdition,
    drafts: &[TargetDraft],
) -> Option<TargetId> {
    let mut library = None;
    for target in drafts {
        let id = TargetId::new(authority, draft.next_target);
        draft.next_target = draft.next_target.saturating_add(1);
        library = library.or(matches!(
            target.kind,
            crate::resolution::rust::target::CargoTargetKind::Library
        )
        .then_some(id));
        draft.targets.push(RustTarget {
            id,
            package,
            name: Arc::clone(&target.name),
            kind: target.kind,
            entry_path: Arc::clone(&target.entry),
            edition,
        });
    }
    library
}

fn build_dependencies(loaded: &LoadedManifests, draft: &ProjectDraft) -> Box<[RustDependency]> {
    let mut dependencies = Vec::new();
    for entry in loaded.entries.iter() {
        let source = match draft.manifests.get(entry.document.path()) {
            Some(id) => *id,
            None => continue,
        };
        dependencies.extend(
            entry
                .edges
                .iter()
                .map(|edge| build_dependency(draft, source, edge)),
        );
    }
    dependencies.into_boxed_slice()
}

fn build_dependency(
    draft: &ProjectDraft,
    source: PackageId,
    edge: &DeclaredEdge,
) -> RustDependency {
    let package = edge
        .manifest
        .as_ref()
        .and_then(|manifest| draft.manifests.get(manifest))
        .copied();
    RustDependency {
        source,
        name: Arc::clone(&edge.name),
        package_name: Arc::clone(&edge.package_name),
        kind: edge.kind,
        activation: edge.activation.clone(),
        package,
        library: package.and_then(|id| draft.library_of(id)),
    }
}

/// The repository-relative package directory; empty for the root package.
fn relative_directory(manifest_path: &Arc<str>) -> Arc<str> {
    match manifest_path.rsplit_once('/') {
        Some((directory, _)) => Arc::from(directory),
        None => Arc::from(""),
    }
}

/// SHA-256 over the sorted participating manifest paths and their digests.
fn manifest_revision(entries: &[ManifestEntry]) -> [u8; 32] {
    let mut buffer = Vec::new();
    for entry in entries {
        buffer.extend_from_slice(entry.document.relative().as_bytes());
        buffer.push(0);
        buffer.extend_from_slice(entry.document.digest());
    }
    digest_bytes(&buffer)
}

fn root_fingerprint(root: &Path) -> Result<[u8; 32], RustProjectError> {
    let text = root.to_str().ok_or_else(|| RustProjectError::NonUtf8Path {
        path: paths::path_text(root),
    })?;
    Ok(digest_bytes(text.as_bytes()))
}
