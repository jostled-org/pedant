//! Manifest traversal that turns a repository root into a Go module project.
//!
//! The root `go.mod` is the sole `replace` and `exclude` authority. An admitted
//! module contributes its own `module` and `require` declarations and nothing
//! else, which is what a single-main-module build does. Only a requirement an
//! admitted module contributed, replaced by the root with an in-root local
//! directory, brings another manifest into the project.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::error::GoProjectError;
use super::exclusion::GoExclusion;
use super::identity::{GoModuleId, ProjectAuthority, index_of, position};
use super::limits::GoResolutionLimits;
use super::manifest::{GoManifestDocument, ParsedExclusion, ParsedReplacement, ParsedRequirement};
use super::module::GoModule;
use super::paths;
use super::project::GoProject;
use super::replacement::{GoReplacement, GoReplacementTarget};
use super::requirement::{GoRequirement, GoRequirementResolution};
use crate::hash::digest_bytes;
use crate::observe::{self, Observation};
use crate::resolution::capacity::admits_one_more;

/// The one reason a repository root anchors no Go project.
const NO_ROOT_MANIFEST: &str = "the project root holds no readable go.mod";

/// One admitted module, before the project mints its identity.
struct LoadedModule {
    path: Arc<str>,
    directory: Arc<str>,
    manifest: Arc<str>,
    depth: u32,
    digest: [u8; 32],
}

/// One requirement, before the project mints the identities it names.
struct LoadedRequirement {
    module: u32,
    path: Box<str>,
    version: Box<str>,
    resolution: LoadedResolution,
}

/// What a requirement resolved to, keyed by project-local module index.
enum LoadedResolution {
    External,
    ReplacedModule { path: Arc<str>, version: Arc<str> },
    LocalModule(u32),
}

/// One root replacement, and whether an admitted requirement selected it.
struct ReplacementEntry {
    declaration: ParsedReplacement,
    applied: bool,
}

/// Everything one load retains while it walks the module graph.
struct Loader<'a> {
    root: &'a Path,
    limits: GoResolutionLimits,
    modules: Vec<LoadedModule>,
    resolved: Vec<LoadedRequirement>,
    replacements: Vec<ReplacementEntry>,
    exclusions: Box<[ParsedExclusion]>,
    directories: BTreeMap<PathBuf, u32>,
    declared: BTreeMap<Arc<str>, u32>,
    pending: VecDeque<(u32, Box<[ParsedRequirement]>)>,
    revision: Vec<u8>,
}

/// Read the main module at `root` and every local replacement it requires.
pub(super) fn load_project(
    root: &Path,
    limits: GoResolutionLimits,
) -> Result<GoProject, GoProjectError> {
    let canonical = paths::canonical_root(root)?;
    observe::record(Observation::ProjectLoad);
    let document = read_root_manifest(&canonical)?;
    Loader::new(&canonical, limits).run(document)
}

/// The main module's manifest, which a Go project cannot be loaded without.
fn read_root_manifest(root: &Path) -> Result<GoManifestDocument, GoProjectError> {
    match paths::confined_manifest(root, root)? {
        Some(manifest) => GoManifestDocument::read(root, manifest.path()),
        None => Err(GoProjectError::InvalidRoot {
            path: paths::path_text(root),
            reason: Box::from(NO_ROOT_MANIFEST),
        }),
    }
}

impl<'a> Loader<'a> {
    fn new(root: &'a Path, limits: GoResolutionLimits) -> Self {
        Self {
            root,
            limits,
            modules: Vec::new(),
            resolved: Vec::new(),
            replacements: Vec::new(),
            exclusions: Box::from([]),
            directories: BTreeMap::new(),
            declared: BTreeMap::new(),
            pending: VecDeque::new(),
            revision: Vec::new(),
        }
    }

    /// Admit the main module, then resolve requirements until none is pending.
    fn run(mut self, root_document: GoManifestDocument) -> Result<GoProject, GoProjectError> {
        self.exclusions = root_document.exclusions;
        self.replacements = root_document
            .replacements
            .into_vec()
            .into_iter()
            .map(|declaration| ReplacementEntry {
                declaration,
                applied: false,
            })
            .collect();
        let main = LoadedModule {
            path: Arc::clone(&root_document.module),
            directory: Arc::from(""),
            manifest: Arc::from(root_document.relative),
            depth: 0,
            digest: root_document.digest,
        };
        self.retain_module(self.root.to_path_buf(), main, root_document.requirements)?;
        while let Some((owner, requirements)) = self.pending.pop_front() {
            self.resolve_module_requirements(owner, requirements)?;
        }
        self.seal()
    }

    /// Resolve every requirement one admitted module declares.
    fn resolve_module_requirements(
        &mut self,
        owner: u32,
        requirements: Box<[ParsedRequirement]>,
    ) -> Result<(), GoProjectError> {
        for requirement in requirements.into_vec() {
            self.resolve_requirement(owner, requirement)?;
        }
        Ok(())
    }

    /// Resolve one requirement against the root manifest's directives.
    fn resolve_requirement(
        &mut self,
        owner: u32,
        requirement: ParsedRequirement,
    ) -> Result<(), GoProjectError> {
        self.check_not_excluded(&requirement)?;
        let resolution = self.resolve_target(owner, &requirement)?;
        self.resolved.push(LoadedRequirement {
            module: owner,
            path: requirement.path,
            version: requirement.version,
            resolution,
        });
        Ok(())
    }

    /// A root exclusion that matches an admitted requirement refuses the load.
    fn check_not_excluded(&self, requirement: &ParsedRequirement) -> Result<(), GoProjectError> {
        let excluded = self.exclusions.iter().any(|exclusion| {
            exclusion.path == requirement.path && exclusion.version == requirement.version
        });
        match excluded {
            false => Ok(()),
            true => Err(GoProjectError::ExcludedRequirement {
                module: requirement.path.clone(),
                version: requirement.version.clone(),
            }),
        }
    }

    /// What the applicable replacement, if any, resolves a requirement to.
    fn resolve_target(
        &mut self,
        owner: u32,
        requirement: &ParsedRequirement,
    ) -> Result<LoadedResolution, GoProjectError> {
        let Some(selected) = self.applicable_replacement(requirement) else {
            return Ok(LoadedResolution::External);
        };
        self.replacements[selected].applied = true;
        let directory = match &self.replacements[selected].declaration.target {
            GoReplacementTarget::Module { path, version } => {
                return Ok(LoadedResolution::ReplacedModule {
                    path: Arc::clone(path),
                    version: Arc::clone(version),
                });
            }
            GoReplacementTarget::LocalDirectory(directory) => directory.clone(),
        };
        self.admit_local(owner, (&directory, requirement))
            .map(LoadedResolution::LocalModule)
    }

    /// The replacement one requirement selects: an exact `(path, version)`
    /// entry outranks a path-only entry for the same path.
    fn applicable_replacement(&self, requirement: &ParsedRequirement) -> Option<usize> {
        let exact = self.replacements.iter().position(|entry| {
            entry.declaration.path == requirement.path
                && entry.declaration.version.as_deref() == Some(&*requirement.version)
        });
        exact.or_else(|| {
            self.replacements.iter().position(|entry| {
                entry.declaration.path == requirement.path && entry.declaration.version.is_none()
            })
        })
    }

    /// Admit the in-root local module a replacement names, or return the one
    /// already admitted from that canonical directory.
    fn admit_local(
        &mut self,
        owner: u32,
        replacement: (&str, &ParsedRequirement),
    ) -> Result<u32, GoProjectError> {
        let (_, requirement) = replacement;
        let canonical = self.canonical_target(replacement)?;
        if let Some(admitted) = self.directories.get(&canonical) {
            return Ok(*admitted);
        }
        let document = self.read_module_manifest(&canonical, replacement)?;
        let relative = paths::relative_shared(self.root, &canonical)?;
        self.check_declared_module(&document, (&relative, &requirement.path))?;
        let module = LoadedModule {
            path: Arc::clone(&document.module),
            directory: relative,
            manifest: Arc::from(document.relative),
            depth: self.depth_of(owner)?.saturating_add(1),
            digest: document.digest,
        };
        self.retain_module(canonical, module, document.requirements)
    }

    /// The canonical form of a replacement target that stays inside the root.
    fn canonical_target(
        &self,
        replacement: (&str, &ParsedRequirement),
    ) -> Result<PathBuf, GoProjectError> {
        let (directory, requirement) = replacement;
        match paths::canonical_in_root(self.root, &self.root.join(directory))? {
            Some(canonical) => Ok(canonical),
            None => Err(GoProjectError::MissingReplacementManifest {
                directory: directory.into(),
                module: requirement.path.clone(),
            }),
        }
    }

    /// The replacement target's manifest, distinguishing an absent one from an
    /// unreadable one.
    fn read_module_manifest(
        &self,
        canonical: &Path,
        replacement: (&str, &ParsedRequirement),
    ) -> Result<GoManifestDocument, GoProjectError> {
        let (directory, requirement) = replacement;
        match paths::confined_manifest(self.root, canonical)? {
            Some(manifest) => GoManifestDocument::read(self.root, manifest.path()),
            None => Err(GoProjectError::MissingReplacementManifest {
                directory: directory.into(),
                module: requirement.path.clone(),
            }),
        }
    }

    /// The target must declare the required path, and no two directories may
    /// declare one module path.
    fn check_declared_module(
        &self,
        document: &GoManifestDocument,
        site: (&str, &str),
    ) -> Result<(), GoProjectError> {
        let (relative, expected) = site;
        if document.module.as_ref() != expected {
            return Err(GoProjectError::ReplacementModuleMismatch {
                directory: relative.into(),
                declared: document.module.as_ref().into(),
                expected: expected.into(),
            });
        }
        match self.declared.get(&document.module) {
            None => Ok(()),
            Some(admitted) => Err(GoProjectError::ConflictingLocalModules {
                module: document.module.as_ref().into(),
                first: self.directory_of(*admitted)?.into(),
                second: relative.into(),
            }),
        }
    }

    /// Check both load ceilings, then retain one module and queue its
    /// requirements.
    ///
    /// Every module enters the project here, so a ceiling checked in this one
    /// body dominates every insertion into the retained tables.
    fn retain_module(
        &mut self,
        canonical: PathBuf,
        module: LoadedModule,
        requirements: Box<[ParsedRequirement]>,
    ) -> Result<u32, GoProjectError> {
        check_manifest_capacity(self.modules.len(), self.limits)?;
        check_dependency_depth(module.depth, self.limits)?;
        let index = position(self.modules.len());
        self.revision.extend_from_slice(&module.digest);
        self.directories.insert(canonical, index);
        self.declared.insert(Arc::clone(&module.path), index);
        self.modules.push(module);
        self.pending.push_back((index, requirements));
        Ok(index)
    }

    /// The depth of an already-admitted module.
    ///
    /// Absence is reported rather than answered. A depth taken as zero would
    /// restart the replacement-depth count that `check_dependency_depth`
    /// bounds, so an unknown owner would widen the very ceiling it feeds.
    fn depth_of(&self, module: u32) -> Result<u32, GoProjectError> {
        admitted(&self.modules, module).map(|held| held.depth)
    }

    /// The repository-relative directory of an already-admitted module.
    ///
    /// Absence is reported rather than answered. An empty directory renders as
    /// the repository root in a `ConflictingLocalModules` refusal, which names
    /// a directory the conflict is not in.
    fn directory_of(&self, module: u32) -> Result<&str, GoProjectError> {
        admitted(&self.modules, module).map(|held| &*held.directory)
    }

    /// Mint identities and seal the project.
    fn seal(self) -> Result<GoProject, GoProjectError> {
        let authority =
            ProjectAuthority::new(root_fingerprint(self.root)?, digest_bytes(&self.revision));
        let mut modules = self
            .modules
            .into_iter()
            .enumerate()
            .map(|(index, module)| GoModule {
                id: GoModuleId::new(authority, position(index)),
                path: module.path,
                directory: module.directory,
                manifest: module.manifest,
                depth: module.depth,
            });
        let Some(main) = modules.next() else {
            return Err(GoProjectError::InvalidRoot {
                path: paths::path_text(self.root),
                reason: Box::from(NO_ROOT_MANIFEST),
            });
        };
        let required: Box<[GoModule]> = modules.collect();
        Ok(GoProject {
            root: self.root.into(),
            limits: self.limits,
            authority,
            main,
            required,
            requirements: self
                .resolved
                .into_iter()
                .map(|requirement| published_requirement(authority, requirement))
                .collect(),
            replacements: self
                .replacements
                .into_iter()
                .map(published_replacement)
                .collect(),
            exclusions: self
                .exclusions
                .into_vec()
                .into_iter()
                .map(|exclusion| GoExclusion {
                    path: exclusion.path,
                    version: exclusion.version,
                })
                .collect(),
        })
    }
}

/// One module a load already admitted, by its project-local index.
///
/// Absence is a refusal rather than an answer: every index reaching this lookup
/// is one `retain_module` returned, so a miss is the loader disagreeing with
/// itself, and both readers of it would otherwise resolve that disagreement
/// into a depth of zero or a directory that renders as the repository root.
fn admitted(modules: &[LoadedModule], module: u32) -> Result<&LoadedModule, GoProjectError> {
    modules
        .get(index_of(module))
        .ok_or(GoProjectError::MissingAdmittedModule { index: module })
}

/// The published form of one loaded requirement.
fn published_requirement(
    authority: ProjectAuthority,
    requirement: LoadedRequirement,
) -> GoRequirement {
    GoRequirement {
        module: GoModuleId::new(authority, requirement.module),
        path: requirement.path,
        version: requirement.version,
        resolution: match requirement.resolution {
            LoadedResolution::External => GoRequirementResolution::External,
            LoadedResolution::ReplacedModule { path, version } => {
                GoRequirementResolution::ReplacedModule { path, version }
            }
            LoadedResolution::LocalModule(index) => {
                GoRequirementResolution::LocalModule(GoModuleId::new(authority, index))
            }
        },
    }
}

/// The published form of one root replacement.
fn published_replacement(entry: ReplacementEntry) -> GoReplacement {
    GoReplacement {
        path: entry.declaration.path,
        version: entry.declaration.version,
        target: entry.declaration.target,
        applied: entry.applied,
    }
}

/// SHA-256 over the canonical root's text, which scopes every issued identity.
fn root_fingerprint(root: &Path) -> Result<[u8; 32], GoProjectError> {
    match root.to_str() {
        Some(text) => Ok(digest_bytes(text.as_bytes())),
        None => Err(GoProjectError::NonUtf8Path {
            path: paths::path_text(root),
        }),
    }
}

/// One more manifest must still fit under the configured ceiling.
fn check_manifest_capacity(held: usize, limits: GoResolutionLimits) -> Result<(), GoProjectError> {
    match admits_one_more(held, limits.max_module_manifests) {
        true => Ok(()),
        false => Err(GoProjectError::ManifestLimitExceeded {
            limit: limits.max_module_manifests,
        }),
    }
}

/// One module's replacement depth must sit under the configured ceiling.
fn check_dependency_depth(depth: u32, limits: GoResolutionLimits) -> Result<(), GoProjectError> {
    match depth > limits.max_dependency_depth {
        true => Err(GoProjectError::DependencyDepthLimitExceeded {
            limit: limits.max_dependency_depth,
        }),
        false => Ok(()),
    }
}
