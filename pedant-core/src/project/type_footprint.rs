use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::check_config::CheckConfig;
use crate::ir::IrSpan;
use crate::lint::discover_crate_root;
use crate::violation::{Severity, Violation, ViolationType};

use super::ProjectContext;
use super::shape::{FileShape, canonical_predicates};

/// A located fact: a position in a file. Serves both as a type's definition
/// site and as one file's contribution to a build alternative.
struct Site<'a> {
    file: &'a Arc<str>,
    span: IrSpan,
}

/// Impls that are guaranteed to compile together: same `#[cfg]` predicates.
#[derive(Default)]
struct Alternative<'a> {
    methods: usize,
    sites: Vec<Site<'a>>,
}

/// A type's inherent impls across a crate, split into the part every build has
/// and the parts that depend on a `#[cfg]`.
#[derive(Default)]
struct Footprint<'a> {
    unconditional: Alternative<'a>,
    alternatives: BTreeMap<Box<[Box<str>]>, Alternative<'a>>,
}

/// A `#[cfg]`-gated `mod` declaration's reach: a path whose subtree the gate
/// guards, and the predicates guarding it.
struct GatedRoot<'a> {
    path: PathBuf,
    predicates: &'a [Box<str>],
}

/// Aggregate each type's inherent impls across the files of its crate, then
/// report the god-objects and the scattered APIs that only a crate-wide view
/// can see.
///
/// # Type identity
///
/// pedant is syntactic: it sees the name `Foo`, never a resolved path. So a
/// name is aggregated only when the crate defines it in exactly one place.
/// Zero or several definition sites make the name unattributable and the type
/// is skipped. The rule trades detections for the absence of false positives.
///
/// Aggregating per crate is sound rather than approximate: the orphan rule
/// confines an inherent `impl` to the crate defining the type, so two files
/// that share a crate root can never be implementing two different `Foo`s
/// unless the crate also defines `Foo` twice — which the identity rule already
/// rejects.
///
/// # Conditional impls
///
/// A `#[cfg]` is not a licence to stop counting. `#[cfg(feature = "x")]` where
/// `x` is a default feature compiles in every ordinary build, so excluding
/// gated impls would let one attribute hide a god-object that ships — the very
/// evasion this check exists to close, one layer up.
///
/// Instead impls are grouped by the predicates guarding them, and a type is
/// measured against the *worst build*: everything unconditional, plus the
/// single richest alternative. See [`Footprint::worst_build`].
///
/// # Approximated conservatively
///
/// - Shadowing: `mod a { struct Foo; }` and `mod b { struct Foo; }` are two
///   definition sites, so both are skipped even if either is a god-object.
/// - Re-exports: a `pub use` is not a definition, so a re-exported same-name
///   type contributes no site.
/// - Inherent impls written through a type alias (`type Foo = Bar; impl Foo`)
///   attribute to whatever else is named `Foo`, since aliases are not tracked
///   as definitions.
/// - Two alternatives a build could enable at once (two non-default features,
///   say) count as one, since only the richer is taken. Predicate *text* is an
///   alternative's identity, so `unix` and `not(windows)` read as distinct
///   though they overlap.
/// - `#[path]` module overrides are not followed, so a gate on such a `mod`
///   does not reach the file it names.
///
/// Each is a missed detection or a name pedant declines to resolve, never a
/// finding invented from a guess.
pub(super) fn check_type_footprint(
    ctx: &ProjectContext<'_>,
    config: &CheckConfig,
    violations: &mut Vec<Violation>,
) {
    if !config.check_high_method_count && !config.check_scattered_inherent_impl {
        return;
    }
    let gated = cfg_gated_roots(ctx.file_shapes);
    for shapes in group_by_crate(ctx.file_shapes).values() {
        check_crate(shapes, &gated, config, violations);
    }
}

/// Partition files by crate root: the nearest ancestor directory holding a
/// `Cargo.toml`, which is exactly how Cargo resolves a file's package.
///
/// A file with no manifest above it — a loose path on the command line — keys
/// on itself, so it forms a group of one and aggregation degrades to the
/// per-file behavior rather than guessing at a crate boundary. This needs no
/// `cargo metadata`: the check wants a partition key, not package identity, and
/// requiring metadata would make the check silent wherever it cannot run.
fn group_by_crate(shapes: &[FileShape]) -> BTreeMap<PathBuf, Vec<&FileShape>> {
    let mut groups: BTreeMap<PathBuf, Vec<&FileShape>> = BTreeMap::new();
    for shape in shapes {
        let path = Path::new(&*shape.file_path);
        let key = discover_crate_root(path).map_or_else(|| path.to_path_buf(), Path::to_path_buf);
        groups.entry(key).or_default().push(shape);
    }
    groups
}

/// Resolve every `#[cfg]`-gated `mod` declaration to the paths it guards: the
/// `<name>.rs` file, and the `<name>/` directory whose whole subtree it gates.
///
/// A gate on a `mod` is written in the parent file, so this is the only way the
/// files it pulls in learn they are conditional. Matching by path prefix also
/// carries the gate down through ungated submodules, which are just as
/// conditional as the module declaring them.
fn cfg_gated_roots(shapes: &[FileShape]) -> Vec<GatedRoot<'_>> {
    let mut roots = Vec::new();
    for shape in shapes {
        let Some(dir) = child_module_dir(Path::new(&*shape.file_path)) else {
            continue;
        };
        for module in &shape.cfg_gated_modules {
            roots.push(GatedRoot {
                path: dir.join(format!("{}.rs", module.name)),
                predicates: &module.cfg_predicates,
            });
            roots.push(GatedRoot {
                path: dir.join(&*module.name),
                predicates: &module.cfg_predicates,
            });
        }
    }
    roots
}

/// The directory a file's `mod name;` declarations resolve against: the file's
/// own directory for a module root, else the directory named after the file.
fn child_module_dir(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    match path.file_stem()?.to_str()? {
        "mod" | "lib" | "main" => Some(parent.to_path_buf()),
        stem => Some(parent.join(stem)),
    }
}

/// Predicates guarding a file, gathered from every gated `mod` above it.
fn file_predicates<'a>(path: &str, gated: &[GatedRoot<'a>]) -> Vec<&'a str> {
    let path = Path::new(path);
    gated
        .iter()
        .filter(|root| path.starts_with(&root.path))
        .flat_map(|root| root.predicates.iter().map(|predicate| &**predicate))
        .collect()
}

fn check_crate(
    shapes: &[&FileShape],
    gated: &[GatedRoot<'_>],
    config: &CheckConfig,
    violations: &mut Vec<Violation>,
) {
    let def_sites = index_def_sites(shapes);
    for (type_name, footprint) in index_footprints(shapes, gated) {
        // Exactly one definition site, or the name is not ours to attribute.
        let Some([def]) = def_sites.get(type_name).map(Vec::as_slice) else {
            continue;
        };
        let (methods, sites) = footprint.worst_build();
        let files = distinct_files(&sites);
        // A type confined to one file is fully visible to the per-file check.
        if files.len() < 2 {
            continue;
        }
        report_scattered(type_name, def, &files, config, violations);
        report_aggregate_count(type_name, methods, &sites, &files, config, violations);
    }
}

fn index_def_sites<'a>(shapes: &[&'a FileShape]) -> BTreeMap<&'a str, Vec<Site<'a>>> {
    let mut sites: BTreeMap<&str, Vec<Site<'_>>> = BTreeMap::new();
    for shape in shapes {
        for def in &shape.type_defs {
            sites.entry(&def.type_name).or_default().push(Site {
                file: &shape.file_path,
                span: def.span,
            });
        }
    }
    sites
}

/// Build each type's crate-wide footprint, folding the gates on a file's `mod`
/// chain into the predicate set that identifies a build alternative.
fn index_footprints<'a>(
    shapes: &[&'a FileShape],
    gated: &[GatedRoot<'_>],
) -> BTreeMap<&'a str, Footprint<'a>> {
    let mut footprints: BTreeMap<&str, Footprint<'_>> = BTreeMap::new();
    for shape in shapes {
        let from_modules = file_predicates(&shape.file_path, gated);
        for site in &shape.inherent_impls {
            let predicates = canonical_predicates(
                from_modules
                    .iter()
                    .copied()
                    .chain(site.cfg_predicates.iter().map(|predicate| &**predicate)),
            );
            footprints.entry(&site.type_name).or_default().add(
                predicates,
                &shape.file_path,
                site.first_impl,
                site.method_count,
            );
        }
    }
    footprints
}

impl<'a> Footprint<'a> {
    fn add(
        &mut self,
        predicates: Box<[Box<str>]>,
        file: &'a Arc<str>,
        span: IrSpan,
        methods: usize,
    ) {
        let alternative = match predicates.is_empty() {
            true => &mut self.unconditional,
            false => self.alternatives.entry(predicates).or_default(),
        };
        alternative.methods += methods;
        alternative.sites.push(Site { file, span });
    }

    /// The worst build this type can appear in: everything unconditional, plus
    /// the single richest `#[cfg]` alternative.
    ///
    /// Summing every alternative would count `#[cfg(unix)]` and
    /// `#[cfg(windows)]` impls in one total though no build has both — an
    /// invented god-object. Excluding them all would let a `#[cfg]` on a
    /// default-on feature hide one that ships. The max is a total some real
    /// build actually attains, so it can only miss a god-object, never invent
    /// one.
    fn worst_build(&self) -> (usize, Vec<&Site<'a>>) {
        let richest = self
            .alternatives
            .values()
            .max_by_key(|alt| (alt.methods, alt.sites.len()));
        let methods = self.unconditional.methods + richest.map_or(0, |alt| alt.methods);
        let mut sites: Vec<&Site<'a>> = self
            .unconditional
            .sites
            .iter()
            .chain(richest.into_iter().flat_map(|alt| alt.sites.iter()))
            .collect();
        sites
            .sort_by(|left, right| (left.file, left.span.line).cmp(&(right.file, right.span.line)));
        (methods, sites)
    }
}

/// File paths in `sites`, deduplicated, keeping their sorted order.
fn distinct_files<'a>(sites: &[&Site<'a>]) -> Vec<&'a Arc<str>> {
    let mut files: Vec<&Arc<str>> = sites.iter().map(|site| site.file).collect();
    files.dedup_by(|left, right| left.as_ref() == right.as_ref());
    files
}

/// Flag a type whose inherent impls span more than one file.
///
/// Reported at the definition site: the one place a scattered API is not.
fn report_scattered(
    type_name: &str,
    def: &Site<'_>,
    files: &[&Arc<str>],
    config: &CheckConfig,
    violations: &mut Vec<Violation>,
) {
    if !config.check_scattered_inherent_impl {
        return;
    }
    violations.push(
        Violation::new(
            ViolationType::ScatteredInherentImpl,
            Arc::clone(def.file),
            def.span.line,
            def.span.column + 1,
            format!(
                "`{type_name}`'s inherent impls span {} files ({}); gather the type's own API into one file",
                files.len(),
                file_list(files)
            ),
        )
        .with_severity(Severity::Warn),
    );
}

fn file_list(files: &[&Arc<str>]) -> String {
    files
        .iter()
        .map(|file| file_name(file))
        .collect::<Vec<_>>()
        .join(", ")
}

fn file_name(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}

/// Re-report `high-method-count` with the type's crate-wide total.
fn report_aggregate_count(
    type_name: &str,
    methods: usize,
    sites: &[&Site<'_>],
    files: &[&Arc<str>],
    config: &CheckConfig,
    violations: &mut Vec<Violation>,
) {
    if !config.check_high_method_count || methods <= config.max_methods {
        return;
    }
    supersede_per_file_counts(type_name, files, violations);
    let first = sites[0];
    violations.push(Violation::new(
        ViolationType::HighMethodCount {
            type_name: Box::from(type_name),
        },
        Arc::clone(first.file),
        first.span.line,
        first.span.column + 1,
        format!(
            "`{type_name}` has {methods} inherent methods across {} files (limit: {}), split its responsibilities into focused types",
            files.len(),
            config.max_methods
        ),
    ));
}

/// Drop the per-file `high-method-count` findings the aggregate replaces.
///
/// The per-file check can only see its own slice of a scattered type; once the
/// crate-wide total is known, that slice is the same finding stated with a
/// smaller number. Scoped to this type in these files, so a same-named type in
/// another crate keeps its own report.
fn supersede_per_file_counts(
    type_name: &str,
    files: &[&Arc<str>],
    violations: &mut Vec<Violation>,
) {
    violations.retain(|violation| !is_superseded(violation, type_name, files));
}

fn is_superseded(violation: &Violation, type_name: &str, files: &[&Arc<str>]) -> bool {
    let ViolationType::HighMethodCount { type_name: found } = &violation.violation_type else {
        return false;
    };
    &**found == type_name
        && files
            .iter()
            .any(|file| file.as_ref() == violation.file_path.as_ref())
}
