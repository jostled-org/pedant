use std::path::Path;
use std::sync::Arc;

use crate::check_config::{CheckConfig, FlatModuleFamily};
use crate::violation::{Violation, ViolationType};

use super::ProjectContext;

/// Flag any `<stem>.rs` file that sits beside a `<stem>/` directory module.
/// The convention is directory modules rooted at `<stem>/mod.rs`; the stray
/// sibling file makes the module root ambiguous. `mod.rs`/`lib.rs` are exempt.
pub(super) fn check_conflicting_module_root(
    ctx: &ProjectContext<'_>,
    config: &CheckConfig,
    violations: &mut Vec<Violation>,
) {
    if !config.check_conflicting_module_root {
        return;
    }
    for file in ctx.rust_files {
        let path = Path::new(file);
        let Some(stem) = module_stem(path) else {
            continue;
        };
        // The sibling directory shares the file's path with the `.rs` removed.
        if path.with_extension("").is_dir() {
            violations.push(Violation::new(
                ViolationType::ConflictingModuleRoot,
                Arc::from(file.as_str()),
                1,
                1,
                format!(
                    "`{stem}.rs` conflicts with the `{stem}/` directory module; fold it into `{stem}/mod.rs`"
                ),
            ));
        }
    }
}

/// The module stem of a `.rs` file, unless it is a `mod.rs`/`lib.rs` root.
fn module_stem(path: &Path) -> Option<&str> {
    match path.extension()?.to_str()? {
        "rs" => {}
        _ => return None,
    }
    match path.file_stem()?.to_str()? {
        "mod" | "lib" => None,
        stem => Some(stem),
    }
}

/// Flag prefixed module-family members that sit flat under `parent` instead of
/// below the configured `parent/package_root/` directory.
pub(super) fn check_flat_module_family(
    ctx: &ProjectContext<'_>,
    config: &CheckConfig,
    violations: &mut Vec<Violation>,
) {
    if !config.check_flat_module_family {
        return;
    }
    for family in config.flat_module_families.iter() {
        scan_family(ctx.workspace_root, family, violations);
    }
}

fn scan_family(root: &Path, family: &FlatModuleFamily, violations: &mut Vec<Violation>) {
    let parent_dir = root.join(&*family.parent);
    let Ok(entries) = std::fs::read_dir(&parent_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if name == &*family.package_root || !is_family_member(name, &family.prefix, is_dir) {
            continue;
        }
        let rel = format!("{}/{}", family.parent, name);
        violations.push(Violation::new(
            ViolationType::FlatModuleFamily,
            Arc::from(rel.as_str()),
            1,
            1,
            format!(
                "`{name}` is a flat `{}` family member; move it under `{}/{}/`",
                family.prefix, family.parent, family.package_root
            ),
        ));
    }
}

/// A family member is `prefix.rs`, `prefix_*.rs`, or a `prefix_*/` directory.
fn is_family_member(name: &str, prefix: &str, is_dir: bool) -> bool {
    let family_prefix = format!("{prefix}_");
    match (is_dir, name.strip_suffix(".rs")) {
        (true, _) => name.starts_with(&family_prefix),
        (false, Some(stem)) => stem == prefix || stem.starts_with(&family_prefix),
        (false, None) => false,
    }
}
