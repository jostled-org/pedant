use std::path::Path;
use std::sync::Arc;

use crate::check_config::CheckConfig;
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
