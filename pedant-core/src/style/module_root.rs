use std::path::Path;
use std::sync::Arc;

use crate::check_config::CheckConfig;
use crate::ir::{FileIr, TypeDefKind};
use crate::violation::{Violation, ViolationType};

use super::common::emit_violation;

/// Flag item definitions in module-root files (`mod.rs`, `lib.rs` by default).
///
/// A module root should only wire the tree together: `mod` declarations,
/// `use`/`pub use` re-exports, attributes, and docs. Any `fn`, `struct`,
/// `enum`, `union`, `trait`, or `impl` definition is a finding.
pub(super) fn check_module_root_definitions(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_module_root_definitions || !is_module_root(fp, config) {
        return;
    }

    for def in &ir.type_defs {
        emit(violations, fp, def.span, type_keyword(def.kind), &def.name);
    }
    for imp in &ir.impl_blocks {
        emit(violations, fp, imp.span, "impl", &imp.self_type);
    }
    for func in &ir.functions {
        if !func.is_associated {
            emit(violations, fp, func.span, "fn", &func.name);
        }
    }
}

/// Match the file's base name against the configured module-root list.
fn is_module_root(fp: &str, config: &CheckConfig) -> bool {
    let Some(name) = Path::new(fp).file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    config.module_root_files.iter().any(|root| &**root == name)
}

fn type_keyword(kind: TypeDefKind) -> &'static str {
    match kind {
        TypeDefKind::Struct => "struct",
        TypeDefKind::Enum => "enum",
        TypeDefKind::Trait => "trait",
        TypeDefKind::Union => "union",
    }
}

fn emit(
    violations: &mut Vec<Violation>,
    fp: &Arc<str>,
    span: crate::ir::IrSpan,
    keyword: &str,
    name: &str,
) {
    emit_violation(
        violations,
        fp,
        span,
        ViolationType::ModuleRootDefinitions,
        format!(
            "module root defines `{keyword} {name}`; move it to a leaf module and re-export with `pub use`"
        ),
    );
}
