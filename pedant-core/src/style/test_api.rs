use std::sync::Arc;

use crate::check_config::CheckConfig;
use crate::ir::{FileIr, IrSpan};
use crate::pattern::matches_glob;
use crate::violation::{Violation, ViolationType};

use super::common::emit_violation;

/// Flag test-only APIs (by configured name glob) defined under `src/` without an
/// enclosing `#[cfg(feature = "…")]` gate for the configured support feature.
pub(super) fn check_ungated_test_api(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_ungated_test_api || !is_under_src(fp) {
        return;
    }
    let feature = &*config.test_support_feature;
    let patterns = &config.test_api_patterns;

    for func in &ir.functions {
        maybe_flag(
            &func.name,
            &func.cfg_feature_gates,
            func.span,
            patterns,
            feature,
            fp,
            violations,
        );
    }
    for type_def in &ir.type_defs {
        maybe_flag(
            &type_def.name,
            &type_def.cfg_feature_gates,
            type_def.span,
            patterns,
            feature,
            fp,
            violations,
        );
    }
}

fn maybe_flag(
    name: &str,
    gates: &[Arc<str>],
    span: IrSpan,
    patterns: &[Arc<str>],
    feature: &str,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    let is_test_only = patterns.iter().any(|pattern| matches_glob(pattern, name));
    let is_gated = gates.iter().any(|gate| &**gate == feature);
    if is_test_only && !is_gated {
        emit_violation(
            violations,
            fp,
            span,
            ViolationType::UngatedTestApi,
            format!(
                "test-only API `{name}` in `src/` is not gated behind `#[cfg(feature = \"{feature}\")]`"
            ),
        );
    }
}

/// True when any path component is `src`.
fn is_under_src(fp: &str) -> bool {
    fp.split(['/', '\\']).any(|component| component == "src")
}
