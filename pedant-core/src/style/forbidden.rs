use std::sync::Arc;

use crate::check_config::{CheckConfig, PatternCheck};
use crate::ir::{FileIr, IrSpan};
use crate::pattern::matches_pattern;
use crate::violation::{Violation, ViolationType};

use super::common::emit_violation;

pub(super) fn check_all_forbidden(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    check_forbidden_patterns(
        &config.forbid_attributes,
        ir.attributes.iter().map(|a| (a.span, &*a.text)),
        |p| ViolationType::ForbiddenAttribute { pattern: p },
        fp,
        violations,
    );

    check_forbidden_patterns(
        &config.forbid_types,
        ir.type_refs.iter().map(|t| (t.span, &*t.text)),
        |p| ViolationType::ForbiddenType { pattern: p },
        fp,
        violations,
    );

    check_forbidden_patterns(
        &config.forbid_calls,
        ir.method_calls.iter().map(|m| (m.span, &*m.text)),
        |p| ViolationType::ForbiddenCall { pattern: p },
        fp,
        violations,
    );

    check_forbidden_patterns(
        &config.forbid_macros,
        ir.macro_invocations.iter().map(|m| (m.span, &*m.text)),
        |p| ViolationType::ForbiddenMacro { pattern: p },
        fp,
        violations,
    );

    check_let_underscore_result(ir, config, fp, violations);
    check_unsafe(ir, config, fp, violations);
    check_inline_tests(ir, config, fp, violations);
}

fn match_forbidden(check: &PatternCheck, text: &str) -> Option<Arc<str>> {
    check
        .patterns
        .iter()
        .find(|p| matches_pattern(text, p))
        .map(Arc::clone)
}

fn check_forbidden_patterns<'a>(
    check: &PatternCheck,
    items: impl Iterator<Item = (IrSpan, &'a str)>,
    make_violation: impl Fn(Arc<str>) -> ViolationType,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !check.enabled {
        return;
    }
    for (span, text) in items {
        let Some(pattern) = match_forbidden(check, text) else {
            continue;
        };
        emit_violation(violations, fp, span, make_violation(pattern), text);
    }
}

fn check_let_underscore_result(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_let_underscore_result {
        return;
    }
    for binding in &ir.bindings {
        if !binding.is_wildcard || !binding.has_init || binding.init_is_write_macro {
            continue;
        }
        let Some(span) = binding.span else { continue };
        emit_violation(
            violations,
            fp,
            span,
            ViolationType::LetUnderscoreResult,
            "let _ = discards a Result; handle the error or use an assertion",
        );
    }
}

fn check_unsafe(ir: &FileIr, config: &CheckConfig, fp: &Arc<str>, violations: &mut Vec<Violation>) {
    if !config.forbid_unsafe {
        return;
    }
    for site in &ir.unsafe_sites {
        if site.kind != crate::ir::UnsafeKind::Block {
            continue;
        }
        emit_violation(
            violations,
            fp,
            site.span,
            ViolationType::ForbiddenUnsafe,
            "unsafe block detected",
        );
    }
}

fn check_inline_tests(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_inline_tests {
        return;
    }
    for module in &ir.modules {
        if !module.is_cfg_test {
            continue;
        }
        emit_violation(
            violations,
            fp,
            module.span,
            ViolationType::InlineTests,
            format!(
                "test module `{}` should be in tests/ directory",
                module.name
            ),
        );
    }
}
