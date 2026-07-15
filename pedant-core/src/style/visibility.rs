use std::sync::Arc;

use crate::check_config::{CheckConfig, ItemVisibilityRule};
use crate::ir::{FileIr, IrSpan, TypeDefKind, Visibility};
use crate::violation::{Violation, ViolationType, VisibilityDetail};

use super::common::emit_violation;

/// Enforce configured item-visibility policies: a named item at a path must
/// exist exactly once, of the configured kind, with the exact visibility.
pub(super) fn check_item_visibility_policy(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_item_visibility_policy {
        return;
    }
    for rule in config.item_visibility_policy.iter() {
        if path_matches(fp, &rule.path) {
            evaluate_rule(ir, rule, fp, violations);
        }
    }
}

/// Match the analyzed file against a repository-relative policy path by suffix,
/// so the rule fires regardless of absolute/relative invocation.
fn path_matches(fp: &str, rule_path: &str) -> bool {
    let fp = fp.replace('\\', "/");
    let rule = rule_path.replace('\\', "/");
    fp == rule || fp.ends_with(&format!("/{rule}"))
}

fn evaluate_rule(
    ir: &FileIr,
    rule: &ItemVisibilityRule,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    let expected = rule.visibility.trim();
    let of_kind = collect_of_kind(ir, rule.kind.trim(), &rule.name);

    let (span, observed) = match of_kind.as_slice() {
        // Exactly one item with the required visibility: clean.
        [(_, visibility)] if visibility.to_string() == expected => return,
        [(span, visibility)] => (*span, visibility.to_string()),
        [] => {
            let (span, label) = absent_detail(ir, &rule.name);
            (span, label.to_string())
        }
        duplicates => (duplicates[0].0, "duplicate".to_string()),
    };

    emit_violation(
        violations,
        fp,
        span,
        ViolationType::ItemVisibilityPolicy {
            detail: VisibilityDetail {
                subject: Arc::from(&*rule.name),
                expected: Arc::from(expected),
                observed: Arc::from(observed.as_str()),
            },
        },
        format!(
            "`{}` ({}): expected visibility `{expected}`, found `{observed}`",
            rule.name,
            rule.kind.trim()
        ),
    );
}

/// Collect items matching the configured kind and name, with their span and
/// visibility. `fn` matches free functions only; associated methods are skipped.
fn collect_of_kind<'a>(ir: &'a FileIr, kind: &str, name: &str) -> Vec<(IrSpan, &'a Visibility)> {
    match kind_to_typedef(kind) {
        Some(td_kind) => ir
            .type_defs
            .iter()
            .filter(|t| &*t.name == name && t.kind == td_kind)
            .map(|t| (t.span, &t.visibility))
            .collect(),
        None if kind == "fn" => ir
            .functions
            .iter()
            .filter(|f| &*f.name == name && !f.is_associated)
            .map(|f| (f.span, &f.visibility))
            .collect(),
        None => Vec::new(),
    }
}

fn kind_to_typedef(kind: &str) -> Option<TypeDefKind> {
    match kind {
        "struct" => Some(TypeDefKind::Struct),
        "enum" => Some(TypeDefKind::Enum),
        "union" => Some(TypeDefKind::Union),
        "trait" => Some(TypeDefKind::Trait),
        _ => None,
    }
}

/// Distinguish an absent item from one that exists under a different kind, and
/// return a span to anchor the finding on.
fn absent_detail(ir: &FileIr, name: &str) -> (IrSpan, &'static str) {
    if let Some(type_def) = ir.type_defs.iter().find(|t| &*t.name == name) {
        return (type_def.span, "wrong-kind");
    }
    if let Some(func) = ir
        .functions
        .iter()
        .find(|f| &*f.name == name && !f.is_associated)
    {
        return (func.span, "wrong-kind");
    }
    (IrSpan { line: 1, column: 0 }, "missing")
}
