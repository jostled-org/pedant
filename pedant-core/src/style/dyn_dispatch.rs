use std::sync::Arc;

use crate::check_config::CheckConfig;
use crate::ir::{FileIr, TypeRefContext};
use crate::violation::{Violation, ViolationType};

use super::common::emit_violation;

/// Table entry for dyn-dispatch checks that share the pattern:
/// "if config flag && tr.involves_dyn, emit formatted message".
struct DynCheck {
    context: TypeRefContext,
    enabled: fn(&CheckConfig) -> bool,
    make_violation: fn() -> ViolationType,
    label: &'static str,
}

const DYN_CHECKS: &[DynCheck] = &[
    DynCheck {
        context: TypeRefContext::Return,
        enabled: |c| c.check_dyn_return,
        make_violation: || ViolationType::DynReturn,
        label: "return type",
    },
    DynCheck {
        context: TypeRefContext::Param,
        enabled: |c| c.check_dyn_param,
        make_violation: || ViolationType::DynParam,
        label: "parameter",
    },
    DynCheck {
        context: TypeRefContext::Field,
        enabled: |c| c.check_dyn_field,
        make_violation: || ViolationType::DynField,
        label: "struct field",
    },
];

pub(super) fn check_dyn_dispatch(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    for tr in &ir.type_refs {
        let matched = DYN_CHECKS
            .iter()
            .find(|dc| dc.context == tr.context && (dc.enabled)(config) && tr.involves_dyn);
        match matched {
            Some(dc) => {
                emit_violation(
                    violations,
                    fp,
                    tr.span,
                    (dc.make_violation)(),
                    format!("dynamic dispatch in {}: {}", dc.label, tr.text),
                );
            }
            None if config.check_vec_box_dyn && tr.is_vec_box_dyn => {
                emit_violation(
                    violations,
                    fp,
                    tr.span,
                    ViolationType::VecBoxDyn,
                    format!("Vec of boxed trait object: {}", tr.text),
                );
            }
            None => {}
        }
    }
}

pub(super) fn check_default_hasher_refs(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_default_hasher {
        return;
    }
    for tr in &ir.type_refs {
        if !tr.is_default_hasher {
            continue;
        }
        emit_violation(
            violations,
            fp,
            tr.span,
            ViolationType::DefaultHasher,
            format!("default SipHash hasher: {}", tr.text),
        );
    }
}

pub(super) fn check_clone_in_loop(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_clone_in_loop {
        return;
    }

    // Build per-function set of refcounted binding names
    let mut refcounted_by_fn: std::collections::BTreeMap<usize, std::collections::BTreeSet<&str>> =
        std::collections::BTreeMap::new();
    for binding in &ir.bindings {
        if let (true, Some(fn_idx)) = (binding.is_refcounted, binding.containing_fn) {
            refcounted_by_fn
                .entry(fn_idx)
                .or_default()
                .insert(&binding.name);
        }
    }

    for mc in &ir.method_calls {
        if mc.loop_depth == 0 || &*mc.method_name != "clone" {
            continue;
        }
        let is_refcounted = mc
            .receiver_ident
            .as_deref()
            .and_then(|recv| {
                mc.containing_fn
                    .and_then(|fn_idx| refcounted_by_fn.get(&fn_idx))
                    .map(|set| set.contains(recv))
            })
            .unwrap_or(false);
        if is_refcounted {
            continue;
        }
        emit_violation(
            violations,
            fp,
            mc.span,
            ViolationType::CloneInLoop,
            ".clone() inside loop body allocates per iteration",
        );
    }
}
