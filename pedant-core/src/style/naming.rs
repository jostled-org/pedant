use std::collections::BTreeMap;
use std::sync::Arc;

use crate::check_config::CheckConfig;
use crate::ir::type_introspection::classify_single_char;
use crate::ir::{BindingFact, FileIr};
use crate::violation::{Violation, ViolationType};

use super::common::emit_violation;

pub(super) fn check_naming(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_naming.enabled {
        return;
    }
    let generic_names = &config.check_naming.generic_names;

    let mut bindings_by_fn: BTreeMap<usize, Vec<&BindingFact>> = BTreeMap::new();
    for b in &ir.bindings {
        let Some(fn_idx) = b.containing_fn else {
            continue;
        };
        if b.is_wildcard || b.name.starts_with('_') {
            continue;
        }
        bindings_by_fn.entry(fn_idx).or_default().push(b);
    }

    for (fn_idx, func) in ir.functions.iter().enumerate() {
        let has_arithmetic = func.has_arithmetic;
        let fn_bindings = match bindings_by_fn.get(&fn_idx) {
            Some(bs) => bs,
            None => continue,
        };

        let total = fn_bindings.len();
        if total == 0 {
            continue;
        }
        let offenders: Vec<&str> = fn_bindings
            .iter()
            .filter(|b| is_generic_name(&b.name, b.loop_depth, has_arithmetic, generic_names))
            .map(|b| b.name.as_ref())
            .collect();
        let generic_count = offenders.len();
        if generic_count < config.check_naming.min_generic_count {
            continue;
        }
        let ratio = generic_count as f64 / total as f64;
        if ratio <= config.check_naming.max_generic_ratio {
            continue;
        }
        let offender_list = offenders.join(", ");
        emit_violation(
            violations,
            fp,
            func.span,
            ViolationType::GenericNaming,
            format!(
                "{generic_count}/{total} bindings are generic ({offender_list}), use domain-specific names",
            ),
        );
    }
}

pub(super) fn check_high_param_count(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_high_param_count {
        return;
    }
    for func in &ir.functions {
        let count = func.params.iter().filter(|p| &*p.name != "self").count();
        if count > config.max_params {
            emit_violation(
                violations,
                fp,
                func.span,
                ViolationType::HighParamCount,
                format!(
                    "`{}` has {count} parameters (limit: {}), group into a struct",
                    func.name, config.max_params
                ),
            );
        }
    }
}

fn is_generic_name(
    name: &str,
    loop_depth: usize,
    has_arithmetic: bool,
    generic_names: &[Arc<str>],
) -> bool {
    classify_single_char(name, loop_depth, has_arithmetic)
        .unwrap_or_else(|| generic_names.iter().any(|g| g.as_ref() == name))
}
