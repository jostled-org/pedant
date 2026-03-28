use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::check_config::{CheckConfig, PatternCheck};
use crate::graph::bfs_component;
use crate::ir::type_introspection::classify_single_char;
use crate::ir::{BindingFact, BranchContext, ControlFlowKind, FileIr, IrSpan, TypeRefContext};
use crate::pattern::matches_pattern;
use crate::violation::{Violation, ViolationType};

/// Entry point: runs every enabled style check over a file's IR facts.
pub fn check_style(ir: &FileIr, config: &CheckConfig) -> Vec<Violation> {
    let mut violations = Vec::new();
    let fp = &ir.file_path;

    check_control_flow(ir, config, fp, &mut violations);

    check_forbidden_patterns(
        &config.forbid_attributes,
        ir.attributes.iter().map(|a| (a.span, &*a.text)),
        |p| ViolationType::ForbiddenAttribute { pattern: p },
        fp,
        &mut violations,
    );

    check_forbidden_patterns(
        &config.forbid_types,
        ir.type_refs.iter().map(|t| (t.span, &*t.text)),
        |p| ViolationType::ForbiddenType { pattern: p },
        fp,
        &mut violations,
    );

    check_forbidden_patterns(
        &config.forbid_calls,
        ir.method_calls.iter().map(|m| (m.span, &*m.text)),
        |p| ViolationType::ForbiddenCall { pattern: p },
        fp,
        &mut violations,
    );

    check_forbidden_patterns(
        &config.forbid_macros,
        ir.macro_invocations.iter().map(|m| (m.span, &*m.text)),
        |p| ViolationType::ForbiddenMacro { pattern: p },
        fp,
        &mut violations,
    );
    check_dyn_dispatch(ir, config, fp, &mut violations);
    check_default_hasher_refs(ir, config, fp, &mut violations);
    check_clone_in_loop(ir, config, fp, &mut violations);
    check_let_underscore_result(ir, config, fp, &mut violations);
    check_unsafe(ir, config, fp, &mut violations);
    check_inline_tests(ir, config, fp, &mut violations);
    check_naming(ir, config, fp, &mut violations);
    check_mixed_concerns(ir, config, fp, &mut violations);
    check_high_param_count(ir, config, fp, &mut violations);

    violations
}

fn emit_violation(
    violations: &mut Vec<Violation>,
    fp: &Arc<str>,
    span: IrSpan,
    violation_type: ViolationType,
    message: impl Into<Box<str>>,
) {
    violations.push(Violation::new(
        violation_type,
        Arc::clone(fp),
        span.line,
        span.column + 1,
        message,
    ));
}

fn check_control_flow(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    for cf in &ir.control_flow {
        if cf.depth > config.max_depth {
            emit_violation(
                violations,
                fp,
                cf.span,
                ViolationType::MaxDepth,
                format!(
                    "nesting depth {} exceeds limit of {}",
                    cf.depth, config.max_depth
                ),
            );
        }

        match cf.kind {
            ControlFlowKind::If => {
                check_if_branching(cf, config, fp, violations);
            }
            ControlFlowKind::Match => {
                check_match_branching(cf, config, fp, violations);
            }
            _ => {}
        }
    }
}

fn check_if_branching(
    cf: &crate::ir::ControlFlowFact,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    match cf.parent_branch {
        Some(BranchContext::If) if config.check_nested_if => {
            emit_violation(
                violations,
                fp,
                cf.span,
                ViolationType::NestedIf,
                "if nested inside if, consider combining conditions",
            );
        }
        Some(BranchContext::Match) if config.check_if_in_match => {
            emit_violation(
                violations,
                fp,
                cf.span,
                ViolationType::IfInMatch,
                "if inside match arm, consider match guard",
            );
        }
        _ => {}
    }

    let Some(ref else_info) = cf.else_info else {
        return;
    };

    if let (true, Some(chain_len)) = (
        config.check_else_chain,
        else_info
            .chain_len
            .filter(|&len| len >= config.else_chain_threshold),
    ) {
        emit_violation(
            violations,
            fp,
            cf.span,
            ViolationType::ElseChain,
            format!("if/else chain has {chain_len} branches, consider match"),
        );
    }

    if let (true, Some(else_sp)) = (config.forbid_else, else_info.span) {
        emit_violation(
            violations,
            fp,
            else_sp,
            ViolationType::ForbiddenElse,
            "use match or early return instead of else",
        );
    }
}

fn check_match_branching(
    cf: &crate::ir::ControlFlowFact,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    match cf.parent_branch {
        Some(BranchContext::Match) if config.check_nested_match => {
            emit_violation(
                violations,
                fp,
                cf.span,
                ViolationType::NestedMatch,
                "nested match expression, consider tuple matching",
            );
        }
        Some(BranchContext::If) if config.check_match_in_if => {
            emit_violation(
                violations,
                fp,
                cf.span,
                ViolationType::MatchInIf,
                "match inside if, consider restructuring",
            );
        }
        _ => {}
    }
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

fn check_dyn_dispatch(
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

fn check_default_hasher_refs(
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

fn check_clone_in_loop(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_clone_in_loop {
        return;
    }

    // Build per-function set of refcounted binding names
    let mut refcounted_by_fn: BTreeMap<usize, BTreeSet<&str>> = BTreeMap::new();
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

fn is_generic_name(
    name: &str,
    loop_depth: usize,
    has_arithmetic: bool,
    generic_names: &[Arc<str>],
) -> bool {
    classify_single_char(name, loop_depth, has_arithmetic)
        .unwrap_or_else(|| generic_names.iter().any(|g| g.as_ref() == name))
}

fn check_naming(ir: &FileIr, config: &CheckConfig, fp: &Arc<str>, violations: &mut Vec<Violation>) {
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
        let generic_count = fn_bindings
            .iter()
            .filter(|b| is_generic_name(&b.name, b.loop_depth, has_arithmetic, generic_names))
            .count();
        if generic_count < config.check_naming.min_generic_count {
            continue;
        }
        let ratio = generic_count as f64 / total as f64;
        if ratio <= config.check_naming.max_generic_ratio {
            continue;
        }
        let offender_list: Vec<&str> = fn_bindings
            .iter()
            .filter(|b| is_generic_name(&b.name, b.loop_depth, has_arithmetic, generic_names))
            .map(|b| b.name.as_ref())
            .collect();
        let offender_list = offender_list.join(", ");
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

fn check_mixed_concerns(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_mixed_concerns || ir.type_defs.len() < 2 {
        return;
    }

    let defined_types: BTreeSet<&str> = ir.type_defs.iter().map(|td| td.name.as_ref()).collect();

    let type_def_iter = ir
        .type_defs
        .iter()
        .flat_map(|td| td.edges.iter().map(|(a, b)| (a.as_ref(), b.as_ref())));

    let impl_iter = ir
        .impl_blocks
        .iter()
        .flat_map(|ib| ib.edges.iter().map(|(a, b)| (a.as_ref(), b.as_ref())));

    let mut fn_edges: Vec<(&str, &str)> = Vec::new();
    for func in &ir.functions {
        if func.item_depth == 0 {
            let names = &func.signature_type_names;
            crate::graph::for_each_pair(names.len(), |i, j| {
                fn_edges.push((names[i].as_ref(), names[j].as_ref()));
            });
        }
        fn_edges.extend(
            func.body_type_edges
                .iter()
                .map(|(a, b)| (a.as_ref(), b.as_ref())),
        );
    }

    let all_edges = type_def_iter.chain(impl_iter).chain(fn_edges);

    let Some(message) = find_disconnected_groups(&defined_types, all_edges) else {
        return;
    };
    emit_violation(
        violations,
        fp,
        IrSpan { line: 1, column: 0 },
        ViolationType::MixedConcerns,
        message,
    );
}

fn check_high_param_count(
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

fn find_disconnected_groups<'a>(
    defined_types: &BTreeSet<&'a str>,
    all_edges: impl Iterator<Item = (&'a str, &'a str)>,
) -> Option<Box<str>> {
    let mut adj: BTreeMap<&str, Vec<&str>> = defined_types
        .iter()
        .map(|&name| (name, Vec::new()))
        .collect();
    for (src, dst) in all_edges {
        if src == dst || !defined_types.contains(src) || !defined_types.contains(dst) {
            continue;
        }
        adj.entry(src).or_default().push(dst);
        adj.entry(dst).or_default().push(src);
    }

    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut components: Vec<Vec<&str>> = Vec::new();

    for name in defined_types {
        if visited.contains(name) {
            continue;
        }
        components.push(bfs_component(name, &adj, &mut visited));
    }

    if components.len() < 2 {
        return None;
    }

    components.sort_by(|a, b| a.first().cmp(&b.first()));
    let mut result = String::from("disconnected type groups: ");
    for (i, c) in components.iter().enumerate() {
        if i > 0 {
            result.push_str(", ");
        }
        result.push('{');
        result.push_str(&c.join(", "));
        result.push('}');
    }
    Some(result.into_boxed_str())
}
