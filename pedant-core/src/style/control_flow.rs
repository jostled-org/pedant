use std::sync::Arc;

use crate::check_config::CheckConfig;
use crate::ir::{BranchContext, ControlFlowKind, FileIr};
use crate::violation::{Violation, ViolationType};

use super::common::emit_violation;

pub(super) fn check_control_flow(
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
