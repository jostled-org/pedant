mod common;
mod control_flow;
mod dyn_dispatch;
mod forbidden;
mod mixed_concerns;
mod naming;

use crate::check_config::CheckConfig;
use crate::ir::FileIr;
use crate::violation::Violation;

/// Entry point: runs every enabled style check over a file's IR facts.
pub fn check_style(ir: &FileIr, config: &CheckConfig) -> Vec<Violation> {
    let mut violations = Vec::new();
    let fp = &ir.file_path;

    control_flow::check_control_flow(ir, config, fp, &mut violations);
    forbidden::check_all_forbidden(ir, config, fp, &mut violations);
    dyn_dispatch::check_dyn_dispatch(ir, config, fp, &mut violations);
    dyn_dispatch::check_default_hasher_refs(ir, config, fp, &mut violations);
    dyn_dispatch::check_clone_in_loop(ir, config, fp, &mut violations);
    naming::check_naming(ir, config, fp, &mut violations);
    naming::check_high_param_count(ir, config, fp, &mut violations);
    mixed_concerns::check_mixed_concerns(ir, config, fp, &mut violations);

    violations
}
