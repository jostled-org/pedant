use crate::check_config::CheckConfig;
use crate::ir::FileIr;
use crate::violation::Violation;

use super::{
    control_flow, dyn_dispatch, forbidden, mixed_concerns, module_root, naming, size, test_api,
    visibility,
};

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
    size::check_long_function_body(ir, config, fp, &mut violations);
    size::check_large_source_file(ir, config, fp, &mut violations);
    size::check_high_method_count(ir, config, fp, &mut violations);
    module_root::check_module_root_definitions(ir, config, fp, &mut violations);
    visibility::check_item_visibility_policy(ir, config, fp, &mut violations);
    test_api::check_ungated_test_api(ir, config, fp, &mut violations);
    mixed_concerns::check_mixed_concerns(ir, config, fp, &mut violations);

    violations
}
