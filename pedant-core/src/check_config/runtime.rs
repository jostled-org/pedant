use std::borrow::Cow;
use std::sync::Arc;

use super::file::{
    ConfigFile, FeatureBoundaryRule, FlatModuleFamily, ItemVisibilityRule, PathOverride,
    default_else_chain_threshold, default_max_depth, default_max_function_body_lines,
    default_max_methods, default_max_params, default_module_root_files,
    default_source_file_deny_lines, default_source_file_warn_lines, default_test_api_patterns,
    default_test_support_feature,
};
use super::naming::NamingCheck;
use super::pattern::PatternCheck;
use crate::pattern::matches_glob;

/// Find the most specific `[overrides]` entry whose glob matches `file_path`.
///
/// When multiple patterns match, the longest pattern wins. If two patterns
/// have the same length, lexicographic (sorted) order breaks the tie.
/// This makes override precedence deterministic and independent of
/// declaration order in the config file.
pub fn check_path_override<'a>(
    file_path: &str,
    config: &'a ConfigFile,
) -> Option<&'a PathOverride> {
    config
        .overrides
        .iter()
        .filter(|(pattern, _)| matches_glob(pattern, file_path))
        .max_by_key(|(pattern, _)| pattern.len())
        .map(|(_, override_config)| override_config)
}

/// Single source of truth for boolean check fields.
///
/// Each entry: `"doc", field_name, default_value;`
///
/// Adding a new boolean check requires:
/// 1. Add one line here
/// 2. Add the field to `ConfigFile` (bool) and `PathOverride` (Option<bool>)
///
/// The macro generates `CheckConfig` fields + Default + from_config_file +
/// merge_bool_overrides. A compile-time assertion (`assert_bool_fields_in_sync`)
/// catches missing fields in `ConfigFile` or `PathOverride`.
///
/// Non-boolean fields (max_depth, forbid_*, check_naming, etc.) stay hand-written.
macro_rules! for_each_bool_check {
    ($callback:ident!) => {
        $callback! {
            "Flag `if` inside `if`.", check_nested_if, true;
            "Flag `if` inside `match` arm.", check_if_in_match, true;
            "Flag `match` inside `match`.", check_nested_match, true;
            "Flag `match` inside `if` branch.", check_match_in_if, true;
            "Flag long `if/else if` chains.", check_else_chain, true;
            "Flag any use of the `else` keyword.", forbid_else, false;
            "Flag any `unsafe` block.", forbid_unsafe, true;
            "Flag dynamic dispatch in return types.", check_dyn_return, false;
            "Flag dynamic dispatch in function parameters.", check_dyn_param, false;
            "Flag `Vec<Box<dyn T>>`.", check_vec_box_dyn, false;
            "Flag dynamic dispatch in struct fields.", check_dyn_field, false;
            "Flag `.clone()` inside loop bodies.", check_clone_in_loop, false;
            "Flag `HashMap`/`HashSet` with default hasher.", check_default_hasher, false;
            "Flag disconnected type groups in a single file.", check_mixed_concerns, false;
            "Flag `#[cfg(test)] mod` blocks in source files.", check_inline_tests, false;
            "Flag `let _ = expr` that discards a Result.", check_let_underscore_result, false;
            "Flag functions with too many parameters.", check_high_param_count, false;
            "Flag function bodies that exceed the line ceiling.", check_long_function_body, false;
            "Flag item definitions in module-root files.", check_module_root_definitions, false;
            "Flag source files that exceed the line ceiling.", check_large_source_file, false;
            "Flag god-object types by inherent-method count.", check_high_method_count, false;
            "Count pure forwarders toward `high-method-count`.", count_forwarders, false;
            "Enforce configured item-visibility policies.", check_item_visibility_policy, true;
            "Flag ungated test-only APIs under `src/`.", check_ungated_test_api, false;
            "Flag sibling `<stem>.rs` and `<stem>/` module roots.", check_conflicting_module_root, false;
            "Enforce configured flat-module-family layout rules.", check_flat_module_family, true;
            "Enforce configured Cargo feature-boundary invariants.", check_feature_boundary, true;
            "Flag types whose inherent impls span more than one file.", check_scattered_inherent_impl, false;
        }
    };
}

/// Generates `CheckConfig` struct (boolean fields + non-boolean fields),
/// `Default`, `from_config_file`, and `merge_bool_overrides`.
macro_rules! impl_check_config {
    ($($doc:literal, $field:ident, $default:expr;)*) => {
        /// Configuration controlling which checks are enabled and their thresholds.
        #[derive(Debug, Clone)]
        pub struct CheckConfig {
            /// Maximum allowed nesting depth.
            pub max_depth: usize,
            /// Minimum branches to trigger `else-chain`.
            pub else_chain_threshold: usize,
            /// Maximum parameter count before `high-param-count` fires.
            pub max_params: usize,
            /// Body line count before `long-function-body` fires.
            pub max_function_body_lines: usize,
            /// File names treated as module roots by `module-root-definitions`.
            pub module_root_files: Arc<[Arc<str>]>,
            /// Line count at which `large-source-file` emits a `Warn`.
            pub source_file_warn_lines: usize,
            /// Line count at which `large-source-file` emits a `Deny`.
            pub source_file_deny_lines: usize,
            /// Inherent-method count before `high-method-count` fires.
            pub max_methods: usize,
            /// Item-visibility policy rules.
            pub item_visibility_policy: Arc<[ItemVisibilityRule]>,
            /// Flat-module-family layout rules.
            pub flat_module_families: Arc<[FlatModuleFamily]>,
            /// Cargo feature-boundary invariants.
            pub feature_boundaries: Arc<[FeatureBoundaryRule]>,
            /// Name globs marking test-only APIs for `ungated-test-api`.
            pub test_api_patterns: Arc<[Arc<str>]>,
            /// Feature that must gate a test-only API.
            pub test_support_feature: Arc<str>,
            /// Banned attribute patterns.
            pub forbid_attributes: PatternCheck,
            /// Banned type patterns.
            pub forbid_types: PatternCheck,
            /// Banned method call patterns.
            pub forbid_calls: PatternCheck,
            /// Banned macro patterns.
            pub forbid_macros: PatternCheck,
            /// Generic naming check configuration.
            pub check_naming: NamingCheck,
            $(
                #[doc = $doc]
                pub $field: bool,
            )*
        }

        impl Default for CheckConfig {
            fn default() -> Self {
                Self {
                    max_depth: default_max_depth(),
                    else_chain_threshold: default_else_chain_threshold(),
                    max_params: default_max_params(),
                    max_function_body_lines: default_max_function_body_lines(),
                    module_root_files: default_module_root_files(),
                    source_file_warn_lines: default_source_file_warn_lines(),
                    source_file_deny_lines: default_source_file_deny_lines(),
                    max_methods: default_max_methods(),
                    item_visibility_policy: Arc::from([]),
                    flat_module_families: Arc::from([]),
                    feature_boundaries: Arc::from([]),
                    test_api_patterns: default_test_api_patterns(),
                    test_support_feature: Arc::from(default_test_support_feature()),
                    forbid_attributes: PatternCheck::default(),
                    forbid_types: PatternCheck::default(),
                    forbid_calls: PatternCheck::default(),
                    forbid_macros: PatternCheck::default(),
                    check_naming: NamingCheck::default(),
                    $( $field: $default, )*
                }
            }
        }

        impl CheckConfig {
            /// Build from a [`ConfigFile`], copying all fields.
            pub fn from_config_file(fc: &ConfigFile) -> Self {
                Self {
                    max_depth: fc.max_depth,
                    else_chain_threshold: fc.else_chain_threshold,
                    max_params: fc.max_params,
                    max_function_body_lines: fc.max_function_body_lines,
                    module_root_files: fc.module_root_files.clone(),
                    source_file_warn_lines: fc.source_file_warn_lines,
                    source_file_deny_lines: fc.source_file_deny_lines,
                    max_methods: fc.max_methods,
                    item_visibility_policy: fc.item_visibility_policy.iter().cloned().collect(),
                    flat_module_families: fc.flat_module_families.iter().cloned().collect(),
                    feature_boundaries: fc.feature_boundaries.iter().cloned().collect(),
                    test_api_patterns: fc.test_api_patterns.clone(),
                    test_support_feature: Arc::from(&*fc.test_support_feature),
                    forbid_attributes: fc.forbid_attributes.clone(),
                    forbid_types: fc.forbid_types.clone(),
                    forbid_calls: fc.forbid_calls.clone(),
                    forbid_macros: fc.forbid_macros.clone(),
                    check_naming: fc.check_naming.clone(),
                    $( $field: fc.$field, )*
                }
            }

            /// Apply `Option<bool>` overrides from a [`PathOverride`].
            pub fn merge_bool_overrides(&mut self, ovr: &PathOverride) {
                $(
                    if let Some(v) = ovr.$field {
                        self.$field = v;
                    }
                )*
            }
        }
    };
}

for_each_bool_check!(impl_check_config!);

/// Compile-time assertion: every boolean check field in `for_each_bool_check!`
/// must exist in `ConfigFile` (as `bool`) and `PathOverride` (as `Option<bool>`).
/// Adding a field to the macro without updating these structs is a compile error.
macro_rules! assert_bool_fields_in_sync {
    ($($doc:literal, $field:ident, $default:expr;)*) => {
        const _: () = {
            // Access each field on both structs. If a field is missing
            // from either, this block fails to compile.
            const fn _check(cf: &ConfigFile, po: &PathOverride) {
                $( let _ = (cf.$field, po.$field); )*
            }
        };
    };
}

for_each_bool_check!(assert_bool_fields_in_sync!);

impl CheckConfig {
    /// Returns the effective config for a file path.
    ///
    /// Borrows `self` when no overrides match (zero clones).
    /// Clones and mutates only when a path override applies.
    /// Returns `None` when the override disables analysis for this path.
    pub fn resolve_for_path<'a>(
        &'a self,
        file_path: &str,
        file_config: Option<&ConfigFile>,
    ) -> Option<Cow<'a, Self>> {
        let Some(fc) = file_config else {
            return Some(Cow::Borrowed(self));
        };

        let Some(override_cfg) = check_path_override(file_path, fc) else {
            return Some(Cow::Borrowed(self));
        };

        if override_cfg.enabled == Some(false) {
            return None;
        }

        let mut config = self.clone();
        if let Some(max_depth) = override_cfg.max_depth {
            config.max_depth = max_depth;
        }
        if let Some(max_params) = override_cfg.max_params {
            config.max_params = max_params;
        }
        if let Some(max_body) = override_cfg.max_function_body_lines {
            config.max_function_body_lines = max_body;
        }
        if let Some(warn) = override_cfg.source_file_warn_lines {
            config.source_file_warn_lines = warn;
        }
        if let Some(deny) = override_cfg.source_file_deny_lines {
            config.source_file_deny_lines = deny;
        }
        if let Some(max_methods) = override_cfg.max_methods {
            config.max_methods = max_methods;
        }

        config.merge_bool_overrides(override_cfg);

        macro_rules! apply {
            ($field:ident) => {
                if let Some(ref ovr) = override_cfg.$field {
                    config.$field.apply_override(ovr);
                }
            };
        }
        apply!(forbid_attributes);
        apply!(forbid_types);
        apply!(forbid_calls);
        apply!(forbid_macros);
        apply!(check_naming);

        Some(Cow::Owned(config))
    }
}
