use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use serde::Deserialize;

use super::gate::GateConfig;
use super::naming::{NamingCheck, NamingOverride};
use super::pattern::{PatternCheck, PatternOverride};
use super::string_list::deserialize_arc_str_slice;

/// One `item-visibility-policy` rule: a named item at a path must have an
/// exact visibility.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ItemVisibilityRule {
    /// Repository-relative source path the item must live in.
    pub path: Box<str>,
    /// Item kind: `struct`, `enum`, `union`, `trait`, or `fn`.
    pub kind: Box<str>,
    /// Exact item name.
    pub name: Box<str>,
    /// Required visibility: `private`, `pub`, `pub(crate)`, `pub(super)`,
    /// or `pub(in <path>)`.
    pub visibility: Box<str>,
}

/// One `feature-boundary` rule: a package feature must obey the named invariant.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FeatureBoundaryRule {
    /// The package whose feature is constrained.
    pub package: Box<str>,
    /// The feature name the rule applies to.
    pub feature: Box<str>,
    /// `no-default` (must not be reachable from any default feature) or
    /// `dev-only` (may be enabled only through dev-dependency edges).
    pub rule: Box<str>,
}

/// One `flat-module-family` rule: a prefixed module family under `parent` must
/// live below `parent/package_root/`.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FlatModuleFamily {
    /// Directory (repo-relative) whose direct children are checked.
    pub parent: Box<str>,
    /// Sub-directory of `parent` where the family must live.
    pub package_root: Box<str>,
    /// Module-name prefix identifying family members.
    pub prefix: Box<str>,
}

/// Deserialized `.pedant.toml` file with all check settings.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// Security gate rules configuration.
    #[serde(default)]
    pub gate: GateConfig,
    /// Depth limit for nesting checks (default: 3).
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    /// Branch count that triggers `else-chain` (default: 3).
    #[serde(default = "default_else_chain_threshold")]
    pub else_chain_threshold: usize,
    /// Maximum parameter count before `high-param-count` fires (default: 5).
    #[serde(default = "default_max_params")]
    pub max_params: usize,
    /// Body line count before `long-function-body` fires (default: 120).
    #[serde(default = "default_max_function_body_lines")]
    pub max_function_body_lines: usize,
    /// File names treated as module roots by `module-root-definitions`
    /// (default: `mod.rs`, `lib.rs`).
    #[serde(
        default = "default_module_root_files",
        deserialize_with = "deserialize_arc_str_slice"
    )]
    pub module_root_files: Arc<[Arc<str>]>,
    /// Line count at which `large-source-file` emits a `Warn` (default: 500).
    #[serde(default = "default_source_file_warn_lines")]
    pub source_file_warn_lines: usize,
    /// Line count at which `large-source-file` emits a `Deny` (default: 1000).
    #[serde(default = "default_source_file_deny_lines")]
    pub source_file_deny_lines: usize,
    /// Inherent-method count before `high-method-count` fires (default: 40).
    #[serde(default = "default_max_methods")]
    pub max_methods: usize,
    /// Banned attribute patterns (e.g., `allow(dead_code)`).
    #[serde(default)]
    pub forbid_attributes: PatternCheck,
    /// Banned type patterns (e.g., `Arc<String>`).
    #[serde(default)]
    pub forbid_types: PatternCheck,
    /// Banned method call patterns (e.g., `.unwrap()`).
    #[serde(default)]
    pub forbid_calls: PatternCheck,
    /// Banned macro patterns (e.g., `panic!`).
    #[serde(default)]
    pub forbid_macros: PatternCheck,
    /// Thresholds for the generic-naming check.
    #[serde(default)]
    pub check_naming: NamingCheck,
    /// Flag `if` inside `if`.
    #[serde(default = "default_true")]
    pub check_nested_if: bool,
    /// Flag `if` inside `match` arm.
    #[serde(default = "default_true")]
    pub check_if_in_match: bool,
    /// Flag `match` inside `match`.
    #[serde(default = "default_true")]
    pub check_nested_match: bool,
    /// Flag `match` inside `if` branch.
    #[serde(default = "default_true")]
    pub check_match_in_if: bool,
    /// Flag long `if/else if` chains.
    #[serde(default = "default_true")]
    pub check_else_chain: bool,
    /// Flag any use of the `else` keyword.
    #[serde(default)]
    pub forbid_else: bool,
    /// Flag any `unsafe` block.
    #[serde(default = "default_true")]
    pub forbid_unsafe: bool,
    /// Flag dynamic dispatch in return types.
    #[serde(default)]
    pub check_dyn_return: bool,
    /// Flag dynamic dispatch in function parameters.
    #[serde(default)]
    pub check_dyn_param: bool,
    /// Flag `Vec<Box<dyn T>>` anywhere.
    #[serde(default)]
    pub check_vec_box_dyn: bool,
    /// Flag dynamic dispatch in struct fields.
    #[serde(default)]
    pub check_dyn_field: bool,
    /// Flag `.clone()` inside loop bodies.
    #[serde(default)]
    pub check_clone_in_loop: bool,
    /// Flag `HashMap`/`HashSet` with default SipHash hasher.
    #[serde(default)]
    pub check_default_hasher: bool,
    /// Flag disconnected type groups in a single file.
    #[serde(default)]
    pub check_mixed_concerns: bool,
    /// Flag `#[cfg(test)] mod` blocks embedded in source files.
    #[serde(default)]
    pub check_inline_tests: bool,
    /// Flag `let _ = expr` that discards a Result.
    #[serde(default)]
    pub check_let_underscore_result: bool,
    /// Flag functions with too many parameters.
    #[serde(default)]
    pub check_high_param_count: bool,
    /// Flag function bodies that exceed the line ceiling.
    #[serde(default)]
    pub check_long_function_body: bool,
    /// Flag item definitions in module-root files.
    #[serde(default)]
    pub check_module_root_definitions: bool,
    /// Flag source files that exceed the line ceiling.
    #[serde(default)]
    pub check_large_source_file: bool,
    /// Flag god-object types by inherent-method count.
    #[serde(default)]
    pub check_high_method_count: bool,
    /// Count pure forwarders toward `high-method-count`.
    #[serde(default)]
    pub count_forwarders: bool,
    /// Enforce configured item-visibility policies.
    #[serde(default = "default_true")]
    pub check_item_visibility_policy: bool,
    /// Item-visibility policy rules.
    #[serde(default)]
    pub item_visibility_policy: Vec<ItemVisibilityRule>,
    /// Flag ungated test-only APIs under `src/`.
    #[serde(default)]
    pub check_ungated_test_api: bool,
    /// Flag sibling `<stem>.rs` and `<stem>/` module roots.
    #[serde(default)]
    pub check_conflicting_module_root: bool,
    /// Name globs that mark test-only APIs (default: `*_for_tests`).
    #[serde(
        default = "default_test_api_patterns",
        deserialize_with = "deserialize_arc_str_slice"
    )]
    pub test_api_patterns: Arc<[Arc<str>]>,
    /// Feature that must gate a test-only API (default: `test-support`).
    #[serde(default = "default_test_support_feature")]
    pub test_support_feature: Box<str>,
    /// Enforce configured flat-module-family layout rules.
    #[serde(default = "default_true")]
    pub check_flat_module_family: bool,
    /// Flat-module-family layout rules.
    #[serde(default)]
    pub flat_module_families: Vec<FlatModuleFamily>,
    /// Enforce configured Cargo feature-boundary invariants.
    #[serde(default = "default_true")]
    pub check_feature_boundary: bool,
    /// Cargo feature-boundary invariants.
    #[serde(default)]
    pub feature_boundaries: Vec<FeatureBoundaryRule>,
    /// Flag types whose inherent impls span more than one file.
    #[serde(default)]
    pub check_scattered_inherent_impl: bool,
    /// Per-path configuration overrides keyed by glob pattern.
    #[serde(default)]
    pub overrides: BTreeMap<Box<str>, PathOverride>,
}

/// Per-path overrides (e.g., for `tests/**`). `None` inherits from base config.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PathOverride {
    /// `Some(false)` disables all checks for matched paths.
    pub enabled: Option<bool>,
    /// Replace nesting depth limit.
    pub max_depth: Option<usize>,
    /// Replace maximum parameter count.
    pub max_params: Option<usize>,
    /// Replace function body line ceiling.
    pub max_function_body_lines: Option<usize>,
    /// Replace the `large-source-file` warning line ceiling. Pair with a
    /// TOML comment recording why this path is allowed to be large.
    pub source_file_warn_lines: Option<usize>,
    /// Replace the `large-source-file` denial line ceiling.
    pub source_file_deny_lines: Option<usize>,
    /// Replace the `high-method-count` method ceiling.
    pub max_methods: Option<usize>,
    /// Replace forbidden attribute patterns.
    pub forbid_attributes: Option<PatternOverride>,
    /// Replace forbidden type patterns.
    pub forbid_types: Option<PatternOverride>,
    /// Replace forbidden call patterns.
    pub forbid_calls: Option<PatternOverride>,
    /// Replace forbidden macro patterns.
    pub forbid_macros: Option<PatternOverride>,
    /// Replace generic naming thresholds.
    pub check_naming: Option<NamingOverride>,
    /// Replace nested-if check state.
    pub check_nested_if: Option<bool>,
    /// Replace if-in-match check state.
    pub check_if_in_match: Option<bool>,
    /// Replace nested-match check state.
    pub check_nested_match: Option<bool>,
    /// Replace match-in-if check state.
    pub check_match_in_if: Option<bool>,
    /// Replace else-chain check state.
    pub check_else_chain: Option<bool>,
    /// Replace `else` keyword ban state.
    pub forbid_else: Option<bool>,
    /// Replace `unsafe` block ban state.
    pub forbid_unsafe: Option<bool>,
    /// Replace dyn-return check state.
    pub check_dyn_return: Option<bool>,
    /// Replace dyn-param check state.
    pub check_dyn_param: Option<bool>,
    /// Replace `Vec<Box<dyn T>>` check state.
    pub check_vec_box_dyn: Option<bool>,
    /// Replace dyn-field check state.
    pub check_dyn_field: Option<bool>,
    /// Replace clone-in-loop check state.
    pub check_clone_in_loop: Option<bool>,
    /// Replace default-hasher check state.
    pub check_default_hasher: Option<bool>,
    /// Replace mixed-concerns check state.
    pub check_mixed_concerns: Option<bool>,
    /// Replace inline-tests check state.
    pub check_inline_tests: Option<bool>,
    /// Replace let-underscore-result check state.
    pub check_let_underscore_result: Option<bool>,
    /// Replace high-param-count check state.
    pub check_high_param_count: Option<bool>,
    /// Replace long-function-body check state.
    pub check_long_function_body: Option<bool>,
    /// Replace module-root-definitions check state.
    pub check_module_root_definitions: Option<bool>,
    /// Replace large-source-file check state.
    pub check_large_source_file: Option<bool>,
    /// Replace high-method-count check state.
    pub check_high_method_count: Option<bool>,
    /// Replace the forwarder-counting policy.
    pub count_forwarders: Option<bool>,
    /// Replace item-visibility-policy check state.
    pub check_item_visibility_policy: Option<bool>,
    /// Replace ungated-test-api check state.
    pub check_ungated_test_api: Option<bool>,
    /// Replace conflicting-module-root check state.
    pub check_conflicting_module_root: Option<bool>,
    /// Replace flat-module-family check state.
    pub check_flat_module_family: Option<bool>,
    /// Replace feature-boundary check state.
    pub check_feature_boundary: Option<bool>,
    /// Replace scattered-inherent-impl check state.
    pub check_scattered_inherent_impl: Option<bool>,
}

pub(super) fn default_max_depth() -> usize {
    3
}

pub(super) fn default_else_chain_threshold() -> usize {
    3
}

pub(super) fn default_max_params() -> usize {
    5
}

pub(super) fn default_max_function_body_lines() -> usize {
    120
}

static MODULE_ROOT_FILES_ARC: LazyLock<Arc<[Arc<str>]>> =
    LazyLock::new(|| [Arc::from("mod.rs"), Arc::from("lib.rs")].into());

pub(super) fn default_module_root_files() -> Arc<[Arc<str>]> {
    Arc::clone(&MODULE_ROOT_FILES_ARC)
}

pub(super) fn default_source_file_warn_lines() -> usize {
    500
}

pub(super) fn default_source_file_deny_lines() -> usize {
    1000
}

pub(super) fn default_max_methods() -> usize {
    40
}

static TEST_API_PATTERNS_ARC: LazyLock<Arc<[Arc<str>]>> =
    LazyLock::new(|| [Arc::from("*_for_tests")].into());

pub(super) fn default_test_api_patterns() -> Arc<[Arc<str>]> {
    Arc::clone(&TEST_API_PATTERNS_ARC)
}

pub(super) fn default_test_support_feature() -> Box<str> {
    "test-support".into()
}

fn default_true() -> bool {
    true
}
