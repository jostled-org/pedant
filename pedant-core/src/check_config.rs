use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, LazyLock};

use serde::Deserialize;

use crate::pattern::matches_glob;

/// A set of glob patterns matched against rendered AST node text.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct PatternCheck {
    /// Master switch; `false` skips all patterns.
    #[serde(default)]
    pub enabled: bool,
    /// Glob patterns (e.g., `.unwrap()`, `allow(dead_code)`).
    #[serde(default, deserialize_with = "deserialize_arc_str_slice")]
    pub patterns: Arc<[Arc<str>]>,
}

impl PatternCheck {
    /// Merge a path-specific override, replacing fields that are set.
    pub fn apply_override(&mut self, ovr: &PatternOverride) {
        if let Some(enabled) = ovr.enabled {
            self.enabled = enabled;
        }
        if !ovr.patterns.is_empty() {
            self.patterns = ovr.patterns.clone();
        }
    }
}

fn deserialize_arc_str_slice<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Arc<[Arc<str>]>, D::Error> {
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    Ok(strings.into_iter().map(Arc::from).collect())
}

/// Default list of generic variable names that LLMs overuse.
const DEFAULT_GENERIC_NAMES: &[&str] = &[
    "tmp", "temp", "data", "val", "value", "result", "res", "ret", "buf", "buffer", "item", "elem",
    "obj", "input", "output", "info", "ctx", "args", "params", "thing", "stuff", "foo", "bar",
    "baz",
];

/// Thresholds for the generic-naming check (`tmp`, `val`, `data`, etc.).
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NamingCheck {
    /// Master switch; `false` skips the naming check entirely.
    #[serde(default)]
    pub enabled: bool,
    /// Words considered generic. Replaces the built-in list when provided.
    #[serde(
        default = "default_generic_names",
        deserialize_with = "deserialize_arc_str_slice"
    )]
    pub generic_names: Arc<[Arc<str>]>,
    /// Fraction of bindings that must be generic before flagging (0.0..=1.0).
    #[serde(default = "default_max_generic_ratio")]
    pub max_generic_ratio: f64,
    /// Absolute minimum generic count before the ratio check kicks in.
    #[serde(default = "default_min_generic_count")]
    pub min_generic_count: usize,
}

impl Default for NamingCheck {
    fn default() -> Self {
        Self {
            enabled: false,
            generic_names: default_generic_names(),
            max_generic_ratio: default_max_generic_ratio(),
            min_generic_count: default_min_generic_count(),
        }
    }
}

impl NamingCheck {
    /// Merge a path-specific override, replacing fields that are set.
    pub fn apply_override(&mut self, ovr: &NamingOverride) {
        if let Some(enabled) = ovr.enabled {
            self.enabled = enabled;
        }
        if let Some(ref names) = ovr.generic_names {
            self.generic_names = names.clone();
        }
        if let Some(ratio) = ovr.max_generic_ratio {
            self.max_generic_ratio = ratio;
        }
        if let Some(count) = ovr.min_generic_count {
            self.min_generic_count = count;
        }
    }
}

/// Path-specific overrides for the naming check. `None` inherits from base config.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct NamingOverride {
    /// Replace the enabled state.
    pub enabled: Option<bool>,
    /// Replace the generic names list.
    #[serde(default, deserialize_with = "deserialize_option_arc_str_slice")]
    pub generic_names: Option<Arc<[Arc<str>]>>,
    /// Replace the maximum generic ratio threshold.
    pub max_generic_ratio: Option<f64>,
    /// Replace the minimum generic count threshold.
    pub min_generic_count: Option<usize>,
}

static GENERIC_NAMES_ARC: LazyLock<Arc<[Arc<str>]>> = LazyLock::new(|| {
    DEFAULT_GENERIC_NAMES
        .iter()
        .map(|s| Arc::from(*s))
        .collect()
});

fn default_generic_names() -> Arc<[Arc<str>]> {
    Arc::clone(&GENERIC_NAMES_ARC)
}

type ArcStrSlice = Arc<[Arc<str>]>;

fn deserialize_option_arc_str_slice<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ArcStrSlice>, D::Error> {
    let opt: Option<Vec<String>> = Option::deserialize(deserializer)?;
    Ok(opt.map(|v| v.into_iter().map(Arc::from).collect()))
}

fn default_max_generic_ratio() -> f64 {
    0.3
}

fn default_min_generic_count() -> usize {
    2
}

/// Path-specific overrides for a pattern check. `None` inherits from base config.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct PatternOverride {
    /// Replace the enabled state.
    pub enabled: Option<bool>,
    /// Replace the pattern list. Empty slice inherits from base.
    #[serde(default, deserialize_with = "deserialize_arc_str_slice")]
    pub patterns: Arc<[Arc<str>]>,
}

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

fn default_max_depth() -> usize {
    3
}

fn default_else_chain_threshold() -> usize {
    3
}

fn default_max_params() -> usize {
    5
}

fn default_max_function_body_lines() -> usize {
    120
}

static MODULE_ROOT_FILES_ARC: LazyLock<Arc<[Arc<str>]>> =
    LazyLock::new(|| [Arc::from("mod.rs"), Arc::from("lib.rs")].into());

fn default_module_root_files() -> Arc<[Arc<str>]> {
    Arc::clone(&MODULE_ROOT_FILES_ARC)
}

fn default_source_file_warn_lines() -> usize {
    500
}

fn default_source_file_deny_lines() -> usize {
    1000
}

fn default_max_methods() -> usize {
    40
}

static TEST_API_PATTERNS_ARC: LazyLock<Arc<[Arc<str>]>> =
    LazyLock::new(|| [Arc::from("*_for_tests")].into());

fn default_test_api_patterns() -> Arc<[Arc<str>]> {
    Arc::clone(&TEST_API_PATTERNS_ARC)
}

fn default_test_support_feature() -> Box<str> {
    "test-support".into()
}

fn default_true() -> bool {
    true
}

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

/// Failure modes when loading `.pedant.toml`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Disk I/O failure reading the config file.
    #[error("failed to read config file: {0}")]
    Read(#[from] std::io::Error),
    /// TOML syntax or schema error in the config file.
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Read and deserialize a `.pedant.toml` from the given path.
pub fn load_config_file(path: &Path) -> Result<ConfigFile, ConfigError> {
    let content = fs::read_to_string(path)?;
    Ok(toml::from_str(&content)?)
}

/// Search `.pedant.toml` in the project root, then `$XDG_CONFIG_HOME/pedant/config.toml`.
pub fn find_config_file() -> Result<Option<std::path::PathBuf>, ConfigError> {
    let project_config = find_project_config_file()?;
    Ok(project_config.or_else(find_global_config_file))
}

fn find_project_config_file() -> Result<Option<std::path::PathBuf>, ConfigError> {
    let config_path = std::env::current_dir()?.join(".pedant.toml");
    Ok(config_path.exists().then_some(config_path))
}

fn find_global_config_file() -> Option<std::path::PathBuf> {
    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
        })?;
    let config_path = config_dir.join("pedant").join("config.toml");
    config_path.exists().then_some(config_path)
}

/// Per-rule override from the `[gate]` TOML section.
#[derive(Debug)]
pub enum GateRuleOverride {
    /// Suppresses the rule entirely.
    Disabled,
    /// Changes the rule's effective severity.
    Severity(crate::gate::GateSeverity),
}

/// Deserialized `[gate]` section of `.pedant.toml`.
///
/// Keys are either `enabled` (master switch) or rule names mapped to
/// `false` (disabled) or a severity string (`"deny"`, `"warn"`, `"info"`).
#[derive(Debug)]
pub struct GateConfig {
    /// Master switch; `false` disables all gate rules.
    pub enabled: bool,
    /// Per-rule overrides keyed by rule name.
    pub overrides: BTreeMap<Box<str>, GateRuleOverride>,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            overrides: BTreeMap::new(),
        }
    }
}

impl<'de> Deserialize<'de> for GateConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum GateTomlValue {
            Bool(bool),
            String(String),
        }

        let raw: BTreeMap<Box<str>, GateTomlValue> = BTreeMap::deserialize(deserializer)?;
        let mut enabled = true;
        let mut overrides = BTreeMap::new();

        for (key, value) in raw {
            match (&*key, value) {
                ("enabled", GateTomlValue::Bool(b)) => enabled = b,
                ("enabled", GateTomlValue::String(_)) => {
                    return Err(D::Error::custom("'enabled' must be a boolean"));
                }
                (_, _) if !is_known_gate_rule(&key) => {
                    return Err(D::Error::custom(format!("unknown gate rule '{key}'")));
                }
                (_, GateTomlValue::Bool(false)) => {
                    overrides.insert(key, GateRuleOverride::Disabled);
                }
                (_, GateTomlValue::Bool(true)) => {} // true = use default, no override
                (_, GateTomlValue::String(s)) => {
                    let severity = parse_gate_severity(&s).ok_or_else(|| {
                        D::Error::custom(format!(
                            "invalid gate severity '{s}': expected \"deny\", \"warn\", or \"info\""
                        ))
                    })?;
                    overrides.insert(key, GateRuleOverride::Severity(severity));
                }
            }
        }

        Ok(GateConfig { enabled, overrides })
    }
}

fn is_known_gate_rule(rule_name: &str) -> bool {
    crate::gate::all_gate_rules()
        .iter()
        .any(|rule| rule.name == rule_name)
}

fn parse_gate_severity(s: &str) -> Option<crate::gate::GateSeverity> {
    use crate::gate::GateSeverity;
    match s {
        "deny" => Some(GateSeverity::Deny),
        "warn" => Some(GateSeverity::Warn),
        "info" => Some(GateSeverity::Info),
        _ => None,
    }
}
