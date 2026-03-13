use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use serde::Deserialize;

use crate::reporter::OutputFormat;
use crate::visitor::CheckConfig;

/// Command-line arguments for the pedant binary.
#[derive(Parser, Debug)]
#[command(name = "pedant")]
#[command(about = "An opinionated Rust linter, with special focus on AI-generated code")]
#[command(version)]
pub struct Cli {
    /// Files to check
    #[arg(required_unless_present_any = ["stdin", "list_checks", "explain"])]
    pub files: Vec<String>,

    /// Read from stdin
    #[arg(long)]
    pub stdin: bool,

    /// List all available checks
    #[arg(long)]
    pub list_checks: bool,

    /// Show detailed rationale for a check (e.g., --explain forbidden-call)
    #[arg(long, value_name = "CHECK")]
    pub explain: Option<String>,

    /// Maximum nesting depth
    #[arg(short = 'd', long, default_value = "3")]
    pub max_depth: usize,

    /// Config file path
    #[arg(short = 'c', long)]
    pub config: Option<String>,

    /// Output format: text, json
    #[arg(short = 'f', long, default_value = "text")]
    pub format: String,

    /// Only output violations, no summary
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Disable nested-if check
    #[arg(long)]
    pub no_nested_if: bool,

    /// Disable if-in-match check
    #[arg(long)]
    pub no_if_in_match: bool,

    /// Disable nested-match check
    #[arg(long)]
    pub no_nested_match: bool,

    /// Disable match-in-if check
    #[arg(long)]
    pub no_match_in_if: bool,

    /// Disable else-chain check
    #[arg(long)]
    pub no_else_chain: bool,

    /// Output capability profile as JSON
    #[arg(long)]
    pub capabilities: bool,

    /// Output capability attestation as JSON (implies --capabilities)
    #[arg(long, requires_all = ["crate_name", "crate_version"])]
    pub attestation: bool,

    /// Crate name for attestation output
    #[arg(long, value_name = "NAME")]
    pub crate_name: Option<String>,

    /// Crate version for attestation output
    #[arg(long, value_name = "VERSION")]
    pub crate_version: Option<String>,
}

/// A set of glob-style patterns to match against AST nodes.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct PatternCheck {
    /// Whether this pattern check is active.
    #[serde(default)]
    pub enabled: bool,
    /// Glob-style patterns to match against AST node text.
    #[serde(default, deserialize_with = "deserialize_arc_str_vec")]
    pub patterns: Vec<Arc<str>>,
}

fn deserialize_arc_str_vec<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Arc<str>>, D::Error> {
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    Ok(strings.into_iter().map(Arc::from).collect())
}

/// Default list of generic variable names that LLMs overuse.
const DEFAULT_GENERIC_NAMES: &[&str] = &[
    "tmp", "temp", "data", "val", "value", "result", "res", "ret", "buf", "buffer", "item", "elem",
    "obj", "input", "output", "info", "ctx", "args", "params", "thing", "stuff", "foo", "bar",
    "baz",
];

/// Configuration for the generic-naming check.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NamingCheck {
    /// Whether this check is active.
    #[serde(default)]
    pub enabled: bool,
    /// Words considered generic. Overrides the default list when provided.
    #[serde(
        default = "default_generic_names",
        deserialize_with = "deserialize_arc_str_vec"
    )]
    pub generic_names: Vec<Arc<str>>,
    /// Maximum ratio of generic names to total bindings before flagging.
    #[serde(default = "default_max_generic_ratio")]
    pub max_generic_ratio: f64,
    /// Minimum count of generic names before the ratio check applies.
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

/// Per-path override for the naming check.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct NamingOverride {
    /// Override the enabled state.
    pub enabled: Option<bool>,
    /// Override generic names list.
    #[serde(default, deserialize_with = "deserialize_option_arc_str_vec")]
    pub generic_names: Option<Vec<Arc<str>>>,
    /// Override maximum generic ratio.
    pub max_generic_ratio: Option<f64>,
    /// Override minimum generic count.
    pub min_generic_count: Option<usize>,
}

fn default_generic_names() -> Vec<Arc<str>> {
    DEFAULT_GENERIC_NAMES
        .iter()
        .map(|s| Arc::from(*s))
        .collect()
}

fn deserialize_option_arc_str_vec<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<Arc<str>>>, D::Error> {
    let opt: Option<Vec<String>> = Option::deserialize(deserializer)?;
    Ok(opt.map(|v| v.into_iter().map(Arc::from).collect()))
}

fn default_max_generic_ratio() -> f64 {
    0.3
}

fn default_min_generic_count() -> usize {
    2
}

/// Deserialized `.pedant.toml` configuration.
#[derive(Debug, Deserialize, Default)]
pub struct ConfigFile {
    /// Maximum allowed nesting depth (default: 3).
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
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
    /// Minimum branches to trigger `else-chain` (default: 3).
    #[serde(default = "default_else_chain_threshold")]
    pub else_chain_threshold: usize,
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
    /// Flag any use of the `else` keyword.
    #[serde(default)]
    pub forbid_else: bool,
    /// Flag any `unsafe` block.
    #[serde(default = "default_true")]
    pub forbid_unsafe: bool,
    /// Flag `Box<dyn T>` / `Arc<dyn T>` in return types.
    #[serde(default)]
    pub check_dyn_return: bool,
    /// Flag `&dyn T` / `Box<dyn T>` in function parameters.
    #[serde(default)]
    pub check_dyn_param: bool,
    /// Flag `Vec<Box<dyn T>>` anywhere.
    #[serde(default)]
    pub check_vec_box_dyn: bool,
    /// Flag `Box<dyn T>` / `Arc<dyn T>` in struct fields.
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
    /// Generic naming check configuration.
    #[serde(default)]
    pub check_naming: NamingCheck,
    /// Per-path configuration overrides keyed by glob pattern.
    #[serde(default)]
    pub overrides: BTreeMap<String, PathOverride>,
}

/// Per-path override for a pattern check.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct PatternOverride {
    /// Override the enabled state. `None` inherits from the base config.
    pub enabled: Option<bool>,
    /// Replacement patterns. Empty inherits from the base config.
    #[serde(default, deserialize_with = "deserialize_arc_str_vec")]
    pub patterns: Vec<Arc<str>>,
}

/// Per-path configuration overrides (e.g., for `tests/**`).
///
/// All fields are `Option` — `None` inherits from the base config.
#[derive(Debug, Deserialize, Default)]
pub struct PathOverride {
    /// Disable all checks for matched paths when `false`.
    pub enabled: Option<bool>,
    /// Override maximum nesting depth.
    pub max_depth: Option<usize>,
    /// Override forbidden attribute patterns.
    pub forbid_attributes: Option<PatternOverride>,
    /// Override forbidden type patterns.
    pub forbid_types: Option<PatternOverride>,
    /// Override forbidden call patterns.
    pub forbid_calls: Option<PatternOverride>,
    /// Override forbidden macro patterns.
    pub forbid_macros: Option<PatternOverride>,
    /// Override the `else` keyword ban.
    pub forbid_else: Option<bool>,
    /// Override the `unsafe` block ban.
    pub forbid_unsafe: Option<bool>,
    /// Override dynamic dispatch return check.
    pub check_dyn_return: Option<bool>,
    /// Override dynamic dispatch parameter check.
    pub check_dyn_param: Option<bool>,
    /// Override `Vec<Box<dyn T>>` check.
    pub check_vec_box_dyn: Option<bool>,
    /// Override dynamic dispatch field check.
    pub check_dyn_field: Option<bool>,
    /// Override clone-in-loop check.
    pub check_clone_in_loop: Option<bool>,
    /// Override default hasher check.
    pub check_default_hasher: Option<bool>,
    /// Override mixed concerns check.
    pub check_mixed_concerns: Option<bool>,
    /// Override inline tests check.
    pub check_inline_tests: Option<bool>,
    /// Override generic naming check.
    pub check_naming: Option<NamingOverride>,
}

fn default_max_depth() -> usize {
    3
}

fn default_else_chain_threshold() -> usize {
    3
}

fn default_true() -> bool {
    true
}

/// Error loading or parsing a configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read the config file from disk.
    #[error("failed to read config file: {0}")]
    Read(#[from] std::io::Error),
    /// Failed to parse the TOML config file.
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Load and parse a `.pedant.toml` configuration file.
pub fn load_config_file(path: &Path) -> Result<ConfigFile, ConfigError> {
    let content = fs::read_to_string(path)?;
    Ok(toml::from_str(&content)?)
}

/// Search for a config file: `.pedant.toml` in the project root, then `$XDG_CONFIG_HOME/pedant/config.toml`.
pub fn find_config_file() -> Option<std::path::PathBuf> {
    find_project_config_file().or_else(find_global_config_file)
}

fn find_project_config_file() -> Option<std::path::PathBuf> {
    let config_path = std::env::current_dir().ok()?.join(".pedant.toml");
    config_path.exists().then_some(config_path)
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

impl Cli {
    /// Parses the `--format` flag into an [`OutputFormat`].
    pub fn output_format(&self) -> OutputFormat {
        match self.format.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            _ => OutputFormat::Text,
        }
    }

    /// Builds a [`CheckConfig`] by merging CLI flags with an optional file config.
    pub fn to_check_config(&self, file_config: Option<&ConfigFile>) -> CheckConfig {
        let base = file_config.map_or_else(CheckConfig::default, |fc| CheckConfig {
            max_depth: fc.max_depth,
            check_nested_if: fc.check_nested_if,
            check_if_in_match: fc.check_if_in_match,
            check_nested_match: fc.check_nested_match,
            check_match_in_if: fc.check_match_in_if,
            check_else_chain: fc.check_else_chain,
            else_chain_threshold: fc.else_chain_threshold,
            forbid_attributes: fc.forbid_attributes.clone(),
            forbid_types: fc.forbid_types.clone(),
            forbid_calls: fc.forbid_calls.clone(),
            forbid_macros: fc.forbid_macros.clone(),
            forbid_else: fc.forbid_else,
            forbid_unsafe: fc.forbid_unsafe,
            check_dyn_return: fc.check_dyn_return,
            check_dyn_param: fc.check_dyn_param,
            check_vec_box_dyn: fc.check_vec_box_dyn,
            check_dyn_field: fc.check_dyn_field,
            check_clone_in_loop: fc.check_clone_in_loop,
            check_default_hasher: fc.check_default_hasher,
            check_mixed_concerns: fc.check_mixed_concerns,
            check_inline_tests: fc.check_inline_tests,
            check_naming: fc.check_naming.clone(),
        });

        CheckConfig {
            max_depth: self.max_depth,
            check_nested_if: base.check_nested_if && !self.no_nested_if,
            check_if_in_match: base.check_if_in_match && !self.no_if_in_match,
            check_nested_match: base.check_nested_match && !self.no_nested_match,
            check_match_in_if: base.check_match_in_if && !self.no_match_in_if,
            check_else_chain: base.check_else_chain && !self.no_else_chain,
            else_chain_threshold: base.else_chain_threshold,
            forbid_attributes: base.forbid_attributes,
            forbid_types: base.forbid_types,
            forbid_calls: base.forbid_calls,
            forbid_macros: base.forbid_macros,
            forbid_else: base.forbid_else,
            forbid_unsafe: base.forbid_unsafe,
            check_dyn_return: base.check_dyn_return,
            check_dyn_param: base.check_dyn_param,
            check_vec_box_dyn: base.check_vec_box_dyn,
            check_dyn_field: base.check_dyn_field,
            check_clone_in_loop: base.check_clone_in_loop,
            check_default_hasher: base.check_default_hasher,
            check_mixed_concerns: base.check_mixed_concerns,
            check_inline_tests: base.check_inline_tests,
            check_naming: base.check_naming,
        }
    }
}

/// Returns the first path override whose glob matches `file_path`, or `None`.
pub fn check_path_override<'a>(
    file_path: &str,
    config: &'a ConfigFile,
) -> Option<&'a PathOverride> {
    for (pattern, override_config) in &config.overrides {
        if matches_glob(pattern, file_path) {
            return Some(override_config);
        }
    }
    None
}

fn matches_glob(pattern: &str, path: &str) -> bool {
    let path = path.strip_prefix("./").unwrap_or(path);
    let pattern_parts: Box<[&str]> = pattern.split('/').collect();
    let path_parts: Box<[&str]> = path.split('/').collect();
    matches_glob_parts(&pattern_parts, &path_parts)
}

fn matches_glob_parts(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.first(), path.first()) {
        (None, None) => true,
        (Some(&"**"), _) => matches_double_star(&pattern[1..], path),
        (Some(p), Some(s)) if matches_segment(p, s) => {
            matches_glob_parts(&pattern[1..], &path[1..])
        }
        _ => false,
    }
}

fn matches_double_star(rest_pattern: &[&str], path: &[&str]) -> bool {
    if rest_pattern.is_empty() {
        return true;
    }
    (0..=path.len()).any(|i| matches_glob_parts(rest_pattern, &path[i..]))
}

fn matches_segment(pattern: &str, segment: &str) -> bool {
    match pattern {
        "*" => true,
        p if p.contains('*') => matches_wildcard(p, segment),
        _ => pattern == segment,
    }
}

fn matches_wildcard(pattern: &str, segment: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    match parts.len() {
        2 => segment.starts_with(parts[0]) && segment.ends_with(parts[1]),
        _ => pattern == segment,
    }
}
