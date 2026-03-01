use std::collections::HashMap;
use std::fs;
use std::path::Path;

use clap::Parser;
use serde::Deserialize;

use crate::reporter::OutputFormat;
use crate::visitor::CheckConfig;

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
}

/// A set of glob-style patterns to match against AST nodes.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct PatternCheck {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub patterns: Vec<String>,
}

/// Deserialized `.pedant.toml` configuration.
#[derive(Debug, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_true")]
    pub check_nested_if: bool,
    #[serde(default = "default_true")]
    pub check_if_in_match: bool,
    #[serde(default = "default_true")]
    pub check_nested_match: bool,
    #[serde(default = "default_true")]
    pub check_match_in_if: bool,
    #[serde(default = "default_true")]
    pub check_else_chain: bool,
    #[serde(default = "default_else_chain_threshold")]
    pub else_chain_threshold: usize,
    #[serde(default)]
    pub forbid_attributes: PatternCheck,
    #[serde(default)]
    pub forbid_types: PatternCheck,
    #[serde(default)]
    pub forbid_calls: PatternCheck,
    #[serde(default)]
    pub forbid_macros: PatternCheck,
    #[serde(default)]
    pub forbid_else: bool,
    #[serde(default = "default_true")]
    pub forbid_unsafe: bool,
    #[serde(default)]
    pub check_dyn_return: bool,
    #[serde(default)]
    pub check_dyn_param: bool,
    #[serde(default)]
    pub check_vec_box_dyn: bool,
    #[serde(default)]
    pub check_dyn_field: bool,
    #[serde(default)]
    pub check_clone_in_loop: bool,
    #[serde(default)]
    pub check_default_hasher: bool,
    #[serde(default)]
    pub check_mixed_concerns: bool,
    #[serde(default)]
    pub overrides: HashMap<String, PathOverride>,
}

/// Per-path override for a pattern check.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct PatternOverride {
    pub enabled: Option<bool>,
    #[serde(default)]
    pub patterns: Vec<String>,
}

/// Per-path configuration overrides (e.g., for `tests/**`).
#[derive(Debug, Deserialize, Default)]
pub struct PathOverride {
    pub enabled: Option<bool>,
    pub max_depth: Option<usize>,
    pub forbid_attributes: Option<PatternOverride>,
    pub forbid_types: Option<PatternOverride>,
    pub forbid_calls: Option<PatternOverride>,
    pub forbid_macros: Option<PatternOverride>,
    pub forbid_else: Option<bool>,
    pub forbid_unsafe: Option<bool>,
    pub check_dyn_return: Option<bool>,
    pub check_dyn_param: Option<bool>,
    pub check_vec_box_dyn: Option<bool>,
    pub check_dyn_field: Option<bool>,
    pub check_clone_in_loop: Option<bool>,
    pub check_default_hasher: Option<bool>,
    pub check_mixed_concerns: Option<bool>,
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

/// Load and parse a `.pedant.toml` configuration file.
pub fn load_config_file(path: &Path) -> Result<ConfigFile, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read config file: {e}"))?;
    toml::from_str(&content)
        .map_err(|e| format!("failed to parse config file: {e}"))
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
    pub fn output_format(&self) -> OutputFormat {
        match self.format.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            _ => OutputFormat::Text,
        }
    }

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
        }
    }
}

/// Find the first matching path override for a file.
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
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
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
