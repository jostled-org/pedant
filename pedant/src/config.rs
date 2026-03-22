use clap::Parser;

use crate::reporter::OutputFormat;
use pedant_core::check_config::{CheckConfig, ConfigFile};

/// Command-line arguments for the pedant binary.
#[derive(Parser, Debug)]
#[command(name = "pedant")]
#[command(about = "An opinionated Rust linter, with special focus on AI-generated code")]
#[command(version)]
pub struct Cli {
    /// Files to check
    #[arg(required_unless_present_any = ["stdin", "list_checks", "explain", "diff"])]
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
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

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

    /// Compare two capability profiles and output the diff
    #[arg(long, num_args = 2, value_names = ["OLD", "NEW"], conflicts_with_all = ["stdin", "capabilities", "attestation"])]
    pub diff: Vec<String>,

    /// Evaluate gate rules against capability profile
    #[arg(long)]
    pub gate: bool,

    /// Output capability attestation as JSON (implies --capabilities)
    #[arg(long, requires_all = ["crate_name", "crate_version"])]
    pub attestation: bool,

    /// Crate name for attestation output
    #[arg(long, value_name = "NAME")]
    pub crate_name: Option<String>,

    /// Crate version for attestation output
    #[arg(long, value_name = "VERSION")]
    pub crate_version: Option<String>,

    /// Enable semantic analysis via rust-analyzer for type-aware checks
    #[cfg(feature = "semantic")]
    #[arg(long)]
    pub semantic: bool,
}

impl Cli {
    /// Builds a [`CheckConfig`] by merging CLI flags with an optional file config.
    pub fn to_check_config(&self, file_config: Option<&ConfigFile>) -> CheckConfig {
        let mut base = file_config.map_or_else(CheckConfig::default, CheckConfig::from_config_file);

        // CLI overrides: max_depth always wins, no_* flags disable checks.
        base.max_depth = self.max_depth;
        base.check_nested_if = base.check_nested_if && !self.no_nested_if;
        base.check_if_in_match = base.check_if_in_match && !self.no_if_in_match;
        base.check_nested_match = base.check_nested_match && !self.no_nested_match;
        base.check_match_in_if = base.check_match_in_if && !self.no_match_in_if;
        base.check_else_chain = base.check_else_chain && !self.no_else_chain;
        base
    }
}
