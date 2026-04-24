use clap::{Args, Parser, Subcommand, ValueEnum};
use pedant_core::check_config::{CheckConfig, ConfigFile};

/// Selects how command output is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OutputFormat {
    /// One record per line or human-readable text.
    #[default]
    Text,
    /// Machine-readable JSON.
    Json,
}

/// Threshold for failing supply-chain verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum FailOn {
    /// Fail only when the same version's content hash changes.
    #[default]
    HashMismatch,
    /// Fail on hash mismatches and newly added capabilities.
    NewCapability,
    /// Fail on hash mismatches, new capabilities, and missing baselines.
    NewDependency,
    /// Never fail; report findings only.
    None,
}

impl FailOn {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HashMismatch => "hash-mismatch",
            Self::NewCapability => "new-capability",
            Self::NewDependency => "new-dependency",
            Self::None => "none",
        }
    }
}

/// Top-level CLI.
#[derive(Parser, Debug)]
#[command(name = "pedant")]
#[command(about = "An opinionated Rust linter, with special focus on AI-generated code")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run style checks on Rust source files.
    Check(CheckArgs),
    /// Output capability profile as JSON.
    Capabilities(CapabilitiesArgs),
    /// Output capability attestation as JSON.
    Attestation(AttestationArgs),
    /// Evaluate gate rules against a capability profile.
    Gate(GateArgs),
    /// Compare two capability profiles or attestations.
    Diff(DiffArgs),
    /// Show detailed rationale for a check.
    Explain(ExplainArgs),
    /// List all available checks.
    ListChecks,
    /// Manage and verify dependency baselines.
    SupplyChain(SupplyChainArgs),
}

/// Shared file input flags.
#[derive(Args, Debug, Clone)]
pub struct FileInputArgs {
    /// Files to analyze
    #[arg(required_unless_present = "stdin")]
    pub files: Vec<String>,

    /// Read a single source file from stdin
    #[arg(long)]
    pub stdin: bool,
}

/// Shared style/config flags.
#[derive(Args, Debug, Clone)]
pub struct ConfigArgs {
    /// Maximum nesting depth
    #[arg(short = 'd', long, default_value = "3")]
    pub max_depth: usize,

    /// Config file path
    #[arg(short = 'c', long)]
    pub config: Option<String>,

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

impl ConfigArgs {
    /// Merge CLI flags with the file config, with CLI taking precedence.
    pub fn to_check_config(&self, file_config: Option<&ConfigFile>) -> CheckConfig {
        let mut base = file_config.map_or_else(CheckConfig::default, CheckConfig::from_config_file);

        base.max_depth = self.max_depth;
        base.check_nested_if = base.check_nested_if && !self.no_nested_if;
        base.check_if_in_match = base.check_if_in_match && !self.no_if_in_match;
        base.check_nested_match = base.check_nested_match && !self.no_nested_match;
        base.check_match_in_if = base.check_match_in_if && !self.no_match_in_if;
        base.check_else_chain = base.check_else_chain && !self.no_else_chain;
        base
    }
}

#[derive(Args, Debug, Clone)]
pub struct CheckArgs {
    #[command(flatten)]
    pub input: FileInputArgs,

    #[command(flatten)]
    pub config: ConfigArgs,

    /// Output format: text or json
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Only output violations, no summary
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Enable semantic analysis via rust-analyzer for type-aware checks
    #[cfg(feature = "semantic")]
    #[arg(long)]
    pub semantic: bool,
}

#[derive(Args, Debug, Clone)]
pub struct CapabilitiesArgs {
    #[command(flatten)]
    pub input: FileInputArgs,

    /// Enable semantic analysis via rust-analyzer for reachability annotations
    #[cfg(feature = "semantic")]
    #[arg(long)]
    pub semantic: bool,
}

#[derive(Args, Debug, Clone)]
pub struct AttestationArgs {
    #[command(flatten)]
    pub input: FileInputArgs,

    /// Crate name for attestation output
    #[arg(long, value_name = "NAME")]
    pub crate_name: String,

    /// Crate version for attestation output
    #[arg(long, value_name = "VERSION")]
    pub crate_version: String,

    /// Enable semantic analysis via rust-analyzer for reachability annotations
    #[cfg(feature = "semantic")]
    #[arg(long)]
    pub semantic: bool,
}

#[derive(Args, Debug, Clone)]
pub struct GateArgs {
    #[command(flatten)]
    pub input: FileInputArgs,

    /// Config file path
    #[arg(short = 'c', long)]
    pub config: Option<String>,

    /// Output format: text or json
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Merge findings across all languages for gate evaluation
    #[arg(long)]
    pub cross_language: bool,

    /// Enable semantic analysis via rust-analyzer for flow-aware gate rules
    #[cfg(feature = "semantic")]
    #[arg(long)]
    pub semantic: bool,
}

#[derive(Args, Debug, Clone)]
pub struct DiffArgs {
    /// Old capability profile or attestation path
    pub old: String,

    /// New capability profile or attestation path
    pub new: String,
}

#[derive(Args, Debug, Clone)]
pub struct ExplainArgs {
    /// Check code to explain
    pub code: String,
}

#[derive(Args, Debug, Clone)]
pub struct SupplyChainArgs {
    #[command(subcommand)]
    pub command: SupplyChainCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SupplyChainCommand {
    /// Create baseline attestations for the current Cargo dependency tree.
    Init(SupplyChainWriteArgs),
    /// Refresh baseline attestations after dependency changes.
    Update(SupplyChainWriteArgs),
    /// Verify current Cargo dependencies against committed baselines.
    Verify(SupplyChainVerifyArgs),
}

#[derive(Args, Debug, Clone)]
pub struct SupplyChainWriteArgs {
    /// Where baseline attestations are stored
    #[arg(long, default_value = ".pedant/baselines")]
    pub baseline_path: String,
}

#[derive(Args, Debug, Clone)]
pub struct SupplyChainVerifyArgs {
    /// Where baseline attestations are stored
    #[arg(long, default_value = ".pedant/baselines")]
    pub baseline_path: String,

    /// Fail threshold
    #[arg(long, value_enum, default_value_t = FailOn::HashMismatch)]
    pub fail_on: FailOn,

    /// Print hashed input details for one vendored crate
    #[arg(long, value_name = "CRATE")]
    pub debug_package: Option<String>,
}
