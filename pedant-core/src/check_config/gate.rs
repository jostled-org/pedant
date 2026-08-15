use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::IgnoredAny;
use thiserror::Error;

use super::module_boundary::{
    ModuleBoundaryConfig, ModuleBoundaryConfigError, ModuleBoundaryTable,
};

/// Per-rule override from the `[gate]` TOML section.
#[derive(Debug)]
pub enum GateRuleOverride {
    /// Suppresses the rule entirely.
    Disabled,
    /// Changes the rule's effective severity.
    Severity(crate::gate::GateSeverity),
}

/// A rule setting as written, before it becomes an override.
///
/// Both the capability table and the nested module-boundary table accept the
/// same `false` / `true` / severity-name vocabulary, so they resolve it here.
pub(super) enum RuleSetting<'a> {
    /// `false` disables the rule; `true` selects its default severity.
    Toggle(bool),
    /// A severity name that replaces the rule's default.
    Named(&'a str),
}

/// A rule setting named a severity that does not exist.
#[derive(Debug, Error)]
#[error("invalid gate severity '{0}': expected \"deny\", \"warn\", or \"info\"")]
pub(super) struct InvalidGateSeverity(Box<str>);

/// Resolve one written rule setting, returning `None` when it selects the default.
pub(super) fn rule_override(
    setting: RuleSetting<'_>,
) -> Result<Option<GateRuleOverride>, InvalidGateSeverity> {
    match setting {
        RuleSetting::Toggle(false) => Ok(Some(GateRuleOverride::Disabled)),
        RuleSetting::Toggle(true) => Ok(None),
        RuleSetting::Named(name) => parse_gate_severity(name)
            .map(|severity| Some(GateRuleOverride::Severity(severity)))
            .ok_or_else(|| InvalidGateSeverity(Box::from(name))),
    }
}

/// Deserialized `[gate]` section of `.pedant.toml`.
///
/// Keys are either `enabled` (master switch), the nested `module-boundary`
/// table, or rule names mapped to `false` (disabled) or a severity string
/// (`"deny"`, `"warn"`, `"info"`).
#[derive(Debug)]
pub struct GateConfig {
    /// Master switch; `false` disables all gate rules.
    pub enabled: bool,
    /// Per-rule overrides keyed by rule name.
    pub overrides: BTreeMap<Box<str>, GateRuleOverride>,
    /// Structural module-boundary ceilings, thresholds, and rule settings.
    pub module_boundary: ModuleBoundaryConfig,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            overrides: BTreeMap::new(),
            module_boundary: ModuleBoundaryConfig::default(),
        }
    }
}

/// One raw `[gate]` value, before it is validated against its key.
#[derive(Deserialize)]
#[serde(untagged)]
enum GateTomlValue {
    Bool(bool),
    String(String),
    ModuleBoundary(ModuleBoundaryTable),
    Other(IgnoredAny),
}

/// Why one `[gate]` entry was refused.
#[derive(Debug, Error)]
enum GateConfigError {
    #[error("unknown gate rule '{0}'")]
    UnknownRule(Box<str>),
    #[error("'enabled' must be a boolean")]
    EnabledNotBoolean,
    #[error("'module-boundary' must be a table")]
    ModuleBoundaryNotTable,
    #[error("gate rule '{0}' must be a boolean or a severity string")]
    RuleNotToggleOrSeverity(Box<str>),
    #[error(transparent)]
    ModuleBoundary(#[from] ModuleBoundaryConfigError),
    #[error(transparent)]
    Severity(#[from] InvalidGateSeverity),
}

impl<'de> Deserialize<'de> for GateConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let raw: BTreeMap<Box<str>, GateTomlValue> = BTreeMap::deserialize(deserializer)?;
        let mut config = GateConfig::default();
        for (key, value) in raw {
            apply_entry(&mut config, key, value).map_err(D::Error::custom)?;
        }
        Ok(config)
    }
}

/// Apply one written `[gate]` entry to the configuration under construction.
///
/// The key arrives owned, so a recorded override stores the map's own
/// allocation rather than a copy of it.
fn apply_entry(
    config: &mut GateConfig,
    key: Box<str>,
    value: GateTomlValue,
) -> Result<(), GateConfigError> {
    match (&*key, value) {
        ("module-boundary", GateTomlValue::ModuleBoundary(table)) => {
            config.module_boundary = ModuleBoundaryConfig::from_raw(table)?;
        }
        ("module-boundary", _) => return Err(GateConfigError::ModuleBoundaryNotTable),
        ("enabled", GateTomlValue::Bool(toggle)) => config.enabled = toggle,
        ("enabled", _) => return Err(GateConfigError::EnabledNotBoolean),
        (name, _) if !crate::gate::is_gate_rule(name) => {
            return Err(GateConfigError::UnknownRule(key));
        }
        (_, GateTomlValue::Bool(toggle)) => {
            insert_override(config, key, RuleSetting::Toggle(toggle))?;
        }
        (_, GateTomlValue::String(severity)) => {
            insert_override(config, key, RuleSetting::Named(&severity))?;
        }
        (_, _) => {
            return Err(GateConfigError::RuleNotToggleOrSeverity(key));
        }
    }
    Ok(())
}

/// Record a capability rule setting unless it selects the rule's default.
fn insert_override(
    config: &mut GateConfig,
    rule: Box<str>,
    setting: RuleSetting<'_>,
) -> Result<(), InvalidGateSeverity> {
    if let Some(resolved) = rule_override(setting)? {
        config.overrides.insert(rule, resolved);
    }
    Ok(())
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
