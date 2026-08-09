use std::collections::BTreeMap;

use serde::Deserialize;

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
