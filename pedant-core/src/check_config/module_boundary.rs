//! The `[gate.module-boundary]` section: resource ceilings, local policy
//! thresholds, per-rule settings, and their concrete rejections.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::IgnoredAny;
use thiserror::Error;

use super::gate::{GateRuleOverride, InvalidGateSeverity, RuleSetting, rule_override};

/// One raw `[gate.module-boundary]` value, before it is validated against the
/// field it was written under.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum ModuleBoundaryValue {
    /// An enablement switch or a rule toggle.
    Bool(bool),
    /// A ceiling, count, or percentage.
    Integer(i64),
    /// A rule severity name.
    String(String),
    /// Anything else, so every wrong type reaches a concrete rejection.
    Other(IgnoredAny),
}

/// The raw nested table, buffered by the `[gate]` deserializer.
pub(super) type ModuleBoundaryTable = BTreeMap<Box<str>, ModuleBoundaryValue>;

/// Why one `[gate.module-boundary]` entry was refused.
#[derive(Debug, Error)]
pub(super) enum ModuleBoundaryConfigError {
    /// The key names neither a known field nor a known rule.
    #[error("unknown module-boundary field '{0}'")]
    UnknownField(Box<str>),
    /// A boolean field received another type.
    #[error("module-boundary field '{field}' must be a boolean")]
    NotBoolean {
        /// The field that was written.
        field: Box<str>,
    },
    /// A numeric field received another type.
    #[error("module-boundary field '{field}' must be an integer")]
    NotInteger {
        /// The field that was written.
        field: Box<str>,
    },
    /// A count or ceiling fell outside its `u32` width.
    #[error("module-boundary field '{field}' must fit in u32, got {value}")]
    CountOutOfRange {
        /// The field that was written.
        field: Box<str>,
        /// The rejected value.
        value: i64,
    },
    /// A percentage fell outside `0..=100`.
    #[error("module-boundary field '{field}' must be 0..=100, got {value}")]
    PercentOutOfRange {
        /// The field that was written.
        field: Box<str>,
        /// The rejected value.
        value: i64,
    },
    /// A rule key received neither a toggle nor a severity name.
    #[error("module-boundary rule '{rule}' must be a boolean or a severity string")]
    RuleNotToggleOrSeverity {
        /// The rule that was written.
        rule: Box<str>,
    },
    /// A rule key received an unknown severity name.
    #[error(transparent)]
    Severity(#[from] InvalidGateSeverity),
}

/// Deserialized `[gate.module-boundary]` section of `.pedant.toml`.
///
/// Holds the resource ceilings the graph and analysis owners apply and the
/// local thresholds the four module-boundary rules compare against. Every
/// field is private and read through a by-value accessor, so a threshold
/// cannot be mutated after the configuration is loaded.
#[derive(Debug)]
pub struct ModuleBoundaryConfig {
    enabled: bool,
    rules: BTreeMap<Box<str>, GateRuleOverride>,
    max_nodes: u32,
    max_references: u32,
    max_edges: u32,
    max_selected_edges: u32,
    max_scc_members: u32,
    misplaced_symbol_min_foreign_edges: u32,
    misplaced_symbol_min_affinity_percent: u8,
    low_module_cohesion_min_outgoing_edges: u32,
    low_module_cohesion_min_percent: u8,
}

impl Default for ModuleBoundaryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: BTreeMap::new(),
            max_nodes: 250_000,
            max_references: 1_000_000,
            max_edges: 1_000_000,
            max_selected_edges: 1_000_000,
            max_scc_members: 8,
            misplaced_symbol_min_foreign_edges: 3,
            misplaced_symbol_min_affinity_percent: 60,
            low_module_cohesion_min_outgoing_edges: 4,
            low_module_cohesion_min_percent: 50,
        }
    }
}

impl ModuleBoundaryConfig {
    /// Whether the four module-boundary rules are evaluated at all.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Node ceiling applied by graph construction and analysis.
    pub fn max_nodes(&self) -> u32 {
        self.max_nodes
    }

    /// Reference ceiling applied by graph construction.
    pub fn max_references(&self) -> u32 {
        self.max_references
    }

    /// Raw-edge ceiling applied by graph construction.
    pub fn max_edges(&self) -> u32 {
        self.max_edges
    }

    /// Selected-edge ceiling applied by graph analysis.
    pub fn max_selected_edges(&self) -> u32 {
        self.max_selected_edges
    }

    /// Largest cyclic component that does not trigger `large-scc`.
    pub fn max_scc_members(&self) -> u32 {
        self.max_scc_members
    }

    /// Foreign edges a symbol needs before `misplaced-symbol` can trigger.
    pub fn misplaced_symbol_min_foreign_edges(&self) -> u32 {
        self.misplaced_symbol_min_foreign_edges
    }

    /// Foreign-edge share, in percent, at which `misplaced-symbol` triggers.
    pub fn misplaced_symbol_min_affinity_percent(&self) -> u8 {
        self.misplaced_symbol_min_affinity_percent
    }

    /// Selected outgoing edges a module needs before cohesion is judged.
    pub fn low_module_cohesion_min_outgoing_edges(&self) -> u32 {
        self.low_module_cohesion_min_outgoing_edges
    }

    /// Internal-edge share, in percent, below which cohesion is too low.
    pub fn low_module_cohesion_min_percent(&self) -> u8 {
        self.low_module_cohesion_min_percent
    }

    /// Per-rule settings, read only by the module-boundary evaluator.
    pub(crate) fn rule_overrides(&self) -> &BTreeMap<Box<str>, GateRuleOverride> {
        &self.rules
    }

    /// Validate one raw nested table into a configuration.
    pub(super) fn from_raw(raw: ModuleBoundaryTable) -> Result<Self, ModuleBoundaryConfigError> {
        let mut config = Self::default();
        for (key, value) in raw {
            config.apply(key, value)?;
        }
        Ok(config)
    }

    /// The key arrives owned, so a rule setting stores the map's own allocation.
    fn apply(
        &mut self,
        key: Box<str>,
        value: ModuleBoundaryValue,
    ) -> Result<(), ModuleBoundaryConfigError> {
        match &*key {
            "enabled" => self.enabled = expect_bool(&key, value)?,
            "max-nodes" => self.max_nodes = expect_count(&key, value)?,
            "max-references" => self.max_references = expect_count(&key, value)?,
            "max-edges" => self.max_edges = expect_count(&key, value)?,
            "max-selected-edges" => self.max_selected_edges = expect_count(&key, value)?,
            "max-scc-members" => self.max_scc_members = expect_count(&key, value)?,
            "misplaced-symbol-min-foreign-edges" => {
                self.misplaced_symbol_min_foreign_edges = expect_count(&key, value)?;
            }
            "misplaced-symbol-min-affinity-percent" => {
                self.misplaced_symbol_min_affinity_percent = expect_percent(&key, value)?;
            }
            "low-module-cohesion-min-outgoing-edges" => {
                self.low_module_cohesion_min_outgoing_edges = expect_count(&key, value)?;
            }
            "low-module-cohesion-min-percent" => {
                self.low_module_cohesion_min_percent = expect_percent(&key, value)?;
            }
            _ => return self.apply_rule(key, value),
        }
        Ok(())
    }

    fn apply_rule(
        &mut self,
        rule: Box<str>,
        value: ModuleBoundaryValue,
    ) -> Result<(), ModuleBoundaryConfigError> {
        if !crate::gate::is_module_boundary_rule(&rule) {
            return Err(ModuleBoundaryConfigError::UnknownField(rule));
        }
        if let Some(setting) = rule_setting(&rule, value)? {
            self.rules.insert(rule, setting);
        }
        Ok(())
    }
}

/// Interpret a rule value through the shared `false`/`true`/severity semantics.
fn rule_setting(
    rule: &str,
    value: ModuleBoundaryValue,
) -> Result<Option<GateRuleOverride>, ModuleBoundaryConfigError> {
    match value {
        ModuleBoundaryValue::Bool(toggle) => Ok(rule_override(RuleSetting::Toggle(toggle))?),
        ModuleBoundaryValue::String(name) => Ok(rule_override(RuleSetting::Named(&name))?),
        _ => Err(ModuleBoundaryConfigError::RuleNotToggleOrSeverity {
            rule: Box::from(rule),
        }),
    }
}

fn expect_bool(field: &str, value: ModuleBoundaryValue) -> Result<bool, ModuleBoundaryConfigError> {
    match value {
        ModuleBoundaryValue::Bool(toggle) => Ok(toggle),
        _ => Err(ModuleBoundaryConfigError::NotBoolean {
            field: Box::from(field),
        }),
    }
}

fn expect_integer(
    field: &str,
    value: ModuleBoundaryValue,
) -> Result<i64, ModuleBoundaryConfigError> {
    match value {
        ModuleBoundaryValue::Integer(number) => Ok(number),
        _ => Err(ModuleBoundaryConfigError::NotInteger {
            field: Box::from(field),
        }),
    }
}

fn expect_count(field: &str, value: ModuleBoundaryValue) -> Result<u32, ModuleBoundaryConfigError> {
    let raw = expect_integer(field, value)?;
    u32::try_from(raw).map_err(|_| ModuleBoundaryConfigError::CountOutOfRange {
        field: Box::from(field),
        value: raw,
    })
}

fn expect_percent(
    field: &str,
    value: ModuleBoundaryValue,
) -> Result<u8, ModuleBoundaryConfigError> {
    let raw = expect_integer(field, value)?;
    match u8::try_from(raw) {
        Ok(percent) if percent <= 100 => Ok(percent),
        _ => Err(ModuleBoundaryConfigError::PercentOutOfRange {
            field: Box::from(field),
            value: raw,
        }),
    }
}

impl<'de> Deserialize<'de> for ModuleBoundaryConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let raw = ModuleBoundaryTable::deserialize(deserializer)?;
        Self::from_raw(raw).map_err(D::Error::custom)
    }
}
