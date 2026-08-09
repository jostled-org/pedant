use std::sync::{Arc, LazyLock};

use serde::Deserialize;

use super::string_list::{deserialize_arc_str_slice, deserialize_option_arc_str_slice};

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

fn default_max_generic_ratio() -> f64 {
    0.3
}

fn default_min_generic_count() -> usize {
    2
}
