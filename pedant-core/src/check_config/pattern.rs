use std::sync::Arc;

use serde::Deserialize;

use super::string_list::deserialize_arc_str_slice;

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
