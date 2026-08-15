mod discovery;
mod file;
mod gate;
mod module_boundary;
mod naming;
mod pattern;
mod runtime;
mod string_list;

pub use discovery::{ConfigError, find_config_file, find_global_config_file, load_config_file};
pub use file::{
    ConfigFile, FeatureBoundaryRule, FlatModuleFamily, ItemVisibilityRule, PathOverride,
};
pub use gate::{GateConfig, GateRuleOverride};
pub use module_boundary::ModuleBoundaryConfig;
pub use naming::{NamingCheck, NamingOverride};
pub use pattern::{PatternCheck, PatternOverride};
pub use runtime::{CheckConfig, check_path_override};
