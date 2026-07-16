mod cargo_meta;
mod context;
mod feature_boundary;
mod module_layout;

pub use cargo_meta::{CargoDependency, CargoMetadata, CargoPackage};
pub use context::{ProjectContext, check_project};
