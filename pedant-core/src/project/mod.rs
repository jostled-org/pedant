mod cargo_meta;
mod context;
mod feature_boundary;
mod module_layout;
mod shape;
mod type_footprint;

pub use cargo_meta::{CargoDependency, CargoMetadata, CargoPackage};
pub use context::{ProjectContext, check_project};
pub use shape::{FileShape, InherentImplSite, TypeDefSite, project_shape};
