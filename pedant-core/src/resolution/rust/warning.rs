//! Non-fatal project-layout diagnostics discovered while sources are
//! snapshotted.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use super::snapshot::RustResolutionUnit;

/// A project layout that preserves Tier 1 resolution but prevents sound
/// semantic promotion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustResolutionWarning {
    /// One physical Rust source is instantiated in more than one resolution
    /// unit, while rust-analyzer exposes only one semantic interpretation for
    /// that file.
    SharedSourceUnits {
        /// The normalized repository-relative source path.
        path: Arc<str>,
        /// Stable keys of every resolution unit that instantiates the source.
        units: Box<[Arc<str>]>,
    },
}

impl RustResolutionWarning {
    /// The normalized repository-relative source this warning concerns.
    pub fn path(&self) -> &str {
        match self {
            Self::SharedSourceUnits { path, .. } => path,
        }
    }

    /// Stable keys of every resolution unit that instantiates the source.
    pub fn unit_keys(&self) -> &[Arc<str>] {
        match self {
            Self::SharedSourceUnits { units, .. } => units,
        }
    }
}

impl fmt::Display for RustResolutionWarning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedSourceUnits { path, units } => {
                write!(
                    formatter,
                    "{path} is instantiated by multiple resolution units ("
                )?;
                write_unit_keys(formatter, units)?;
                formatter.write_str(
                    "), but rust-analyzer cannot distinguish their semantic contexts for one \
                     physical source; give each unit its own physical source, or, when the units \
                     share a package library, declare the module only there and reference it \
                     through the library crate",
                )
            }
        }
    }
}

/// Stable report key of one resolution unit.
pub(in crate::resolution::rust) fn unit_key(unit: &RustResolutionUnit) -> Arc<str> {
    Arc::from(format!(
        "{}#{}#{}",
        unit.manifest_path(),
        unit.kind().token(),
        unit.name()
    ))
}

/// Find every physical source instantiated in more than one unit.
pub(super) fn shared_sources(units: &[RustResolutionUnit]) -> Box<[RustResolutionWarning]> {
    let mut owners: BTreeMap<Arc<str>, Vec<Arc<str>>> = BTreeMap::new();
    for unit in units {
        let key = unit_key(unit);
        for path in unit.sources() {
            owners
                .entry(Arc::clone(path))
                .or_default()
                .push(Arc::clone(&key));
        }
    }
    owners
        .into_iter()
        .filter_map(|(path, mut unit_keys)| {
            unit_keys.sort();
            unit_keys.dedup();
            match unit_keys.len() > 1 {
                true => Some(RustResolutionWarning::SharedSourceUnits {
                    path,
                    units: unit_keys.into_boxed_slice(),
                }),
                false => None,
            }
        })
        .collect()
}

fn write_unit_keys(formatter: &mut fmt::Formatter<'_>, units: &[Arc<str>]) -> fmt::Result {
    for (index, unit) in units.iter().enumerate() {
        match index {
            0 => formatter.write_str(unit)?,
            _ => write!(formatter, ", {unit}")?,
        }
    }
    Ok(())
}
