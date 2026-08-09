//! Persistent dependency ancestry for queued resolution units.

use std::sync::Arc;

#[cfg(feature = "resolution-test-support")]
use crate::observe::{self, Observation};
use crate::resolution::rust::identity::TargetId;

/// One immutable ancestry ending at the queued unit itself.
pub(super) struct Ancestry {
    latest: Arc<Link>,
}

/// One unit in an ancestry, retaining the prior prefix by shared ownership.
struct Link {
    previous: Option<Arc<Link>>,
    target: TargetId,
    package_name: Arc<str>,
}

impl Ancestry {
    /// Start the root unit's ancestry without counting an edge extension.
    pub(super) fn root(target: TargetId, package_name: &Arc<str>) -> Self {
        Self {
            latest: Arc::new(Link {
                previous: None,
                target,
                package_name: Arc::clone(package_name),
            }),
        }
    }

    /// Retain this entire prefix and append one child in constant time.
    pub(super) fn extend(&self, target: TargetId, package_name: &Arc<str>) -> Self {
        #[cfg(feature = "resolution-test-support")]
        observe::record(Observation::DependencyChainExtension {
            history_entries_copied: 0,
        });
        Self {
            latest: Arc::new(Link {
                previous: Some(Arc::clone(&self.latest)),
                target,
                package_name: Arc::clone(package_name),
            }),
        }
    }

    /// Whether the latest unit already occurs in its retained prefix.
    pub(super) fn repeats_latest(&self) -> bool {
        let target = self.latest.target;
        links(self.latest.previous.as_deref()).any(|entry| entry.target == target)
    }

    /// Package names from the root through the latest unit.
    pub(super) fn package_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = links(Some(&self.latest))
            .map(|entry| entry.package_name.as_ref())
            .collect();
        names.reverse();
        names
    }
}

/// Walk a retained chain from its latest entry toward the root.
fn links(start: Option<&Link>) -> impl Iterator<Item = &Link> {
    std::iter::successors(start, |entry| entry.previous.as_deref())
}
