//! Module-instance ancestry and the distinct sources one unit reaches.

use std::sync::Arc;

use crate::resolution::rust::identity::{index_of, position};

use super::super::module::{RustModuleId, RustModuleInstance};

/// One unit's module instances and the sources they occupy.
pub(in crate::resolution::rust::snapshot) struct UnitClosure {
    pub(in crate::resolution::rust::snapshot) modules: Box<[RustModuleInstance]>,
    pub(in crate::resolution::rust::snapshot) sources: Box<[Arc<str>]>,
}

/// How one unit's closure walk ended.
///
/// The walk states this rather than leaving a caller to re-derive it from the
/// failures it collected. Whether a crossed ceiling ended the traversal is a
/// decision the walk already made, on the failure it already held, and a second
/// reading of it from the failure window is a second answer that can disagree.
pub(in crate::resolution::rust::snapshot) enum UnitWalk {
    /// Every declaration the walk reached was followed to its end.
    ///
    /// Non-fatal failures may still have been collected beside it: a `mod` item
    /// naming no source ends that branch and nothing else.
    Followed(UnitClosure),
    /// A crossed ceiling ended the traversal part-way.
    ///
    /// The instances reached before it are carried as evidence. Every later
    /// step is measured against a ceiling that is already spent, so no unit
    /// after this one is walked.
    Halted(UnitClosure),
    /// The entry point itself could not be reached, so this unit states no
    /// closure. Another unit's entry may still be readable.
    Unreached,
    /// The entry point could not be reached because a ceiling was crossed
    /// reaching it, which ends the traversal as any other crossed ceiling does.
    Exhausted,
}

impl UnitWalk {
    /// The closure this walk completed, absent when it completed none.
    ///
    /// A halted walk states no completed closure: it stopped at a ceiling, so
    /// what it reached is failure evidence rather than a unit's source
    /// membership.
    pub(in crate::resolution::rust::snapshot) fn completed(self) -> Option<UnitClosure> {
        match self {
            Self::Followed(closure) => Some(closure),
            Self::Halted(_) | Self::Unreached | Self::Exhausted => None,
        }
    }
}

/// Instances built so far, the sources they occupy, and their ceiling.
pub(super) struct Walk {
    instances: Vec<RustModuleInstance>,
    sources: Vec<Arc<str>>,
    ceiling: u32,
}

impl Walk {
    /// A walk holding only the crate-root instance.
    pub(super) fn rooted(path: &Arc<str>, ceiling: u32) -> Self {
        Self {
            instances: vec![RustModuleInstance {
                id: RustModuleId::new(0),
                parent: None,
                name: Arc::from("crate"),
                path: Arc::clone(path),
                inline: false,
                depth: 0,
                scope: 0,
                declaration: None,
            }],
            sources: vec![Arc::clone(path)],
            ceiling,
        }
    }

    pub(super) fn root_id(&self) -> RustModuleId {
        RustModuleId::new(0)
    }

    pub(super) fn next_id(&self) -> RustModuleId {
        RustModuleId::new(position(self.instances.len()))
    }

    /// Whether one more instance would cross this unit's ceiling.
    pub(super) fn at_capacity(&self) -> bool {
        position(self.instances.len()) >= self.ceiling
    }

    pub(super) fn ceiling(&self) -> u32 {
        self.ceiling
    }

    pub(super) fn push(&mut self, instance: RustModuleInstance) -> RustModuleId {
        let id = instance.id;
        self.instances.push(instance);
        id
    }

    pub(super) fn record_source(&mut self, path: &Arc<str>) {
        self.sources.push(Arc::clone(path));
    }

    /// Whether `path` already occupies an instance on `from`'s ancestor chain.
    pub(super) fn ancestor_holds(&self, from: RustModuleId, path: &str) -> bool {
        let mut current = Some(from);
        while let Some(id) = current {
            let instance = match self.instances.get(index_of(id.index())) {
                Some(instance) => instance,
                None => return false,
            };
            if &*instance.path == path {
                return true;
            }
            current = instance.parent;
        }
        false
    }

    pub(super) fn finish(mut self) -> UnitClosure {
        self.sources.sort();
        self.sources.dedup();
        UnitClosure {
            modules: self.instances.into_boxed_slice(),
            sources: self.sources.into_boxed_slice(),
        }
    }
}
