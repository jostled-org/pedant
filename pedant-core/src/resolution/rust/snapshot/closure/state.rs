//! Module-instance ancestry and the distinct sources one unit reaches.

use std::sync::Arc;

use crate::resolution::rust::identity::{index_of, position};

use super::super::module::{RustModuleId, RustModuleInstance};

/// One unit's module instances and the sources they occupy.
pub(in crate::resolution::rust::snapshot) struct UnitClosure {
    pub(in crate::resolution::rust::snapshot) modules: Box<[RustModuleInstance]>,
    pub(in crate::resolution::rust::snapshot) sources: Box<[Arc<str>]>,
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
