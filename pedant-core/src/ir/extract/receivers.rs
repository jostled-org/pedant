//! The local binding types one function body established.
//!
//! A separate owner from the site inventory, because it answers a different
//! question. A site table records what a source declares and is sealed into the
//! finished IR; this environment is scratch state for one body, discarded when
//! that body closes, and it exists only so a method call on a local can name
//! the type that local holds.

use std::collections::BTreeMap;
use std::sync::Arc;

/// The bindings one function body established, keyed by name.
///
/// One binding's type is read once per method call on it, so the type name is
/// shared rather than copied out on every lookup.
pub(super) type Bindings = BTreeMap<Box<str>, Arc<str>>;

/// The receiver types in scope for the body under traversal.
#[derive(Default)]
pub(super) struct ReceiverScope {
    bindings: Bindings,
}

impl ReceiverScope {
    /// Start a fresh environment for one function body, returning the
    /// enclosing one to restore.
    pub(super) fn enter(&mut self) -> Bindings {
        std::mem::take(&mut self.bindings)
    }

    /// Restore an environment [`Self::enter`] replaced.
    pub(super) fn leave(&mut self, restored: Bindings) {
        self.bindings = restored;
    }

    /// Record that the local binding `name` holds a value of type `type_name`.
    pub(super) fn record(&mut self, name: Box<str>, type_name: Arc<str>) {
        self.bindings.insert(name, type_name);
    }

    /// The type a local binding is known to hold, when an annotation, a struct
    /// literal, or an obvious constructor established one.
    pub(super) fn lookup(&self, receiver: &str) -> Option<Arc<str>> {
        self.bindings.get(receiver).cloned()
    }
}
