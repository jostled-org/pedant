//! One written type a snapshotted Go source states, retained by the snapshot
//! rather than borrowed from the parse it came from.
//!
//! `pedant-syntax` keeps the qualifier, the name, and the pointer form as one
//! field group, because the three answers are only ever read together: what a
//! receiver's method set contains depends on all three. The mirror keeps them
//! together for the same reason, and states the retention once — five records
//! of this crate carry a written type, and five flattened copies of the same
//! three fields is five places a later fix reaches one of.

/// One type a snapshotted Go source writes, in its source spelling.
///
/// Never a resolved type: what a name denotes is the resolver's answer, not the
/// grammar's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GoWrittenTypeRecord {
    qualifier: Option<Box<str>>,
    name: Option<Box<str>>,
    pointer: bool,
}

impl GoWrittenTypeRecord {
    /// Retain one extracted written type.
    pub(super) fn of(qualifier: Option<&str>, name: Option<&str>, pointer: bool) -> Self {
        Self {
            qualifier: qualifier.map(Box::from),
            name: name.map(Box::from),
            pointer,
        }
    }

    /// The package qualifier written before the name, for a type another
    /// package declares.
    pub fn qualifier(&self) -> Option<&str> {
        self.qualifier.as_deref()
    }

    /// The written type's own name, absent whenever the shape names no single
    /// type.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Whether the source wrote a pointer form.
    pub fn pointer(&self) -> bool {
        self.pointer
    }
}
