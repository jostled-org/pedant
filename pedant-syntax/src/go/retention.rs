//! What one Go fact extraction is walking for.

/// How much of a source one walk retains.
///
/// The other half of an extraction's budget: `GoFactLimits` bounds what a walk
/// may spend, and this bounds what it spends it on. The enclosing-unit answer
/// reads declarations and nothing else, so a host that also asks for the
/// inventory would otherwise walk the tree twice, build eight fact categories
/// each time, and drop seven of them once.
///
/// One variant per reader, because a reader that took a wider scope than it
/// reads paid the fact ceiling for facts it then dropped — and the ceiling is
/// the same one its own answer runs beneath.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GoFactScope {
    /// Every fact category the inventory states.
    Everything,
    /// Declarations, the scopes that place them, and the package clause the
    /// file opens with.
    ///
    /// What a structure inventory projects, and nothing else: that projection
    /// reads no import, no reference, no binding, and no signature term. The
    /// package clause is the one part of the prelude it does read, because a Go
    /// source declares its package as a structure of its own.
    DeclaredStructures,
    /// Declarations, and the scopes that decide what a declaration is.
    ///
    /// Scopes are retained in every mode because a declaration's identity
    /// depends on where it is written: a `const` at file scope declares a
    /// package member, and the same node inside a body binds a local name.
    DeclarationsOnly,
}
