//! What one Go fact extraction is walking for.

/// How much of a source one walk retains.
///
/// The other half of an extraction's budget: `GoFactLimits` bounds what a walk
/// may spend, and this bounds what it spends it on. The enclosing-unit answer
/// reads declarations and nothing else, so a host that also asks for the
/// inventory would otherwise walk the tree twice, build eight fact categories
/// each time, and drop seven of them once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GoFactScope {
    /// Every fact category the inventory states.
    Everything,
    /// Declarations, and the scopes that decide what a declaration is.
    ///
    /// Scopes are retained in both modes because a declaration's identity
    /// depends on where it is written: a `const` at file scope declares a
    /// package member, and the same node inside a body binds a local name.
    DeclarationsOnly,
}
