//! One lexical module scope inside a single source.

/// A source's own scope, or one an inline `mod` item opens.
///
/// Index zero of a file's scope table is the source itself; every inline `mod`
/// item adds one more. A resolution unit instantiates each scope separately,
/// so the same source may hold two live copies of one scope.
#[derive(Debug)]
pub struct ModuleScope {
    /// The declared module name; empty for the source's own scope.
    pub name: Box<str>,
    /// The scope this one is nested in; absent for the source's own scope.
    pub parent: Option<usize>,
}
