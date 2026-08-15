//! One reference site and where in the syntax it came from.

use std::rc::Rc;

use pedant_types::ReferenceKind;

use crate::ir::cfg::RustCfgCondition;

use super::range::IrRange;

/// Where a reference site came from, which decides how it is projected and how
/// the resolver looks its target up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReferenceOrigin {
    /// One leaf of a `use` tree.
    Import,
    /// A `mod name;` item naming another source.
    ModuleDeclaration,
    /// A multi-segment path in expression position.
    ExpressionPath,
    /// A single-segment path in callee position.
    ///
    /// A single-segment path that is not a callee states no site at all:
    /// without types this tier cannot tell a unit-struct value from a local
    /// binding, so such a path is read for receiver inference only.
    CallPath,
    /// A type named in a signature, a field, a bound, or a body.
    TypeMention,
    /// A method reached through a receiver.
    MethodCall,
    /// The trait an `impl` block implements.
    Implementation,
    /// A macro invocation, whose target this tier does not expand.
    MacroInvocation,
}

/// One reference site, retaining every source occurrence.
#[derive(Debug)]
pub struct ReferenceSite {
    /// What kind of reference this is.
    pub kind: ReferenceKind,
    /// The source text of the reference, alias and all.
    pub text: Box<str>,
    /// Where the reference sits in the source.
    pub range: IrRange,
    /// The scope this reference occurs in.
    pub scope: usize,
    /// The definition this reference occurs inside, in the same source.
    pub enclosing: Option<usize>,
    pub(crate) origin: ReferenceOrigin,
    pub(crate) segments: Box<[Box<str>]>,
    pub(crate) alias: Option<Box<str>>,
    pub(crate) glob: bool,
    pub(crate) receiver: Option<Rc<str>>,
    pub(crate) condition: RustCfgCondition,
    pub(crate) containing_fn: Option<usize>,
}

impl ReferenceSite {
    /// Which syntax produced this site.
    pub(crate) fn origin(&self) -> ReferenceOrigin {
        self.origin
    }

    /// The path segments, with `crate`, `super`, and `self` retained.
    pub(crate) fn segments(&self) -> &[Box<str>] {
        &self.segments
    }

    /// The local name a `use … as name` binds.
    pub(crate) fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    /// Whether this import brings in every name of the module it names.
    pub(crate) fn is_glob(&self) -> bool {
        self.glob
    }

    /// The inferred receiver type of a method call, when one was established.
    pub(crate) fn receiver(&self) -> Option<&str> {
        self.receiver.as_deref()
    }

    /// The conditional-compilation predicates guarding this reference.
    pub(crate) fn condition(&self) -> &RustCfgCondition {
        &self.condition
    }

    /// The `FileIr::functions` index of the callable body this reference sits
    /// in, or `None` at module scope.
    pub(crate) fn containing_fn(&self) -> Option<usize> {
        self.containing_fn
    }
}
