//! The build predicates one Go file states above its package clause.

use crate::go::context::text;
use crate::go::span::GoFactSpan;
use crate::tree_sitter::Node;

/// Which spelling a build predicate is written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoBuildConditionKind {
    /// The `//go:build` form, whose constraint is one boolean expression.
    GoBuild,
    /// The legacy `// +build` form, whose constraint is a space- and
    /// comma-separated term list.
    LegacyBuildTag,
}

/// One retained build predicate.
///
/// The constraint is kept verbatim and is never evaluated here: which platform
/// a term admits depends on host and caller configuration this crate does not
/// own, so the predicate travels to the consumer that models it as possible
/// evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoBuildConditionFact<'source> {
    kind: GoBuildConditionKind,
    constraint: &'source str,
    span: GoFactSpan,
}

impl<'source> GoBuildConditionFact<'source> {
    /// Which spelling states the predicate.
    pub fn kind(&self) -> GoBuildConditionKind {
        self.kind
    }

    /// The constraint text, without its directive prefix.
    pub fn constraint(&self) -> &'source str {
        self.constraint
    }

    /// The extent of the whole comment.
    pub fn span(&self) -> GoFactSpan {
        self.span
    }
}

/// The `//go:build` prefix and the legacy one, longest first.
///
/// Order matters only in that each prefix is tried whole: `// +build` cannot
/// match a `//go:build` line, so a file stating both keeps both.
const DIRECTIVES: [(&str, GoBuildConditionKind); 2] = [
    ("//go:build", GoBuildConditionKind::GoBuild),
    ("// +build", GoBuildConditionKind::LegacyBuildTag),
];

/// The build predicate `node` states, if it states one.
///
/// A predicate is a comment above the package clause, which is where the Go
/// command reads one. `package_seen` is the walk's own answer, so a comment
/// repeating the same text further down the file states no predicate.
pub(super) fn condition_at<'source>(
    node: Node<'_>,
    source: &'source str,
    package_seen: bool,
) -> Option<GoBuildConditionFact<'source>> {
    if node.kind() != "comment" || package_seen {
        return None;
    }
    let comment = text(node, source);
    let (constraint, kind) = DIRECTIVES
        .iter()
        .find_map(|&(prefix, kind)| Some((comment.strip_prefix(prefix)?, kind)))?;
    Some(GoBuildConditionFact {
        kind,
        constraint: constraint.trim(),
        span: GoFactSpan::of_node(node),
    })
}
