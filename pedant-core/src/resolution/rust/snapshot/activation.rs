//! Combining Cargo dependency activations without evaluating them.
//!
//! A path through two conditional edges is active only when both predicates
//! hold; a unit reachable through two paths is active when either holds. This
//! model chooses no feature or platform universe, so it records the combined
//! predicate and never decides whether it is satisfiable.
//!
//! The combination is structural, not textual. Text combined by nesting one
//! rendering inside another restates conjuncts it already contains, grows
//! quadratically along a deep chain, and — because unit selection widens an
//! activation until it stops changing — never settles, so whole subtrees are
//! re-traversed. A sorted, deduplicated operand set settles on the first
//! repetition, and the rendering happens once, at the activation boundary.

use std::sync::Arc;

use crate::resolution::rust::dependency::DependencyActivation;

/// One unevaluated activation predicate, in the shape that makes two paths
/// stating the same condition compare equal whatever order built them.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Predicate {
    /// Active in every configuration.
    Always,
    /// One condition, exactly as the manifest spelled it.
    Stated(Arc<str>),
    /// Active when every operand holds. Operands are sorted and distinct.
    All(Arc<[Predicate]>),
    /// Active when any operand holds. Operands are sorted and distinct.
    Any(Arc<[Predicate]>),
}

/// Which way a combination joins its operands.
#[derive(Clone, Copy)]
enum Operator {
    All,
    Any,
}

/// The predicate of a path that traverses both edges.
pub(super) fn conjoin(left: &Predicate, right: &Predicate) -> Predicate {
    combine(left, right, Operator::All)
}

/// The predicate of a unit reachable through either path.
pub(super) fn disjoin(left: &Predicate, right: &Predicate) -> Predicate {
    match (left, right) {
        (Predicate::Always, _) | (_, Predicate::Always) => Predicate::Always,
        (left, right) => combine(left, right, Operator::Any),
    }
}

impl Predicate {
    /// The predicate one declared activation states.
    pub(super) fn of(activation: &DependencyActivation) -> Self {
        match activation {
            DependencyActivation::Always => Self::Always,
            DependencyActivation::Conditional(condition) => Self::Stated(Arc::clone(condition)),
        }
    }

    /// The activation this predicate records, rendered once.
    pub(super) fn activation(&self) -> DependencyActivation {
        match self {
            Self::Always => DependencyActivation::Always,
            stated => DependencyActivation::Conditional(stated.text()),
        }
    }

    /// This predicate as `cfg` text. An unconditional predicate is the empty
    /// conjunction, which is the `cfg` spelling of a condition that always
    /// holds.
    fn text(&self) -> Arc<str> {
        match self {
            Self::Always => Arc::from("all()"),
            Self::Stated(condition) => Arc::clone(condition),
            Self::All(operands) => rendered(Operator::All, operands),
            Self::Any(operands) => rendered(Operator::Any, operands),
        }
    }
}

fn combine(left: &Predicate, right: &Predicate, operator: Operator) -> Predicate {
    let mut operands = operands_of(left, operator);
    operands.extend(operands_of(right, operator));
    operands.sort();
    operands.dedup();
    reduced(operands, operator)
}

/// No operand states no condition, and one operand needs no operator, so the
/// same set of conditions has exactly one spelling however it was reached.
fn reduced(operands: Vec<Predicate>, operator: Operator) -> Predicate {
    let mut remaining = operands.into_iter();
    match (remaining.next(), remaining.len()) {
        (None, _) => Predicate::Always,
        (Some(single), 0) => single,
        (Some(first), _) => operator.over(std::iter::once(first).chain(remaining).collect()),
    }
}

/// What one predicate contributes to a combination under `operator`.
///
/// A predicate already joined by the same operator contributes its own
/// operands, so `all(all(x, y), x)` settles as `all(x, y)` instead of nesting
/// a conjunct it already holds. An unconditional predicate contributes
/// nothing, which is what makes it the identity of a conjunction.
fn operands_of(predicate: &Predicate, operator: Operator) -> Vec<Predicate> {
    match (predicate, operator) {
        (Predicate::Always, _) => Vec::new(),
        (Predicate::All(operands), Operator::All) => operands.to_vec(),
        (Predicate::Any(operands), Operator::Any) => operands.to_vec(),
        (stated, _) => vec![stated.clone()],
    }
}

fn rendered(operator: Operator, operands: &[Predicate]) -> Arc<str> {
    let joined = operands
        .iter()
        .map(|operand| operand.text().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Arc::from(format!("{}({joined})", operator.token()).as_str())
}

impl Operator {
    fn over(self, operands: Vec<Predicate>) -> Predicate {
        match self {
            Self::All => Predicate::All(Arc::from(operands)),
            Self::Any => Predicate::Any(Arc::from(operands)),
        }
    }

    fn token(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Any => "any",
        }
    }
}
