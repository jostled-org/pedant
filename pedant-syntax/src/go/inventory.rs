//! The bounded fact inventory one Go walk fills.
//!
//! One ceiling is spent here, and it is checked before the state it would pay
//! for is retained: [`admit`] proves capacity before it pushes a record, and it
//! is the sole insertion site, so a refusal cannot be routed around by adding a
//! seventh kind of fact. A refusal returns no inventory at all rather than a
//! truncated one.
//!
//! The depth this walk reports is retained state too, so it is written through
//! [`Inventory::entered`] rather than assigned into a field the walk can reach:
//! the maximum and the narrowing are claims about what this inventory holds, and
//! a caller doing them itself is a second rule for the same number.
//!
//! Split from the walk that fills it because the two answer different
//! questions: this one states what a completed extraction holds and what
//! holding it cost, and the walk states how a tree is traversed to produce it.

use crate::go::binding::GoBindingFact;
use crate::go::condition::GoBuildConditionFact;
use crate::go::declaration::GoDeclarationFact;
use crate::go::error::GoFactError;
use crate::go::import::GoImportFact;
use crate::go::reference::GoReferenceFact;
use crate::go::retention::GoFactScope;
use crate::go::scope::GoScopeFact;
use crate::go::signature::GoSignatureTermFact;
use crate::go::span::GoFactSpan;

/// Every fact one walk retained, before it is sealed into an inventory.
pub(super) struct Inventory<'source> {
    /// Every package clause the source states. A well-formed file states one;
    /// a recovery tree can state more, and the first is the file's own.
    ///
    /// A list rather than an option so the capacity check has one site: a
    /// scalar exempt from the ceiling would be a second retention rule.
    pub(super) packages: Vec<(&'source str, GoFactSpan)>,
    pub(super) conditions: Vec<GoBuildConditionFact<'source>>,
    pub(super) imports: Vec<GoImportFact<'source>>,
    pub(super) declarations: Vec<GoDeclarationFact<'source>>,
    pub(super) signatures: Vec<GoSignatureTermFact<'source>>,
    pub(super) references: Vec<GoReferenceFact<'source>>,
    pub(super) scopes: Vec<GoScopeFact>,
    pub(super) bindings: Vec<GoBindingFact<'source>>,
    /// How many facts this walk retained, as the ceiling counts them.
    pub(super) counted: u32,
    /// The deepest grammar level this walk entered, the root counting as zero.
    ///
    /// Retained rather than discarded because a source read once and shared by
    /// several bounded consumers still owes each of them its own depth ceiling
    /// an answer, and re-descending the tree per consumer would recompute a
    /// number this descent already knew.
    ///
    /// Private, so [`Inventory::entered`] is the sole site it is written, the
    /// way [`admit`] is the sole site a fact is.
    depth: u32,
    limit: u32,
    retained: GoFactScope,
}

impl<'source> Inventory<'source> {
    pub(super) fn new(limit: u32, retained: GoFactScope) -> Self {
        Self {
            packages: Vec::new(),
            conditions: Vec::new(),
            imports: Vec::new(),
            declarations: Vec::new(),
            signatures: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            counted: 0,
            depth: 0,
            limit,
            retained,
        }
    }

    /// What this walk was opened to retain.
    pub(super) fn retained(&self) -> GoFactScope {
        self.retained
    }

    /// Record that the walk entered `depth`, the root counting as zero.
    ///
    /// The sole site the retained depth is written. The walk states the level
    /// it moved to and nothing else: keeping the deepest one, and narrowing a
    /// level counted in `usize` to the width this inventory publishes, are this
    /// type's own answers about what it holds.
    ///
    /// The narrowing is unreachable on every path a walk takes — its own
    /// descent site refuses a level no `u32` can name before the cursor moves —
    /// and saturating names the deepest level this model can state rather than a
    /// shallow one a later ceiling would admit.
    pub(super) fn entered(&mut self, depth: usize) {
        self.depth = self.depth.max(u32::try_from(depth).unwrap_or(u32::MAX));
    }

    /// The deepest grammar level this walk entered, the root counting as zero.
    pub(super) fn depth(&self) -> u32 {
        self.depth
    }

    pub(super) fn name_package(
        &mut self,
        named: (&'source str, GoFactSpan),
    ) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.packages, named)
    }

    pub(super) fn condition(
        &mut self,
        fact: GoBuildConditionFact<'source>,
    ) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.conditions, fact)
    }

    pub(super) fn import(&mut self, fact: GoImportFact<'source>) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.imports, fact)
    }

    pub(super) fn declare(&mut self, fact: GoDeclarationFact<'source>) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.declarations, fact)
    }

    pub(super) fn sign(&mut self, fact: GoSignatureTermFact<'source>) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.signatures, fact)
    }

    pub(super) fn refer(&mut self, fact: GoReferenceFact<'source>) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.references, fact)
    }

    pub(super) fn open(&mut self, fact: GoScopeFact) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.scopes, fact)
    }

    pub(super) fn bind(&mut self, fact: GoBindingFact<'source>) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.bindings, fact)
    }
}

/// Retain one fact, refusing before the inventory would exceed its ceiling.
///
/// The sole insertion site. Every category routes through it, so the capacity
/// check cannot be skipped by adding a seventh kind of fact.
///
/// The configured ceiling and the representable one are proved together, before
/// anything is pushed. A saturating conversion would mint `u32::MAX` as a real
/// fact identity, and every later record would name it too.
fn admit<T>(counted: &mut u32, limit: u32, into: &mut Vec<T>, fact: T) -> Result<u32, GoFactError> {
    check_capacity(*counted, limit)?;
    let index =
        u32::try_from(into.len()).map_err(|_| GoFactError::FactCapacityExceeded { limit })?;
    *counted += 1;
    into.push(fact);
    Ok(index)
}

/// Whether one more fact fits.
fn check_capacity(counted: u32, limit: u32) -> Result<(), GoFactError> {
    match counted < limit {
        true => Ok(()),
        false => Err(GoFactError::FactCapacityExceeded { limit }),
    }
}
