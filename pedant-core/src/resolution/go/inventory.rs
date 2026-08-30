//! Everything one Go source states, extracted exactly once.
//!
//! This is the Go language owner's answer to "what does this file declare?",
//! and it is the only route to that answer a provider has. A provider reads and
//! decodes; it does not parse, and it recognizes no declaration. Keeping the
//! parse here is what lets several project slices share one source without any
//! of them owning a second Go recognizer that could drift from this one.
//!
//! The retained fact count and nesting depth travel with the inventory because
//! a snapshot that reuses a shared record still owes its own fact and depth
//! ceilings an answer, and rewalking the tree per slice would recompute numbers
//! this walk already knew.

use pedant_syntax::go::GoFactLimits;
use pedant_syntax::tree_sitter::parse_bound;
use pedant_syntax::{StructureInventoryLimits, StructureRecord, StructureSpan, SyntaxLanguage};

use crate::observe::{self, Observation};

use super::condition::{self, GoBuildCondition};
use super::facts::GoSourceFacts;
use super::fault::GoSourceFault;
use super::paths;
use super::snapshot_error::GoSourceDefect;

/// One parsed Go source: its retained facts, the predicates it carries, and
/// what its bounded walk spent.
///
/// Not `Clone`. An inventory is shared behind the `Arc` a record holds, and a
/// deep copy of one is a second copy of every boxed fact list the walk
/// retained — exactly the cost that `Arc` exists to prevent. Equality goes with
/// it: nothing compares two inventories, and a derived one would be a whole-tree
/// comparison offered to a caller that has a digest for the question.
#[derive(Debug)]
pub struct GoFileInventory {
    facts: GoSourceFacts,
    conditions: Box<[GoBuildCondition]>,
    structures: Box<[StructureRecord]>,
    fact_count: u32,
    syntax_depth: u32,
}

impl GoFileInventory {
    /// Parse one complete Go source and retain the inventory it states.
    ///
    /// The tree must be complete: an inventory taken from a recovered tree
    /// would state a report whose missing declarations look exactly like
    /// declarations the repository never had.
    ///
    /// A source with no package clause belongs to no package, so it cannot join
    /// one, and it is refused here rather than admitted as a record no unit can
    /// use.
    pub fn of_source(path: &str, text: &str, limits: GoFactLimits) -> Result<Self, GoSourceFault> {
        let Some(parsed) = parse_bound(text, SyntaxLanguage::Go) else {
            return Err(GoSourceFault::Incomplete(GoSourceDefect::Unparsed));
        };
        observe::record(Observation::SourceParse(path));
        if parsed.has_errors() {
            return Err(GoSourceFault::Incomplete(GoSourceDefect::Recovered));
        }
        let facts = parsed
            .go_file_facts(limits)
            .map_err(GoSourceFault::FactExtraction)?;
        observe::record(Observation::SiteVisit(path));
        if facts.package_name().is_none() {
            return Err(GoSourceFault::MissingPackageClause);
        }
        let structures = facts
            .structure_inventory(structure_limits(limits)?)
            .map_err(|error| GoSourceFault::StructureProjection {
                reason: error.to_string().into_boxed_str(),
            })?
            .retained();
        Ok(Self {
            conditions: condition::conditions_of(paths::file_name(path), &facts),
            structures,
            fact_count: facts.fact_count(),
            syntax_depth: facts.syntax_depth(),
            facts: GoSourceFacts::of(&facts),
        })
    }

    /// The structured grammar facts this source states.
    pub fn facts(&self) -> &GoSourceFacts {
        &self.facts
    }

    /// Every unevaluated build predicate this source carries.
    pub fn conditions(&self) -> &[GoBuildCondition] {
        &self.conditions
    }

    /// Every logical structure this source declares, in source order.
    ///
    /// Projected from the same fact inventory above, in the same walk, by the
    /// one Go declaration authority in `pedant-syntax`. A consumer building an
    /// outline therefore reads what this parse recognized rather than
    /// recognizing Go declarations a second time.
    pub fn structures(&self) -> &[StructureRecord] {
        &self.structures
    }

    /// Where the definition the structure at `position` states sits, absent for
    /// a position this source states no structure at.
    ///
    /// This is the Go half of the graph join, stated by the owner that makes
    /// both halves. A Go report points a definition at the extent of the whole
    /// declaration — `state_definition` writes the declaration span, not the
    /// name span — and the structure projection reads that same declaration
    /// span, so the two coincide. Answering here rather than letting a consumer
    /// assume it is what makes a report that moved to the name span a change in
    /// one place instead of a silent join failure in another crate.
    pub fn definition_span(&self, position: usize) -> Option<StructureSpan> {
        self.structures.get(position).map(StructureRecord::span)
    }

    /// How many facts the bounded walk retained.
    pub fn fact_count(&self) -> u32 {
        self.fact_count
    }

    /// The deepest grammar level the bounded walk entered.
    pub fn syntax_depth(&self) -> u32 {
        self.syntax_depth
    }
}

/// The structure ceiling this source's own fact ceilings already imply.
///
/// The projection descends nothing — it reads declarations the walk above
/// already retained — so the fact ceiling is the only bound that can bind, and
/// the depth field is carried across so a refusal names the ceiling this
/// snapshot ran beneath.
///
/// A zero ceiling is refused rather than replaced. Nothing between the
/// caller-supplied [`GoResolutionLimits`](super::limits::GoResolutionLimits) and
/// this call clamps either field, so substituting the crate default would answer
/// a ceiling of zero with the *looser* bounded default — a configured refusal
/// widening the walk instead of stopping it.
fn structure_limits(limits: GoFactLimits) -> Result<StructureInventoryLimits, GoSourceFault> {
    StructureInventoryLimits::new(limits.max_syntax_depth(), limits.max_facts()).ok_or_else(|| {
        GoSourceFault::StructureProjection {
            reason: format!(
                "a ceiling of zero admits no structure: syntax depth {}, facts {}",
                limits.max_syntax_depth(),
                limits.max_facts()
            )
            .into_boxed_str(),
        }
    })
}
