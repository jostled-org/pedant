//! The two ceilings one structure inventory runs beneath.

/// What one source-bound structure inventory may spend.
///
/// Both ceilings are refusals rather than truncations: reaching either returns
/// a [`StructureError`](super::StructureError) and no inventory, so a caller
/// never reads a partial structure set as a complete one. That is the whole
/// point of the type — an outline that silently stopped at its ceiling would
/// name fewer structures than the source holds and carry no sign of it.
///
/// The fields are private and checked, because zero admits nothing: a zero
/// depth refuses before the first descent and a zero count refuses before the
/// first retention, so every inventory a zero-bearing limit could produce is
/// empty regardless of the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructureInventoryLimits {
    max_syntax_depth: u32,
    max_structures_per_source: u32,
}

/// The deepest tree level a bounded walk descends to by default.
const DEFAULT_SYNTAX_DEPTH: u32 = 256;

/// The largest inventory one source may state by default.
const DEFAULT_STRUCTURES_PER_SOURCE: u32 = 262_144;

impl StructureInventoryLimits {
    /// A limit with the deepest admitted tree level and the largest admitted
    /// inventory.
    ///
    /// Absent when either ceiling is zero, which no source can satisfy.
    pub fn new(max_syntax_depth: u32, max_structures_per_source: u32) -> Option<Self> {
        match (max_syntax_depth, max_structures_per_source) {
            (0, _) | (_, 0) => None,
            (depth, structures) => Some(Self {
                max_syntax_depth: depth,
                max_structures_per_source: structures,
            }),
        }
    }

    /// The deepest level the declaration walk may descend to, counting the
    /// source root as zero.
    ///
    /// The walk's own descent, which differs by backend because the backends
    /// descend through different things: a bound tree's walk counts grammar
    /// nodes, and the Rust item walk counts declarations. Both are the levels
    /// that walk actually enters, so both are checked before entering one.
    pub fn max_syntax_depth(self) -> u32 {
        self.max_syntax_depth
    }

    /// The largest number of structures one source's inventory may hold.
    pub fn max_structures_per_source(self) -> u32 {
        self.max_structures_per_source
    }
}

impl Default for StructureInventoryLimits {
    /// The bounded default every loose source is walked beneath.
    fn default() -> Self {
        Self {
            max_syntax_depth: DEFAULT_SYNTAX_DEPTH,
            max_structures_per_source: DEFAULT_STRUCTURES_PER_SOURCE,
        }
    }
}

/// Whether a bounded walk may hold `depth`, counting the source root as zero.
///
/// The one depth comparison in this crate. Three readers ask it — the structure
/// builder before it admits a level, the Go fact walk before it moves its
/// cursor, and the Go structure projection against the depth that walk already
/// reported — and each mints its own refusal from a `false`, because a refusal
/// names the contract that made it. The comparison itself is single, so a
/// ceiling cannot be widened on one side and leave the others bounded
/// differently.
///
/// It sits beside the structure ceiling because that ceiling is the one handed
/// across: `structure::bound` builds the Go fact walk's limits from
/// [`max_syntax_depth`](StructureInventoryLimits::max_syntax_depth) and maps
/// that walk's depth refusal back into `StructureError::SyntaxDepthExceeded`, so
/// on the structure route the two walks are bounded by one number and must admit
/// exactly the same levels.
#[cfg(any(feature = "rust", feature = "_ts"))]
pub(crate) fn admits(depth: u32, limit: u32) -> bool {
    depth <= limit
}

/// The same comparison, for a walk that counts its levels in `usize`.
///
/// The narrowing alone: a level no `u32` can name is past every ceiling this
/// crate can state, including the widest one, so it is refused rather than
/// compared. Saturating it into `u32::MAX` instead would make the deepest
/// admissible source the one that spends the most stack.
#[cfg(any(feature = "rust", feature = "_ts"))]
pub(crate) fn admits_depth(depth: usize, limit: u32) -> bool {
    u32::try_from(depth).is_ok_and(|depth| admits(depth, limit))
}
