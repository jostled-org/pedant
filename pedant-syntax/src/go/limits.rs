//! The two ceilings a Go fact extraction runs beneath.

/// What one Go fact extraction may spend.
///
/// Both ceilings are refusals rather than truncations: reaching either returns
/// a [`GoFactError`](super::GoFactError) and no inventory, so a caller never
/// reads a partial fact set as a complete one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoFactLimits {
    max_syntax_depth: u32,
    max_facts: u32,
}

impl GoFactLimits {
    /// The compatibility limit, which spends everything.
    ///
    /// Capability detection runs beneath this one. Its input is a single source
    /// its own caller already bounded, and its published findings predate any
    /// ceiling here, so a limit that could refuse would change output that is
    /// security evidence. A Go resolution snapshot converts its own
    /// caller-supplied ceilings instead.
    pub const UNBOUNDED: Self = Self {
        max_syntax_depth: u32::MAX,
        max_facts: u32::MAX,
    };

    /// A limit with the deepest admitted node and the largest admitted
    /// inventory.
    pub fn new(max_syntax_depth: u32, max_facts: u32) -> Self {
        Self {
            max_syntax_depth,
            max_facts,
        }
    }

    /// The deepest tree level the walk may descend to, counting the root as
    /// zero.
    pub fn max_syntax_depth(self) -> u32 {
        self.max_syntax_depth
    }

    /// The largest number of facts one inventory may hold.
    pub fn max_facts(self) -> u32 {
        self.max_facts
    }
}
