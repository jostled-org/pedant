//! Which ceilings and counters the completed product owns, where each is
//! declared, and how a body is read for the order it checks and retains in.
//!
//! Invariant 14 is one claim in two halves. Every ceiling is projected once to
//! a named owner — a second module declaring its own copy is how a product ends
//! up with two numbers under one name, one of which no revision hashes — and
//! every check happens before the first excess record is retained, which no
//! input small enough to test would reveal.

/// One limit or counter type, and the module that declares it.
pub(crate) struct BoundedFamily {
    /// The type's name.
    pub(crate) name: &'static str,
    /// The one module that declares it, repository-relative.
    pub(crate) module: &'static str,
}

/// Every ceiling, ceiling registry, and cost counter the product owns.
///
/// Invariant 14 is that every ceiling is projected once to a named owner. A
/// second module declaring its own copy of a ceiling is how a product ends up
/// with two numbers under one name, one of which no revision hashes.
pub(crate) const BOUNDED_FAMILIES: &[BoundedFamily] = &[
    BoundedFamily {
        name: "CodeIntelligenceLimits",
        module: "pedant-snippet/src/index/limits.rs",
    },
    BoundedFamily {
        name: "RepositoryLimits",
        module: "pedant-snippet/src/index/limits.rs",
    },
    BoundedFamily {
        name: "LimitField",
        module: "pedant-snippet/src/index/limit_field.rs",
    },
    BoundedFamily {
        name: "GraphBudget",
        module: "pedant-snippet/src/index/graph_budget.rs",
    },
    BoundedFamily {
        name: "AnalysisLimitRequest",
        module: "pedant-snippet/src/navigation/graph/budget.rs",
    },
    BoundedFamily {
        name: "CapacityOwner",
        module: "pedant-snippet/src/index/error.rs",
    },
    BoundedFamily {
        name: "CapacityCollection",
        module: "pedant-snippet/src/index/error.rs",
    },
    BoundedFamily {
        name: "SourceWork",
        module: "pedant-snippet/src/index/observe.rs",
    },
    BoundedFamily {
        name: "WorkPhase",
        module: "pedant-snippet/src/index/observe.rs",
    },
];

/// The module that lists every ceiling a revision hashes.
pub(crate) const CEILING_REGISTRY: &str = "pedant-snippet/src/index/limit_inventory.rs";

/// The module that mints every capacity refusal.
pub(crate) const CAPACITY_OWNER: &str = "pedant-snippet/src/index/error.rs";

/// The spellings that mean a collection just grew.
pub(crate) const RETENTION_CALLS: &[&str] = &[".push(", ".insert(", ".extend("];

/// The receivers whose growth no ceiling governs.
///
/// An issue list is the record of what a build could not do. It is bounded by
/// the corpus rather than by a limit, and a build that refused to record why it
/// refused would be worse than one that recorded a line too many — so an
/// `issues.push` before a ceiling check is not a retention the ordering claim is
/// about. Naming the receivers here rather than skipping "small" collections
/// keeps the exception readable and one line long.
pub(crate) const DIAGNOSTIC_RECEIVERS: &[&str] = &["issues", "self.issues"];

/// The spelling that means a ceiling was just checked.
///
/// Every refusal in this product is minted by one helper, so the check is
/// findable by name rather than by recognizing a comparison. That is also why
/// [`CAPACITY_OWNER`] is asserted separately: the name would stop meaning
/// anything if a second module started minting its own.
pub(crate) const CAPACITY_CALL: &str = "capacity(";
