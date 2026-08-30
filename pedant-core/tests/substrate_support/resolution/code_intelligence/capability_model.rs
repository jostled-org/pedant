//! What the completed product tree may do, and the exact module that may do it.
//!
//! The positive half of Invariant 16. Its negative half is
//! [`forbidden_model`](super::forbidden_model), and neither is worth much
//! alone: a forbid is satisfiable by a tree nobody read, and the evidence a
//! named owner *must* state is what keeps the forbid from being vacuous. If the
//! reader stopped seeing `File::open` in the one module that opens a file, it
//! stopped seeing `fs::write` everywhere too.

/// One capability the product holds, the module allowed to state it, and the
/// exact evidence that module states.
pub(crate) struct CapabilityOwner {
    /// What the owner is admitted to do, as a failure names it.
    pub(crate) capability: &'static str,
    /// The one module allowed to state it, repository-relative.
    pub(crate) module: &'static str,
    /// Every spelling the owner must state. All of them, so an owner that
    /// stopped reaching its dependency fails here rather than widening the
    /// forbid below into a claim about nothing.
    pub(crate) evidence: &'static [&'static str],
}

/// Every capability the completed product holds.
///
/// Six owners and no seventh. A read arrives through one opener, a directory
/// through one walker, a canonical path through one normalizer, a change
/// through one watcher, an elapsed span through the drain that watcher feeds,
/// and a digest through the two revision claims that mint one. Every other
/// module of the product works on bytes already in memory.
pub(crate) const CAPABILITY_OWNERS: &[CapabilityOwner] = &[
    CapabilityOwner {
        capability: "opening a source file",
        module: "pedant-snippet/src/index/read.rs",
        evidence: &["std::fs::File", "File::open"],
    },
    CapabilityOwner {
        capability: "resolving a path against the canonical root",
        module: "pedant-snippet/src/index/path.rs",
        evidence: &["canonicalize"],
    },
    CapabilityOwner {
        capability: "walking the repository under its ignore files",
        module: "pedant-snippet/src/index/discovery.rs",
        evidence: &["ignore::WalkBuilder"],
    },
    CapabilityOwner {
        capability: "observing the root for changes",
        module: "pedant-snippet/src/live/watcher.rs",
        evidence: &["notify::recommended_watcher", "RecommendedWatcher"],
    },
    CapabilityOwner {
        capability: "measuring how long one change drain has run",
        module: "pedant-snippet/src/live/watcher.rs",
        evidence: &["Instant::now"],
    },
    CapabilityOwner {
        capability: "stating the process exit status",
        module: "pedant-snippet/src/main.rs",
        evidence: &["std::process::ExitCode"],
    },
];

/// The modules that hash bytes already in memory.
///
/// Two rather than one: a source digest and a revision claim are different
/// answers taken with the same primitive, and collapsing them would put the
/// revision vocabulary inside the file reader.
pub(crate) const DIGEST_OWNERS: &[&str] = &[
    "pedant-snippet/src/index/claim.rs",
    "pedant-snippet/src/index/read.rs",
];

/// The spelling every digest owner states.
pub(crate) const DIGEST_EVIDENCE: &str = "Sha256";
