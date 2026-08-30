//! What no module of the completed product tree may do.
//!
//! The negative half of Invariant 16, stated beside the positive half in
//! [`capability_model`](super::capability_model). Every row is a spelling a
//! reader would have to write to grant this product a capability its audit
//! refused, read out of the product's own sources.
//!
//! The edge a source scan cannot see — a capability that arrives as a
//! dependency and is used through a re-export — is forbidden by name in
//! [`dependency_model`](super::dependency_model), which the boundary proof and
//! the source-capability proof both read. One list, so neither can forbid a
//! crate the other admits.

/// One forbidden route, and why no module of this product may take it.
pub(crate) struct ForbiddenRoute {
    /// The exact spelling no module may state.
    pub(crate) evidence: &'static str,
    /// The family a failure reports it under.
    pub(crate) family: &'static str,
}

/// Every route Invariant 16 forbids, by the capability it would grant.
///
/// The toolchain rows are the ones a navigation product is most likely to grow:
/// an answer that could be improved by asking Cargo, Go, or a language server
/// is exactly the answer a reader wishes were better, and the specification's
/// third load-bearing constraint is that it must not be bought that way.
pub(crate) const FORBIDDEN_ROUTES: &[ForbiddenRoute] = &[
    ForbiddenRoute {
        evidence: "fs::write",
        family: "file write",
    },
    ForbiddenRoute {
        evidence: "File::create",
        family: "file write",
    },
    ForbiddenRoute {
        evidence: "OpenOptions",
        family: "file write",
    },
    ForbiddenRoute {
        evidence: "create_dir",
        family: "file write",
    },
    ForbiddenRoute {
        evidence: "remove_file",
        family: "file write",
    },
    ForbiddenRoute {
        evidence: "remove_dir",
        family: "file write",
    },
    ForbiddenRoute {
        evidence: "std::process::Command",
        family: "process execution",
    },
    ForbiddenRoute {
        evidence: "Command::new",
        family: "process execution",
    },
    ForbiddenRoute {
        evidence: "TcpStream",
        family: "network",
    },
    ForbiddenRoute {
        evidence: "TcpListener",
        family: "network",
    },
    ForbiddenRoute {
        evidence: "UdpSocket",
        family: "network",
    },
    ForbiddenRoute {
        evidence: "reqwest",
        family: "network",
    },
    ForbiddenRoute {
        evidence: "ra_ap_",
        family: "language server",
    },
    ForbiddenRoute {
        evidence: "rust-analyzer",
        family: "language server",
    },
    ForbiddenRoute {
        evidence: "cargo metadata",
        family: "toolchain invocation",
    },
    ForbiddenRoute {
        evidence: "go build",
        family: "toolchain invocation",
    },
    ForbiddenRoute {
        evidence: "tsc --",
        family: "toolchain invocation",
    },
    ForbiddenRoute {
        evidence: "VecDeque",
        family: "a graph traversal this crate does not own",
    },
    ForbiddenRoute {
        evidence: "BinaryHeap",
        family: "a graph traversal this crate does not own",
    },
    ForbiddenRoute {
        evidence: "petgraph",
        family: "a graph traversal this crate does not own",
    },
];

/// The trees no module of the navigation surface may parse.
///
/// Invariant 3: a source is parsed and walked at most once per index revision,
/// and the index did that before it published. A query that reached a parser
/// would be answering from a repository the revision no longer names.
pub(crate) const NO_PARSE_TREE: &str = "pedant-snippet/src/navigation";

/// Every spelling that would be a parse or a declaration walk.
pub(crate) const PARSE_EVIDENCE: &[&str] = &[
    "syn::parse",
    "parse_file",
    "enclosing_unit",
    "structure_inventory",
    "tree_sitter",
];
