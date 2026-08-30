//! The eight public operations, the module that answers each, and the one
//! dispatcher both transports state their question in.
//!
//! Nothing says that a transport must call the library operation rather than
//! assemble its own answer beside it. A second spelling answers the same
//! question until one of the two is fixed, and the byte-parity claim between
//! the CLI and the MCP server would then be a claim about two spellings that
//! agree today.

/// One public operation, and the one module that answers it.
pub(crate) struct Operation {
    /// The method a caller names on the published state.
    pub(crate) method: &'static str,
    /// The crate-internal function that answers it.
    pub(crate) answerer: &'static str,
    /// The one module that declares that function, repository-relative.
    pub(crate) module: &'static str,
}

/// The eight questions, and the eight modules that answer them.
///
/// `read_structure` and `structure_at` share a module because they are the same
/// lookup reached two ways — by handle and by point — and the specification
/// requires them to return byte-identical source for one structure. Two modules
/// would be two implementations of that identity.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        method: "list_projects",
        answerer: "projects_listed",
        module: "pedant-snippet/src/navigation/project_list.rs",
    },
    Operation {
        method: "search_symbols",
        answerer: "symbols_selected",
        module: "pedant-snippet/src/navigation/search.rs",
    },
    Operation {
        method: "outline_file",
        answerer: "outlined",
        module: "pedant-snippet/src/navigation/outline.rs",
    },
    Operation {
        method: "read_structure",
        answerer: "structure_by_handle",
        module: "pedant-snippet/src/navigation/point.rs",
    },
    Operation {
        method: "structure_at",
        answerer: "structure_at_point",
        module: "pedant-snippet/src/navigation/point.rs",
    },
    Operation {
        method: "query_relations",
        answerer: "relations_selected",
        module: "pedant-snippet/src/navigation/graph/relations.rs",
    },
    Operation {
        method: "find_path",
        answerer: "path_selected",
        module: "pedant-snippet/src/navigation/graph/route.rs",
    },
    Operation {
        method: "analyze_graph",
        answerer: "graph_analyzed",
        module: "pedant-snippet/src/navigation/graph/analysis.rs",
    },
];

/// The module that declares all eight operations on the published state.
pub(crate) const STATE_MODULE: &str = "pedant-snippet/src/index/state.rs";

/// The module both transports state their question in.
///
/// One dispatcher, so a CLI answer and an MCP answer to the same question are
/// one set of bytes rather than two that happen to agree.
pub(crate) const DISPATCH_MODULE: &str = "pedant-snippet/src/operation.rs";

/// The transport modules that must reach the library only through the
/// dispatcher.
///
/// A transport that called a state method itself would be a second place the
/// question is spelled, and the parity claim between the two transports would
/// then be a claim about two spellings that agree today.
pub(crate) const TRANSPORT_MODULES: &[&str] = &[
    "pedant-snippet/src/cli.rs",
    "pedant-snippet/src/command.rs",
    "pedant-snippet/src/registry/entries.rs",
    "pedant-snippet/src/render.rs",
    "pedant-snippet/src/request.rs",
    "pedant-snippet/src/server.rs",
];
