//! Reading one command line as one question.
//!
//! Every command names the same three things — which repository, which question,
//! and how to print the answer — so this module turns each of the eight into one
//! [`Requested`] and the runner treats them all alike. The MCP registry does the
//! same job for JSON parameters, which is why neither transport renders anything
//! of its own.
//!
//! A query with nothing to normalize is written here as a struct literal with
//! named fields, rather than passed positionally to a constructor beside the
//! dispatcher. Two adjacent `Option<Box<str>>` filters handed over by position
//! could be swapped at either transport and still compile, answering a different
//! question under the same name; named fields cannot be.

use pedant_snippet::{PageRequest, StructureHandle, SymbolQuery};

use crate::cli::{
    AtArgs, Format, HostArgs, ListProjectsArgs, OutlineArgs, PageArgs, Question, ReadArgs,
    SearchArgs,
};
use crate::operation::{Operation, page};

/// One question, and everything needed to answer and print it.
pub(crate) struct Requested<'command> {
    /// Which repository to index, and under which ceilings.
    pub(crate) host: &'command HostArgs,
    /// How to print the answer.
    pub(crate) format: Format,
    /// What to ask.
    pub(crate) operation: Operation,
}

/// The question one command line states.
///
/// Total, because [`Question`] holds only questions: `mcp` is the other variant
/// of [`crate::cli::Command`] and never reaches here, so there is no absence to
/// report and no refusal branch nothing can take.
pub(crate) fn requested(question: &Question) -> Requested<'_> {
    match question {
        Question::ListProjects(args) => list_projects(args),
        Question::Search(args) => search(args),
        Question::Outline(args) => outline(args),
        Question::Read(args) => read(args),
        Question::At(args) => at(args),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        Question::Relations(args) => graph_queries::relations(args),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        Question::Path(args) => graph_queries::path(args),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        Question::Graph(args) => graph_queries::graph(args),
    }
}

/// Which page a paged command asked for.
fn paged(args: &PageArgs) -> PageRequest {
    page(args.page_size, args.cursor)
}

fn list_projects(args: &ListProjectsArgs) -> Requested<'_> {
    Requested {
        host: &args.host,
        format: args.format.format,
        operation: Operation::ListProjects(paged(&args.page)),
    }
}

fn search(args: &SearchArgs) -> Requested<'_> {
    let query = SymbolQuery {
        text: args.query.as_str().into(),
        mode: args.mode,
        language: args.language,
        kind: args.kind,
        owner_name: args.owner_name.as_deref().map(Box::from),
        path_prefix: args.path_prefix.as_deref().map(Box::from),
    };
    Requested {
        host: &args.host,
        format: args.format.format,
        operation: Operation::SearchSymbols(query, paged(&args.page)),
    }
}

fn outline(args: &OutlineArgs) -> Requested<'_> {
    Requested {
        host: &args.host,
        format: args.format.format,
        operation: Operation::OutlineFile(args.path.as_str().into()),
    }
}

fn read(args: &ReadArgs) -> Requested<'_> {
    Requested {
        host: &args.host,
        format: args.format.format,
        operation: Operation::ReadStructure(StructureHandle::new(args.revision, args.structure_id)),
    }
}

fn at(args: &AtArgs) -> Requested<'_> {
    Requested {
        host: &args.host,
        format: args.format.format,
        operation: Operation::StructureAt {
            path: args.path.as_str().into(),
            line: args.line,
            column: args.column,
        },
    }
}

/// The three questions a build with a graph producer also answers.
///
/// Grouped in one module so the feature gate is written once rather than on
/// three functions and their three call sites.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod graph_queries {
    use pedant_snippet::{AnalysisLimitRequest, ProjectHandle, StructureHandle};

    use super::{Requested, paged};
    use crate::cli::{GraphArgs, PathArgs, RelationsArgs};
    use crate::operation::{Operation, analysis_query, path_query, relation_query};

    pub(super) fn relations(args: &RelationsArgs) -> Requested<'_> {
        let query = relation_query(
            StructureHandle::new(args.revision, args.structure_id),
            args.project_id,
            args.direction,
            &args.edges.edge_kinds,
            &args.edges.certainties,
            args.max_depth,
        );
        Requested {
            host: &args.host,
            format: args.format.format,
            operation: Operation::QueryRelations(query, paged(&args.page)),
        }
    }

    pub(super) fn path(args: &PathArgs) -> Requested<'_> {
        let query = path_query(
            StructureHandle::new(args.from_revision, args.from_id),
            StructureHandle::new(args.to_revision, args.to_id),
            args.project_id,
            &args.edges.edge_kinds,
            &args.edges.certainties,
        );
        Requested {
            host: &args.host,
            format: args.format.format,
            operation: Operation::FindPath(query),
        }
    }

    pub(super) fn graph(args: &GraphArgs) -> Requested<'_> {
        let query = analysis_query(
            ProjectHandle::new(args.project_revision, args.project_id),
            args.mode,
            &args.edges.edge_kinds,
            &args.edges.certainties,
            AnalysisLimitRequest {
                max_nodes: args.max_nodes,
                max_selected_edges: args.max_selected_edges,
                max_depth: args.max_depth,
                max_betweenness_work: args.max_betweenness_work,
            },
        );
        Requested {
            host: &args.host,
            format: args.format.format,
            operation: Operation::AnalyzeGraph(query),
        }
    }
}
