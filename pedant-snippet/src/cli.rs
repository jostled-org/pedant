//! The command-line surface: the nine commands, and the option groups they
//! share.
//!
//! Every option a command reads is one of three groups. Host options say which
//! repository to index and under which ceilings, and every command takes them
//! because every command needs an index — the server included. Query options
//! say how to print one answer. Graph options say which edges an answer may
//! follow. A command takes the groups its question needs and nothing else,
//! which is why `path` has no depth flag: a route is as long as the topology
//! makes it.
//!
//! Every closed token this surface accepts is read through
//! [`token`](crate::token::token), so the spelling a caller types is the one the
//! library serializes and no second vocabulary exists to drift from it.
//!
//! No sentence describing a question, or one of the arguments that question
//! states, is written here. Every one of them is a `const` in
//! [`crate::registry::schema`], read through `#[command(about = …)]` and
//! `#[arg(help = …)]`, because the MCP registry describes the identical
//! arguments and two hand-written copies drifted. The sentences this module
//! does own are the ones no tool takes and no schema describes: the host
//! ceilings, the output format, and the `mcp` transport itself.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use pedant_snippet::{
    CodeIntelligenceLimits, IndexRevision, Language, MatchMode, PageCursor, ProjectAuthority,
    StructureKind,
};

#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
use crate::registry::schema::{
    ANALYSIS_MAX_BETWEENNESS_WORK, ANALYSIS_MAX_DEPTH, ANALYSIS_MAX_NODES,
    ANALYSIS_MAX_SELECTED_EDGES, ANALYSIS_MODE, ANALYZE_GRAPH, EDGE_CERTAINTIES, EDGE_KINDS,
    FIND_PATH, PATH_PROJECT, PROJECT_SUBJECT, QUERY_RELATIONS, RELATION_DEPTH, RELATION_DIRECTION,
    RELATIONS_PROJECT, ROUTE_END_SUBJECT, ROUTE_START_SUBJECT,
};
use crate::registry::schema::{
    IDENTITY_POSITION, KIND_FILTER, LANGUAGE_FILTER, LIST_PROJECTS, MATCH_MODE, OUTLINE_FILE,
    OUTLINE_PATH, OWNER_NAME_FILTER, PAGE_CURSOR, PATH_PREFIX_FILTER, POINT_COLUMN, POINT_LINE,
    POINT_PATH, READ_STRUCTURE, SEARCH_SYMBOLS, SEARCH_TEXT, STRUCTURE_AT, STRUCTURE_SUBJECT,
    identity_revision, page_size_description,
};
use crate::token::token;

/// The `pedant-snippet` command line.
#[derive(Parser, Debug)]
#[command(
    name = "pedant-snippet",
    version,
    about = "Answer navigation questions about one indexed repository"
)]
pub(crate) struct Cli {
    /// The question to answer.
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// One question, or the transport that answers many.
///
/// Two variants, because `mcp` states a transport and every other command
/// states a question. Written as one flat enum, "the server asks nothing" was an
/// invariant with two owners — the runner routed the server away and the request
/// reader returned absence for it — and the second owner's refusal branch was
/// unreachable. `clap` flattens [`Question`] into this tree, so the nine
/// published commands and their order are what they were.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// A navigation question, in the eight spellings that state one.
    #[command(flatten)]
    Answer(Question),
    /// Serve every question over stdio MCP, keeping the index current.
    Mcp(HostArgs),
}

/// The eight questions a command line can state.
#[derive(Subcommand, Debug)]
pub(crate) enum Question {
    #[command(about = LIST_PROJECTS)]
    ListProjects(ListProjectsArgs),
    #[command(about = SEARCH_SYMBOLS)]
    Search(SearchArgs),
    #[command(about = OUTLINE_FILE)]
    Outline(OutlineArgs),
    #[command(about = READ_STRUCTURE)]
    Read(ReadArgs),
    #[command(about = STRUCTURE_AT)]
    At(AtArgs),
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    #[command(about = QUERY_RELATIONS)]
    Relations(RelationsArgs),
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    #[command(about = FIND_PATH)]
    Path(PathArgs),
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    #[command(about = ANALYZE_GRAPH)]
    Graph(GraphArgs),
}

/// Which repository to index, and under which ceilings.
///
/// Every ceiling is optional and an omitted one is the documented default, so
/// the defaults live in [`CodeIntelligenceLimits`] alone. A ceiling written down
/// twice is a ceiling that can be raised in one place and not the other, and
/// every one of them is part of the index revision.
#[derive(Args, Debug)]
pub(crate) struct HostArgs {
    /// The repository root, absolute or relative to the working directory.
    #[arg(long, default_value = ".")]
    pub(crate) root: PathBuf,
    /// A project authority to select explicitly, as `rust:<PATH>` or
    /// `go:<PATH>`. Repeatable.
    #[arg(long = "project", value_parser = authority)]
    pub(crate) projects: Vec<ProjectAuthority>,
    /// Directory entries the corpus walk may visit.
    #[arg(long)]
    max_directory_entries: Option<u32>,
    /// Project authorities discovery may select.
    #[arg(long)]
    max_authorities: Option<u32>,
    /// Distinct physical source files the index may admit.
    #[arg(long)]
    max_files: Option<u32>,
    /// Bytes one source file may hold.
    #[arg(long)]
    max_source_file_bytes: Option<u64>,
    /// Bytes all retained source text may hold.
    #[arg(long)]
    max_total_source_bytes: Option<u64>,
    /// Physical logical structures the index may retain.
    #[arg(long)]
    max_structures: Option<u32>,
    /// Resolved project slices the index may retain.
    #[arg(long)]
    max_slices: Option<u32>,
    /// Graph nodes across every slice.
    #[arg(long)]
    max_graph_nodes: Option<u32>,
    /// Graph reference records across every slice.
    #[arg(long)]
    max_graph_references: Option<u32>,
    /// Graph edges across every slice.
    #[arg(long)]
    max_graph_edges: Option<u32>,
    /// Items one page may carry.
    #[arg(long)]
    max_page_items: Option<u32>,
}

/// Replace each stated ceiling on the defaults, leaving every omitted one.
///
/// A macro rather than eleven `if let` statements, because every arm is the same
/// sentence about a different field and the field names are already equal on
/// both sides. Written out, the eleventh arm is where a copy-paste assigns the
/// tenth field twice.
///
/// Named for what it does rather than for what it reads: `stated_ceilings` is
/// also the published library function that projects every ceiling for hashing,
/// and one spelling naming two unrelated jobs is one a reader has to
/// disambiguate by module.
macro_rules! apply_ceilings {
    ($repository:expr, $args:expr, $($field:ident),+ $(,)?) => {
        $(if let Some(stated) = $args.$field {
            $repository.$field = stated;
        })+
    };
}

impl HostArgs {
    /// The ceilings this command line states.
    pub(crate) fn limits(&self) -> CodeIntelligenceLimits {
        let mut limits = CodeIntelligenceLimits::default();
        apply_ceilings!(
            limits.repository,
            self,
            max_directory_entries,
            max_authorities,
            max_files,
            max_source_file_bytes,
            max_total_source_bytes,
            max_structures,
            max_slices,
            max_graph_nodes,
            max_graph_references,
            max_graph_edges,
            max_page_items,
        );
        limits
    }
}

/// How one answer is printed.
#[derive(Args, Debug)]
pub(crate) struct FormatArgs {
    /// How to print the result.
    #[arg(long, value_enum, default_value_t = Format::Json)]
    pub(crate) format: Format,
}

/// Which page of a paged answer a caller wants.
#[derive(Args, Debug)]
pub(crate) struct PageArgs {
    #[arg(long, help = page_size_help())]
    pub(crate) page_size: Option<u32>,
    #[arg(long, value_parser = token::<PageCursor>, help = PAGE_CURSOR)]
    pub(crate) cursor: Option<PageCursor>,
}

/// The shared page sentence, with the one caveat only a command line owes.
///
/// The ceiling named is the default rather than the effective one, because clap
/// renders help before it has parsed the flag that would change it. So the
/// sentence names that flag as well as the number, which is the whole of what
/// this surface can honestly promise.
fn page_size_help() -> String {
    let ceiling = CodeIntelligenceLimits::default().repository.max_page_items;
    format!(
        "{}, unless --max-page-items states another ceiling",
        page_size_description(ceiling)
    )
}

/// The shared edge sentence, with the repetition rule only a command line owes.
///
/// A tool call sends one array; a command line repeats one flag, and the schema
/// has no way to say so. So the shared clause is read from its owner and the
/// spelling rule is appended here.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn repeatable(description: &str) -> String {
    format!("{description}. Repeatable, and at least one is required")
}

/// How one answer is printed.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum Format {
    /// The shared response envelope, with a trailing newline.
    Json,
    /// A projection of that envelope, for a reader rather than a program.
    Text,
}

/// Everything `list-projects` needs.
#[derive(Args, Debug)]
pub(crate) struct ListProjectsArgs {
    #[command(flatten)]
    pub(crate) host: HostArgs,
    #[command(flatten)]
    pub(crate) format: FormatArgs,
    #[command(flatten)]
    pub(crate) page: PageArgs,
}

/// Everything `search` needs.
#[derive(Args, Debug)]
pub(crate) struct SearchArgs {
    #[arg(help = SEARCH_TEXT)]
    pub(crate) query: String,
    #[arg(long, value_parser = token::<MatchMode>, help = MATCH_MODE)]
    pub(crate) mode: MatchMode,
    #[arg(long, value_parser = token::<Language>, help = LANGUAGE_FILTER)]
    pub(crate) language: Option<Language>,
    #[arg(long, value_parser = token::<StructureKind>, help = KIND_FILTER)]
    pub(crate) kind: Option<StructureKind>,
    #[arg(long, help = OWNER_NAME_FILTER)]
    pub(crate) owner_name: Option<String>,
    #[arg(long, help = PATH_PREFIX_FILTER)]
    pub(crate) path_prefix: Option<String>,
    #[command(flatten)]
    pub(crate) host: HostArgs,
    #[command(flatten)]
    pub(crate) format: FormatArgs,
    #[command(flatten)]
    pub(crate) page: PageArgs,
}

/// Everything `outline` needs.
#[derive(Args, Debug)]
pub(crate) struct OutlineArgs {
    #[arg(help = OUTLINE_PATH)]
    pub(crate) path: String,
    #[command(flatten)]
    pub(crate) host: HostArgs,
    #[command(flatten)]
    pub(crate) format: FormatArgs,
}

/// Everything `read` needs.
#[derive(Args, Debug)]
pub(crate) struct ReadArgs {
    #[arg(value_parser = token::<IndexRevision>, help = identity_revision(STRUCTURE_SUBJECT))]
    pub(crate) revision: IndexRevision,
    #[arg(help = IDENTITY_POSITION)]
    pub(crate) structure_id: u32,
    #[command(flatten)]
    pub(crate) host: HostArgs,
    #[command(flatten)]
    pub(crate) format: FormatArgs,
}

/// Everything `at` needs.
#[derive(Args, Debug)]
pub(crate) struct AtArgs {
    #[arg(help = POINT_PATH)]
    pub(crate) path: String,
    #[arg(help = POINT_LINE)]
    pub(crate) line: u32,
    #[arg(long, help = POINT_COLUMN)]
    pub(crate) column: Option<u32>,
    #[command(flatten)]
    pub(crate) host: HostArgs,
    #[command(flatten)]
    pub(crate) format: FormatArgs,
}

/// Which edges a graph answer may follow.
///
/// Neither list has a default. `pedant-graph` publishes none because which
/// relations answer a question is policy rather than topology, and a command
/// line that picked one would make that policy invisible.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
#[derive(Args, Debug)]
pub(crate) struct EdgeArgs {
    #[arg(
        long = "edge-kind",
        required = true,
        value_parser = token::<pedant_snippet::EdgeKind>,
        help = repeatable(EDGE_KINDS),
    )]
    pub(crate) edge_kinds: Vec<pedant_snippet::EdgeKind>,
    #[arg(
        long = "certainty",
        required = true,
        value_parser = token::<pedant_snippet::EdgeCertainty>,
        help = repeatable(EDGE_CERTAINTIES),
    )]
    pub(crate) certainties: Vec<pedant_snippet::EdgeCertainty>,
}

/// Everything `relations` needs.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
#[derive(Args, Debug)]
pub(crate) struct RelationsArgs {
    #[arg(value_parser = token::<IndexRevision>, help = identity_revision(STRUCTURE_SUBJECT))]
    pub(crate) revision: IndexRevision,
    #[arg(help = IDENTITY_POSITION)]
    pub(crate) structure_id: u32,
    #[arg(long, help = RELATIONS_PROJECT)]
    pub(crate) project_id: Option<u32>,
    #[arg(
        long,
        value_parser = token::<pedant_snippet::RelationDirection>,
        help = RELATION_DIRECTION,
    )]
    pub(crate) direction: pedant_snippet::RelationDirection,
    #[arg(long, help = RELATION_DEPTH)]
    pub(crate) max_depth: u32,
    #[command(flatten)]
    pub(crate) edges: EdgeArgs,
    #[command(flatten)]
    pub(crate) host: HostArgs,
    #[command(flatten)]
    pub(crate) format: FormatArgs,
    #[command(flatten)]
    pub(crate) page: PageArgs,
}

/// Everything `path` needs.
///
/// No depth: a route is as long as the topology makes it, so the search is
/// bounded by the host's admitted node and selected-edge ceilings alone.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
#[derive(Args, Debug)]
pub(crate) struct PathArgs {
    #[arg(
        value_parser = token::<IndexRevision>,
        help = identity_revision(ROUTE_START_SUBJECT),
    )]
    pub(crate) from_revision: IndexRevision,
    #[arg(help = IDENTITY_POSITION)]
    pub(crate) from_id: u32,
    #[arg(
        value_parser = token::<IndexRevision>,
        help = identity_revision(ROUTE_END_SUBJECT),
    )]
    pub(crate) to_revision: IndexRevision,
    #[arg(help = IDENTITY_POSITION)]
    pub(crate) to_id: u32,
    #[arg(long, help = PATH_PROJECT)]
    pub(crate) project_id: Option<u32>,
    #[command(flatten)]
    pub(crate) edges: EdgeArgs,
    #[command(flatten)]
    pub(crate) host: HostArgs,
    #[command(flatten)]
    pub(crate) format: FormatArgs,
}

/// Everything `graph` needs.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
#[derive(Args, Debug)]
pub(crate) struct GraphArgs {
    #[arg(
        value_parser = token::<IndexRevision>,
        help = identity_revision(PROJECT_SUBJECT),
    )]
    pub(crate) project_revision: IndexRevision,
    #[arg(help = IDENTITY_POSITION)]
    pub(crate) project_id: u32,
    #[arg(
        value_parser = token::<pedant_snippet::AnalysisMode>,
        help = ANALYSIS_MODE,
    )]
    pub(crate) mode: pedant_snippet::AnalysisMode,
    #[arg(long, help = ANALYSIS_MAX_NODES)]
    pub(crate) max_nodes: Option<u32>,
    #[arg(long, help = ANALYSIS_MAX_SELECTED_EDGES)]
    pub(crate) max_selected_edges: Option<u32>,
    #[arg(long, help = ANALYSIS_MAX_DEPTH)]
    pub(crate) max_depth: Option<u32>,
    #[arg(long, help = ANALYSIS_MAX_BETWEENNESS_WORK)]
    pub(crate) max_betweenness_work: Option<u64>,
    #[command(flatten)]
    pub(crate) edges: EdgeArgs,
    #[command(flatten)]
    pub(crate) host: HostArgs,
    #[command(flatten)]
    pub(crate) format: FormatArgs,
}

/// Where one explicit authority's kind ends and its path begins.
const AUTHORITY_SEPARATOR: char = ':';

/// Read one `rust:<PATH>` or `go:<PATH>` authority.
///
/// The kind is required rather than guessed from the file name, because an
/// explicit authority exists precisely so a repository that spells its manifest
/// differently is still indexed, and a guess would defeat the option.
fn authority(stated: &str) -> Result<ProjectAuthority, String> {
    match stated.split_once(AUTHORITY_SEPARATOR) {
        Some(("rust", path)) => Ok(ProjectAuthority::RustManifest { path: path.into() }),
        Some(("go", path)) => Ok(ProjectAuthority::GoModule { path: path.into() }),
        _ => Err(format!(
            "a project authority is `rust:<PATH>` or `go:<PATH>`, and {stated:?} is neither"
        )),
    }
}
