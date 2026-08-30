//! The stdio MCP transport, over one repository kept current.
//!
//! The server builds the index before it accepts a call and watches the root for
//! as long as it serves, so every answer is about the tree as it is rather than
//! as it was at startup. Each call clones the published state and answers from
//! that clone, which is what lets a rebuild run beside a call without changing
//! what the call is part-way through.
//!
//! Shutdown is watcher-first and bounded. EOF on stdin ends the transport, the
//! watcher is then stopped and its applying thread joined, and only then does
//! the process exit — so no transaction lands after the server said it was done.

use std::future;
use std::sync::Arc;

use pedant_snippet::{CodeIntelligenceState, LiveCodeIntelligenceIndex, QueryFailure, RootWatcher};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{QuitReason, RequestContext, RoleServer};
use rmcp::transport::io::stdio;
use rmcp::{ErrorData, ServerHandler, ServiceExt};

use crate::CommandError;
use crate::cli::HostArgs;
use crate::operation::Operation;
use crate::registry;
use crate::render;

/// The MCP handler serving one live repository index.
///
/// The tool definitions are held rather than rebuilt per call: one of them
/// states this host's own page ceiling, so the set is the one this server was
/// started under and listing it twice cannot describe it two ways.
#[derive(Clone)]
struct NavigationServer {
    live: Arc<LiveCodeIntelligenceIndex>,
    tools: Arc<[Tool]>,
}

impl ServerHandler for NavigationServer {
    /// Advertise the tools, under this binary's own name.
    ///
    /// The server info is stated here rather than left to rmcp's default.
    /// `Implementation::from_build_env` reads `CARGO_CRATE_NAME` and
    /// `CARGO_PKG_VERSION`, and those expand where rmcp is compiled, not where
    /// it is used — so the default names the transport library and its release.
    /// Every client would then see `rmcp` as the server it is talking to.
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        )
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        future::ready(Ok(ListToolsResult::with_all_items(self.tools.to_vec())))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        registry::lookup(&self.tools, name)
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, ErrorData>> + Send + '_ {
        future::ready(self.called(&request.name, request.arguments))
    }
}

impl NavigationServer {
    /// Answer one call from the state published when it arrived.
    ///
    /// A malformed call never reaches a query: an unserved name and arguments
    /// that do not deserialize are protocol errors, because in neither case did
    /// a tool run.
    fn called(
        &self,
        name: &str,
        arguments: Option<rmcp::model::JsonObject>,
    ) -> Result<CallToolResult, ErrorData> {
        let operation = registry::requested(name, arguments)?;
        let state = self
            .live
            .state()
            .map_err(|failure| ErrorData::internal_error(failure.to_string(), None))?;
        Ok(answered(&operation, &state))
    }
}

/// One answered call, successful or refused.
///
/// A typed refusal is a tool error carrying the same envelope the CLI writes to
/// stderr: the question was well formed and the index answered it with a
/// refusal, which is exactly what `isError` means.
fn answered(operation: &Operation, state: &CodeIntelligenceState) -> CallToolResult {
    match operation.answered(state) {
        Ok(answer) => sent(&answer),
        Err(failure) => refused(&render::refusal(
            &QueryFailure::of(state, &failure),
            &failure,
        )),
    }
}

/// One successful answer as tool content.
fn sent(answer: &crate::operation::Answered) -> CallToolResult {
    match answer.json() {
        Ok(json) => CallToolResult::success(vec![ContentBlock::text(json)]),
        Err(failure) => refused(&CommandError::Serialize(failure).to_string()),
    }
}

/// One tool error carrying its reason.
fn refused(message: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

/// Serve every question over stdio until stdin reaches EOF.
///
/// One client speaks over one pipe pair and each call answers from retained
/// records, so a current-thread runtime carries the whole transport.
///
/// The timer is enabled because rmcp times out the shutdown this binary
/// contracts, and `tokio::time::timeout` panics without a running timer. The IO
/// driver is not enabled: this build declares no `net`, `process`, or `signal`
/// feature, and rmcp's stdio transport reaches the standard streams through the
/// blocking pool, which needs only `rt`.
pub(crate) fn serve_stdio(host: &HostArgs) -> Result<(), CommandError> {
    let limits = host.limits();
    let tools = registry::definitions(limits.repository.max_page_items);
    let live = Arc::new(LiveCodeIntelligenceIndex::open(
        &host.root,
        &host.projects,
        limits,
    )?);
    released();
    let watcher = live.watch()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(CommandError::Runtime);
    finished(
        runtime.and_then(|runtime| runtime.block_on(serve(&live, &tools))),
        watcher,
    )
}

/// Release the Rust parser's thread-local source map on this thread.
///
/// The first build parses every loose Rust source here, on the thread that then
/// serves for the life of the process, and `proc-macro2`'s `span-locations`
/// retains each parse's text and line table until its thread ends. Every later
/// rebuild happens on the applying thread, which releases its own map; this is
/// the one build that does not, so it is released here.
///
/// Safe at this point because the index retains no `syn` span — a structure
/// record carries a byte range, a line pair, and an owned name — and this
/// binary holds no syntax tree of its own.
#[cfg(feature = "lang-rust")]
fn released() {
    pedant_snippet::invalidate_parser_cache();
}

/// A build with no Rust backend parses no `syn` and fills no source map.
#[cfg(not(feature = "lang-rust"))]
fn released() {}

/// Stop the watcher, then report whichever failure the run has.
///
/// Watcher-first and unconditional: a transport that failed still leaves an
/// observing thread, and a process that exited without joining it could land a
/// transaction after it said it was done. The transport's own failure is the one
/// reported, because a teardown that also failed is a consequence of it.
fn finished(served: Result<(), CommandError>, watcher: RootWatcher) -> Result<(), CommandError> {
    let stopped = watcher.shutdown();
    served?;
    stopped.map_err(CommandError::Live)
}

/// Run the transport until the server task finishes.
async fn serve(
    live: &Arc<LiveCodeIntelligenceIndex>,
    tools: &Arc<[Tool]>,
) -> Result<(), CommandError> {
    let server = NavigationServer {
        live: Arc::clone(live),
        tools: Arc::clone(tools),
    };
    let running = server
        .serve(stdio())
        .await
        .map_err(|failure| CommandError::ServerStart(Box::new(failure)))?;
    let reason = running.waiting().await.map_err(CommandError::ServerStop)?;
    quit(reason)
}

/// The exit one finished server run reports.
///
/// Only a closed transport is the contract's shutdown: the client reached EOF
/// on stdin. Every other reason means the server stopped without being asked,
/// so the operator reads why instead of a silent zero exit.
fn quit(reason: QuitReason) -> Result<(), CommandError> {
    match reason {
        QuitReason::Closed => Ok(()),
        QuitReason::Cancelled => Err(CommandError::ServerCancelled),
        QuitReason::JoinError(failure) => Err(CommandError::ServerStop(failure)),
        other => Err(CommandError::ServerQuit(format!("{other:?}").into())),
    }
}
