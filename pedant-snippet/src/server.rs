//! The stdio MCP transport for the extraction tool.

use std::future;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{QuitReason, RequestContext, RoleServer};
use rmcp::transport::io::stdio;
use rmcp::{ErrorData, ServerHandler, ServiceExt};

use crate::CommandError;
use crate::tool;

/// The MCP handler serving one extraction tool.
///
/// It holds no state: every call reads its own file and answers on its own.
struct SnippetServer;

impl ServerHandler for SnippetServer {
    /// Advertise the one tool, under this binary's own name.
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
        future::ready(Ok(ListToolsResult::with_all_items(
            vec![tool::definition()],
        )))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        tool::lookup(name)
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, ErrorData>> + Send + '_ {
        future::ready(tool::dispatch(&request.name, request.arguments))
    }
}

/// Serve the tool over stdio until stdin reaches EOF.
///
/// One client speaks over one pipe pair and each call answers from one short
/// file read, so a current-thread runtime carries the whole transport.
///
/// The timer is enabled because rmcp times out the shutdown this binary
/// contracts, and `tokio::time::timeout` panics without a running timer. The IO
/// driver is not enabled: this build declares no `net`, `process`, or `signal`
/// feature, and rmcp's stdio transport reaches the standard streams through the
/// blocking pool, which needs only `rt`.
pub(crate) fn serve_stdio() -> Result<(), CommandError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(CommandError::Runtime)?
        .block_on(serve())
}

/// Run the transport until the server task finishes.
async fn serve() -> Result<(), CommandError> {
    let running = SnippetServer
        .serve(stdio())
        .await
        .map_err(|failure| CommandError::ServerStart(Box::new(failure)))?;
    let reason = running.waiting().await.map_err(CommandError::ServerStop)?;
    finished(reason)
}

/// The exit one finished server run reports.
///
/// Only a closed transport is the contract's shutdown: the client reached EOF
/// on stdin. Every other reason means the server stopped without being asked,
/// so the operator reads why instead of a silent zero exit.
fn finished(reason: QuitReason) -> Result<(), CommandError> {
    match reason {
        QuitReason::Closed => Ok(()),
        QuitReason::Cancelled => Err(CommandError::ServerCancelled),
        QuitReason::JoinError(failure) => Err(CommandError::ServerStop(failure)),
        other => Err(CommandError::ServerQuit(format!("{other:?}").into())),
    }
}
