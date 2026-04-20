use std::future;
use std::sync::{Arc, RwLock};

use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ListToolsResult, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::service::RoleServer;

use crate::index::WorkspaceIndex;
use crate::registry;
use crate::tools;

/// MCP protocol handler backed by a shared, incrementally-updated workspace index.
pub struct PedantServer {
    index: Arc<RwLock<WorkspaceIndex>>,
}

impl PedantServer {
    /// Wrap a shared index for use as an MCP server.
    pub fn new(index: Arc<RwLock<WorkspaceIndex>>) -> Self {
        Self { index }
    }
}

impl ServerHandler for PedantServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }

    fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_ {
        let tools = registry::all_tools().to_vec();
        future::ready(Ok(ListToolsResult::with_all_items(tools)))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_ {
        let result = match self.index.read() {
            Ok(index) => registry::dispatch(&request.name, request.arguments.as_ref(), &index),
            Err(_) => tools::error_result("internal error: index lock poisoned"),
        };
        future::ready(Ok(result))
    }
}
