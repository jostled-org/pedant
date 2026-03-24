use std::future;
use std::sync::{Arc, LazyLock, RwLock};

use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ListToolsResult, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::service::RoleServer;

use crate::index::WorkspaceIndex;
use crate::schema::all_tools;
use crate::tools::{
    self, AuditCrateParams, ExplainFindingParams, QueryCapabilitiesParams, QueryGateVerdictsParams,
    QueryViolationsParams, SearchByCapabilityParams, audit_crate, explain_finding,
    query_capabilities, query_gate_verdicts, query_violations, search_by_capability,
};

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
        let tools = all_tools().to_vec();
        future::ready(Ok(ListToolsResult::with_all_items(tools)))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_ {
        let result = match self.index.read() {
            Ok(index) => dispatch_tool(&request.name, request.arguments.as_ref(), &index),
            Err(_) => tools::error_result("internal error: index lock poisoned"),
        };
        future::ready(Ok(result))
    }
}

/// Empty map used as default when no arguments are provided.
static EMPTY_ARGS: LazyLock<serde_json::Map<String, serde_json::Value>> =
    LazyLock::new(serde_json::Map::new);

/// Route a tool call by name to the appropriate handler.
fn dispatch_tool(
    name: &str,
    arguments: Option<&serde_json::Map<String, serde_json::Value>>,
    index: &WorkspaceIndex,
) -> CallToolResult {
    let args = arguments.unwrap_or(&EMPTY_ARGS);

    match name {
        "query_capabilities" => call_with(args, |p: QueryCapabilitiesParams| {
            query_capabilities(p, index)
        }),
        "query_gate_verdicts" => call_with(args, |p: QueryGateVerdictsParams| {
            query_gate_verdicts(p, index)
        }),
        "query_violations" => {
            call_with(args, |p: QueryViolationsParams| query_violations(p, index))
        }
        "search_by_capability" => call_with(args, |p: SearchByCapabilityParams| {
            search_by_capability(p, index)
        }),
        "explain_finding" => call_with(args, |p: ExplainFindingParams| explain_finding(p)),
        "audit_crate" => call_with(args, |p: AuditCrateParams| audit_crate(p, index)),
        _ => tools::error_result(&format!("unknown tool: {name}")),
    }
}

/// Deserialize arguments then invoke the handler. Returns an error result on bad params.
fn call_with<P, F>(
    tool_args: &serde_json::Map<String, serde_json::Value>,
    handler: F,
) -> CallToolResult
where
    P: serde::de::DeserializeOwned,
    F: FnOnce(P) -> CallToolResult,
{
    let wrapped = serde_json::Value::Object(tool_args.clone());
    match serde_json::from_value::<P>(wrapped) {
        Ok(params) => handler(params),
        Err(e) => tools::error_result(&format!("invalid parameters: {e}")),
    }
}
