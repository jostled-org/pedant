use std::io::Write;
use std::path::Path;
use std::process;
use std::sync::{Arc, RwLock};

use pedant_core::Config;
use pedant_core::ir::semantic::SemanticContext;
use pedant_mcp::index::{WorkspaceIndex, discover_workspace_root};
use pedant_mcp::server::PedantServer;
use pedant_mcp::watcher::start_watcher;
use rmcp::ServiceExt;
use rmcp::transport::io::stdio;

fn exit_with_error(message: impl std::fmt::Display) -> ! {
    let _ = writeln!(std::io::stderr(), "error: {message}");
    process::exit(1);
}

#[tokio::main]
async fn main() {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => exit_with_error(format_args!("cannot read current directory: {e}")),
    };

    let workspace_root = match discover_workspace_root(&cwd) {
        Ok(Some(root)) => root,
        Ok(None) => exit_with_error(format_args!(
            "no Cargo workspace found (walked up from {})",
            cwd.display()
        )),
        Err(error) => exit_with_error(format_args!(
            "failed to discover workspace root from {}: {error}",
            cwd.display()
        )),
    };

    let semantic = load_semantic(&workspace_root);
    let config = Arc::new(Config::default());
    let index = match WorkspaceIndex::build(&workspace_root, &config, semantic) {
        Ok(idx) => idx,
        Err(e) => exit_with_error(format_args!("failed to index workspace: {e}")),
    };

    let index = Arc::new(RwLock::new(index));

    let _watcher = match start_watcher(&index, Arc::clone(&config)) {
        Ok(w) => w,
        Err(e) => exit_with_error(format_args!("file watcher failed to start: {e}")),
    };

    let server = PedantServer::new(Arc::clone(&index));
    let running = match server.serve(stdio()).await {
        Ok(r) => r,
        Err(e) => exit_with_error(format_args!("MCP server failed to start: {e}")),
    };

    if let Err(e) = running.waiting().await {
        exit_with_error(format_args!("MCP server exited with error: {e}"));
    }
}

#[cfg(feature = "semantic")]
fn load_semantic(workspace_root: &Path) -> Option<SemanticContext> {
    match std::env::var_os("PEDANT_SEMANTIC") {
        Some(val) if val == "1" || val == "true" => SemanticContext::load(workspace_root),
        _ => None,
    }
}

#[cfg(not(feature = "semantic"))]
fn load_semantic(_workspace_root: &Path) -> Option<SemanticContext> {
    None
}
