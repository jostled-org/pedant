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

#[tokio::main]
async fn main() {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "error: cannot read current directory: {e}"
            );
            process::exit(1);
        }
    };

    let workspace_root = match discover_workspace_root(&cwd) {
        Some(root) => root,
        None => {
            let _ = writeln!(
                std::io::stderr(),
                "error: no Cargo workspace found (walked up from {})",
                cwd.display()
            );
            process::exit(1);
        }
    };

    let semantic = load_semantic(&workspace_root);
    let config = Arc::new(Config::default());
    let index = match WorkspaceIndex::build(&workspace_root, &config, semantic) {
        Ok(idx) => idx,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "error: failed to index workspace: {e}");
            process::exit(1);
        }
    };

    let index = Arc::new(RwLock::new(index));

    let _watcher = match start_watcher(&index, Arc::clone(&config)) {
        Ok(w) => w,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "warning: file watcher failed to start: {e}"
            );
            process::exit(1);
        }
    };

    let server = PedantServer::new(Arc::clone(&index));
    let running = match server.serve(stdio()).await {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "error: MCP server failed to start: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = running.waiting().await {
        let _ = writeln!(
            std::io::stderr(),
            "error: MCP server exited with error: {e}"
        );
        process::exit(1);
    }
}

#[cfg(feature = "semantic")]
fn load_semantic(workspace_root: &Path) -> Option<SemanticContext> {
    SemanticContext::load(workspace_root)
}

#[cfg(not(feature = "semantic"))]
fn load_semantic(_workspace_root: &Path) -> Option<SemanticContext> {
    None
}
