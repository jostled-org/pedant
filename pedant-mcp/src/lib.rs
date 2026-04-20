//! MCP server exposing pedant security and capability analysis.

/// Workspace discovery, per-crate analysis caching, and incremental reindex.
pub mod index;
/// Single source of truth for MCP tool definitions, schemas, and dispatch.
pub mod registry;
/// MCP protocol handler routing `call_tool` through the tool registry.
pub mod server;
/// Tool handler implementations for security and capability queries.
pub mod tools;
/// `notify`-based file watcher triggering incremental reindex on `.rs` changes.
pub mod watcher;
