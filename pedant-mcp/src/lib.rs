//! MCP server exposing pedant security and capability analysis.

/// Workspace discovery, per-crate analysis caching, and incremental reindexing.
pub mod index;
/// MCP tool schema definitions and registration.
pub mod schema;
/// MCP protocol bridge routing tool calls to handlers.
pub mod server;
/// Tool handler functions for security queries.
pub mod tools;
/// File system watcher for incremental reindex on source changes.
pub mod watcher;
