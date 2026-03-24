//! MCP server exposing pedant security and capability analysis.

/// Workspace discovery, per-crate analysis caching, and incremental reindex.
pub mod index;
/// MCP tool JSON-Schema definitions built once via `LazyLock`.
pub mod schema;
/// MCP protocol handler routing `call_tool` to query/explain/audit functions.
pub mod server;
/// Tool handler implementations for security and capability queries.
pub mod tools;
/// `notify`-based file watcher triggering incremental reindex on `.rs` changes.
pub mod watcher;
