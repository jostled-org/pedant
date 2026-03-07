use serde::{Deserialize, Serialize};

/// A capability that a crate may exercise.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Network access (TCP, UDP, HTTP, etc.)
    Network,
    /// Filesystem read operations
    FileRead,
    /// Filesystem write operations
    FileWrite,
    /// Process spawning or execution
    ProcessExec,
    /// Environment variable access
    EnvAccess,
    /// Use of unsafe code blocks
    UnsafeCode,
    /// FFI or external function calls
    Ffi,
    /// Cryptographic operations
    Crypto,
    /// System clock or time access
    SystemTime,
}
