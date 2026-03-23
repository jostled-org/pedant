use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseCapabilityError;

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
    /// Proc macro definition (compile-time code execution)
    ProcMacro,
}

impl FromStr for Capability {
    type Err = ParseCapabilityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "network" => Ok(Self::Network),
            "file_read" => Ok(Self::FileRead),
            "file_write" => Ok(Self::FileWrite),
            "process_exec" => Ok(Self::ProcessExec),
            "env_access" => Ok(Self::EnvAccess),
            "unsafe_code" => Ok(Self::UnsafeCode),
            "ffi" => Ok(Self::Ffi),
            "crypto" => Ok(Self::Crypto),
            "system_time" => Ok(Self::SystemTime),
            "proc_macro" => Ok(Self::ProcMacro),
            _ => Err(ParseCapabilityError::new(s)),
        }
    }
}
