use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseCapabilityError;

/// A runtime or compile-time capability that a crate may exercise.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// TCP, UDP, HTTP, WebSocket, or DNS.
    Network,
    /// Reading files or walking directories.
    FileRead,
    /// Creating, writing, or deleting files and directories.
    FileWrite,
    /// Spawning child processes.
    ProcessExec,
    /// Reading environment variables.
    EnvAccess,
    /// `unsafe` blocks, `unsafe fn`, or `unsafe impl`.
    UnsafeCode,
    /// Foreign function interface calls or `extern` blocks.
    Ffi,
    /// Encryption, hashing, signing, or embedded key material.
    Crypto,
    /// `SystemTime`, `Instant`, or third-party clock access.
    SystemTime,
    /// Proc macro definition (code execution at compile time).
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
