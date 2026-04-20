use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseCapabilityError;

/// Define a Capability variant ↔ snake_case string mapping in one place.
///
/// Generates `Display` and `FromStr` from the same table so the two
/// cannot drift. Serde uses `rename_all = "snake_case"` independently
/// but produces identical strings for the same variants.
macro_rules! capability_variants {
    ($($(#[$meta:meta])* $variant:ident => $snake:literal),+ $(,)?) => {
        /// A runtime or compile-time capability that a crate may exercise.
        #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[serde(rename_all = "snake_case")]
        pub enum Capability {
            $($(#[$meta])* $variant,)+
        }

        impl fmt::Display for Capability {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let s = match self {
                    $(Self::$variant => $snake,)+
                };
                f.write_str(s)
            }
        }

        impl FromStr for Capability {
            type Err = ParseCapabilityError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($snake => Ok(Self::$variant),)+
                    _ => Err(ParseCapabilityError::new(s)),
                }
            }
        }
    };
}

capability_variants! {
    /// TCP, UDP, HTTP, WebSocket, or DNS.
    Network => "network",
    /// Reading files or walking directories.
    FileRead => "file_read",
    /// Creating, writing, or deleting files and directories.
    FileWrite => "file_write",
    /// Spawning child processes.
    ProcessExec => "process_exec",
    /// Reading environment variables.
    EnvAccess => "env_access",
    /// `unsafe` blocks, `unsafe fn`, or `unsafe impl`.
    UnsafeCode => "unsafe_code",
    /// Foreign function interface calls or `extern` blocks.
    Ffi => "ffi",
    /// Encryption, hashing, signing, or embedded key material.
    Crypto => "crypto",
    /// `SystemTime`, `Instant`, or third-party clock access.
    SystemTime => "system_time",
    /// Proc macro definition (code execution at compile time).
    ProcMacro => "proc_macro",
}
