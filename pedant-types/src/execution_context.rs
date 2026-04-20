use serde::{Deserialize, Serialize};

/// When during the software lifecycle a capability finding executes.
///
/// `Runtime` is normal application execution. `BuildHook` covers Rust `build.rs`
/// and analogous compile-time scripts. `InstallHook` covers package manager
/// install hooks (npm preinstall, pip setup.py). `Generator` covers code
/// generation directives like Go's `//go:generate`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionContext {
    /// Normal application execution.
    Runtime,
    /// Rust `build.rs` and analogous compile-time scripts.
    BuildHook,
    /// Package manager install hooks (npm preinstall, pip setup.py).
    InstallHook,
    /// Code generation directives (Go `//go:generate`).
    Generator,
}
