//! Fixtures for inline-module path overrides declared from external sources.

use crate::resolution::fixture::FixtureFile;

/// An external source whose inline modules override their child directories.
///
/// `proto.rs` has different standard and declared lookup bases. Every real
/// source lives under the path relative to the declaring file's directory;
/// the duplicate `proto/proto` tree is a complete decoy for the wrong base.
/// The empty nested path must preserve `tonic`'s selected directory, while
/// both conditional alternatives must survive without evaluating host cfg.
pub const EXTERNAL_SOURCE_INLINE_PATHS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/src/lib.rs", "pub mod proto;\n"),
    (
        "repo/src/proto.rs",
        r#"#[path = "proto/tonic"]
pub mod tonic {
    #[path = ""]
    pub mod generated {
        pub mod client;
    }

    #[cfg_attr(unix, path = "unix")]
    #[cfg_attr(windows, path = "windows")]
    pub mod transport {
        pub mod endpoint;
    }
}
"#,
    ),
    (
        "repo/src/proto/tonic/client.rs",
        "pub fn generated_client() {}\n",
    ),
    (
        "repo/src/proto/tonic/unix/endpoint.rs",
        "pub fn unix_endpoint() {}\n",
    ),
    (
        "repo/src/proto/tonic/windows/endpoint.rs",
        "pub fn windows_endpoint() {}\n",
    ),
    (
        "repo/src/proto/proto/tonic/client.rs",
        "pub fn wrong_base_client() {}\n",
    ),
    (
        "repo/src/proto/proto/tonic/unix/endpoint.rs",
        "pub fn wrong_base_unix_endpoint() {}\n",
    ),
    (
        "repo/src/proto/proto/tonic/windows/endpoint.rs",
        "pub fn wrong_base_windows_endpoint() {}\n",
    ),
];

pub const EXPECTED_SOURCES: &[&str] = &[
    "src/lib.rs",
    "src/proto.rs",
    "src/proto/tonic/client.rs",
    "src/proto/tonic/unix/endpoint.rs",
    "src/proto/tonic/windows/endpoint.rs",
];

pub const EXCLUDED_DECOYS: &[&str] = &[
    "src/proto/proto/tonic/client.rs",
    "src/proto/proto/tonic/unix/endpoint.rs",
    "src/proto/proto/tonic/windows/endpoint.rs",
];

pub const EXPECTED_MODULES: &[&str] = &[
    "RustModuleId(0)|crate|src/lib.rs|0|false|None",
    "RustModuleId(1)|proto|src/proto.rs|1|false|Some(RustModuleId(0))",
    "RustModuleId(2)|tonic|src/proto.rs|2|true|Some(RustModuleId(1))",
    "RustModuleId(3)|generated|src/proto.rs|3|true|Some(RustModuleId(2))",
    "RustModuleId(4)|transport|src/proto.rs|3|true|Some(RustModuleId(2))",
    "RustModuleId(5)|transport|src/proto.rs|3|true|Some(RustModuleId(2))",
    "RustModuleId(6)|endpoint|src/proto/tonic/windows/endpoint.rs|4|false|Some(RustModuleId(5))",
    "RustModuleId(7)|endpoint|src/proto/tonic/unix/endpoint.rs|4|false|Some(RustModuleId(4))",
    "RustModuleId(8)|client|src/proto/tonic/client.rs|4|false|Some(RustModuleId(3))",
];
