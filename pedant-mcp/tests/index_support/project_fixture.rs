//! Repository fixture for the shared Cargo project authority.
//!
//! The root manifest is both a workspace and a package, so a discovery path
//! that only expands `[workspace] members` misses the root crate. It also holds
//! an excluded directory, an in-root path dependency that is not a member, and
//! a source file nested well below `src/` that no module declares.
//!
//! `index.rs` and `watcher.rs` are separate test executables that need the same
//! repository, so both declare this one file with `#[path]` rather than each
//! carrying a copy.

use std::fs;
use std::path::Path;

/// Fixture files as (repository-relative path, exact contents).
const PROJECT_FILES: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        r#"[workspace]
members = ["crates/*"]
exclude = ["crates/skipped"]

[package]
name = "root-app"
version = "0.1.0"
edition = "2021"

[dependencies]
helper = { path = "vendor/helper" }
"#,
    ),
    (
        "src/lib.rs",
        "use std::fs;\npub fn read_it() -> std::io::Result<String> { fs::read_to_string(\"x\") }\n",
    ),
    (
        "crates/member/Cargo.toml",
        "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("crates/member/src/lib.rs", "pub fn member() {}\n"),
    (
        "crates/member/src/deep/nested/sibling.rs",
        "use std::net::TcpStream;\npub fn connect() -> std::io::Result<TcpStream> { TcpStream::connect(\"127.0.0.1:0\") }\n",
    ),
    (
        "crates/skipped/Cargo.toml",
        "[package]\nname = \"skipped\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("crates/skipped/src/lib.rs", "pub fn skipped() {}\n"),
    (
        "vendor/helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("vendor/helper/src/lib.rs", "pub fn helper() {}\n"),
];

/// Materialize the fixture in a fresh temporary directory that owns it.
pub(crate) fn build_project_workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    for (relative, contents) in PROJECT_FILES {
        write_fixture_file(tmp.path(), relative, contents);
    }
    tmp
}

fn write_fixture_file(base: &Path, relative: &str, contents: &str) {
    let path = base.join(relative);
    let parent = path.parent().expect("a fixture path has a parent");
    fs::create_dir_all(parent).expect("failed to create fixture directory");
    fs::write(&path, contents).expect("failed to write fixture file");
    assert!(path.is_file(), "fixture file {relative} was not created");
}
