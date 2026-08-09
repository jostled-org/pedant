//! Temporary workspaces the index cases build from scratch.
//!
//! Stated once, so a case that needs a glob workspace and a case that needs a
//! nested one differ in the shape they ask for rather than in how they built it.
//! A workspace that starts from a committed fixture instead comes from
//! [`crate::writable_fixture`], which every mutating root shares.

use std::fs;
use std::path::Path;

pub(crate) fn write_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
}

pub(crate) fn make_nested_workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"shared\", \"shared/nested\"]\n",
    );
    fs::create_dir_all(tmp.path().join("shared/src")).unwrap();
    fs::create_dir_all(tmp.path().join("shared/nested/src")).unwrap();
    write_file(
        &tmp.path().join("shared/Cargo.toml"),
        "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &tmp.path().join("shared/src/lib.rs"),
        "pub fn shared() {}\n",
    );
    write_file(
        &tmp.path().join("shared/nested/Cargo.toml"),
        "[package]\nname = \"nested\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &tmp.path().join("shared/nested/src/lib.rs"),
        "pub fn nested() {}\n",
    );
    tmp
}

pub(crate) fn make_single_crate_workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[package]\nname = \"single-crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &tmp.path().join("src/lib.rs"),
        "use std::fs;\npub fn read_it() -> std::io::Result<String> { fs::read_to_string(\"x\") }\n",
    );
    tmp
}

pub(crate) fn make_workspace_with_go_generator() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::create_dir_all(tmp.path().join("tools")).unwrap();
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[package]\nname = \"go-generator\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(&tmp.path().join("src/lib.rs"), "pub fn rust_side() {}\n");
    write_file(
        &tmp.path().join("tools/main.go"),
        "package main\nimport \"net/http\"\n//go:generate stringer -type=Foo\nfunc main() {}\n",
    );
    tmp
}

pub(crate) fn make_glob_workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*-util\"]\n",
    );
    for crate_name in ["http-util", "fs-util", "http-core"] {
        let crate_dir = tmp.path().join("crates").join(crate_name);
        fs::create_dir_all(crate_dir.join("src")).unwrap();
        write_file(
            &crate_dir.join("Cargo.toml"),
            &format!(
                "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
            ),
        );
        write_file(&crate_dir.join("src/lib.rs"), "pub fn marker() {}\n");
    }
    tmp
}

pub(crate) fn make_nested_glob_workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*/member\"]\n",
    );
    for crate_dir in [
        tmp.path().join("crates/alpha/member"),
        tmp.path().join("crates/beta/member"),
        tmp.path().join("crates/beta/other"),
    ] {
        fs::create_dir_all(crate_dir.join("src")).unwrap();
    }
    for (crate_dir, crate_name) in [
        (tmp.path().join("crates/alpha/member"), "alpha-member"),
        (tmp.path().join("crates/beta/member"), "beta-member"),
        (tmp.path().join("crates/beta/other"), "beta-other"),
    ] {
        write_file(
            &crate_dir.join("Cargo.toml"),
            &format!(
                "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
            ),
        );
        write_file(&crate_dir.join("src/lib.rs"), "pub fn marker() {}\n");
    }
    fs::create_dir_all(tmp.path().join("unrelated/deep/tree/that/should/not/match")).unwrap();
    tmp
}
