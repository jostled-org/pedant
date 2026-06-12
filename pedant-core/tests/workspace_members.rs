use std::fs;
use std::path::Path;

use pedant_core::resolve_workspace_members;

fn write_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
}

fn make_glob_workspace() -> tempfile::TempDir {
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
    }
    tmp
}

fn make_nested_glob_workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*/plugin-*\"]\n",
    );
    for (scope, name) in [
        ("alpha", "plugin-http"),
        ("beta", "plugin-fs"),
        ("beta", "tooling"),
    ] {
        let crate_dir = tmp.path().join("crates").join(scope).join(name);
        fs::create_dir_all(crate_dir.join("src")).unwrap();
        write_file(
            &crate_dir.join("Cargo.toml"),
            &format!(
                "[package]\nname = \"{scope}-{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
            ),
        );
    }
    tmp
}

#[test]
fn resolves_glob_workspace_members() {
    let tmp = make_glob_workspace();
    let members = vec![Box::from("crates/*-util")].into_boxed_slice();
    let resolved = resolve_workspace_members(tmp.path(), &members).unwrap();
    let paths = resolved
        .iter()
        .map(|path| {
            path.strip_prefix(tmp.path())
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(paths, vec!["crates/fs-util", "crates/http-util"]);
}

#[test]
fn resolves_nested_glob_workspace_members() {
    let tmp = make_nested_glob_workspace();
    let members = vec![Box::from("crates/*/plugin-*")].into_boxed_slice();
    let resolved = resolve_workspace_members(tmp.path(), &members).unwrap();
    let paths = resolved
        .iter()
        .map(|path| {
            path.strip_prefix(tmp.path())
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec!["crates/alpha/plugin-http", "crates/beta/plugin-fs"]
    );
}
