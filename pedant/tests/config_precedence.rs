//! `.pedant.toml`'s `max_depth` must be honored when no `--max-depth` flag is
//! passed. A clap default must never silently clobber the configured value —
//! the file is the source of truth unless the caller overrides it explicitly.

use std::fs;

mod common;

/// Three nested `match` arms: depth 3. Trips `max-depth` at limit 2, clean at 3.
const NESTED: &str = concat!(
    "pub fn deep(a: bool, b: bool, c: bool) -> u8 {\n",
    "    match a {\n",
    "        true => match b {\n",
    "            true => match c { true => 1, false => 2 },\n",
    "            false => 3,\n",
    "        },\n",
    "        false => 4,\n",
    "    }\n",
    "}\n",
);

fn workspace(max_depth: u8) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".pedant.toml"),
        format!("max_depth = {max_depth}\n"),
    )
    .unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname=\"t\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/lib.rs"), NESTED).unwrap();
    dir
}

/// With `max_depth = 2` in the file and no CLI flag, the depth-3 nest must fire.
#[test]
fn file_max_depth_is_honored_without_flag() {
    let dir = workspace(2);
    let output = common::run_pedant_in(dir.path(), &["check", "src/lib.rs", "-f", "github"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("title=max-depth"),
        "file's max_depth=2 must be honored without -d; got:\n{stdout}"
    );
}

/// With `max_depth = 5` in the file and no CLI flag, the depth-3 nest is clean —
/// proving the value read is the file's, not the old clap default of 3.
#[test]
fn file_max_depth_relaxes_below_default() {
    let dir = workspace(5);
    let output = common::run_pedant_in(dir.path(), &["check", "src/lib.rs", "-f", "github"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("title=max-depth"),
        "file's max_depth=5 must relax the limit; got:\n{stdout}"
    );
}

/// An explicit `--max-depth` flag still overrides the file value.
#[test]
fn explicit_flag_overrides_file() {
    let dir = workspace(2);
    let output = common::run_pedant_in(
        dir.path(),
        &["check", "src/lib.rs", "-d", "5", "-f", "github"],
        None,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("title=max-depth"),
        "explicit -d 5 must override the file's max_depth=2; got:\n{stdout}"
    );
}
