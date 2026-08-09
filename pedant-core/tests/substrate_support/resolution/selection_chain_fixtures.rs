//! Branching and deep dependency graphs for selection-ancestry proofs.

use crate::resolution::fixture::FixtureFile;

/// Two four-edge branches whose selection performs eight ancestry extensions.
pub const BRANCHING_DEEP_CHAIN: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
left0 = { path = "crates/left0" }
right0 = { path = "crates/right0" }
"#,
    ),
    ("repo/src/lib.rs", "pub fn app() {}\n"),
    ("repo/crates/left0/Cargo.toml", LEFT0_MANIFEST),
    ("repo/crates/left0/src/lib.rs", "pub fn left0() {}\n"),
    ("repo/crates/left1/Cargo.toml", LEFT1_MANIFEST),
    ("repo/crates/left1/src/lib.rs", "pub fn left1() {}\n"),
    ("repo/crates/left2/Cargo.toml", LEFT2_MANIFEST),
    ("repo/crates/left2/src/lib.rs", "pub fn left2() {}\n"),
    ("repo/crates/left3/Cargo.toml", LEFT3_MANIFEST),
    ("repo/crates/left3/src/lib.rs", "pub fn left3() {}\n"),
    ("repo/crates/right0/Cargo.toml", RIGHT0_MANIFEST),
    ("repo/crates/right0/src/lib.rs", "pub fn right0() {}\n"),
    ("repo/crates/right1/Cargo.toml", RIGHT1_MANIFEST),
    ("repo/crates/right1/src/lib.rs", "pub fn right1() {}\n"),
    ("repo/crates/right2/Cargo.toml", RIGHT2_MANIFEST),
    ("repo/crates/right2/src/lib.rs", "pub fn right2() {}\n"),
    ("repo/crates/right3/Cargo.toml", RIGHT3_MANIFEST),
    ("repo/crates/right3/src/lib.rs", "pub fn right3() {}\n"),
];

const LEFT0_MANIFEST: &str = r#"[package]
name = "left0"
version = "0.1.0"
edition = "2021"

[dependencies]
left1 = { path = "../left1" }
"#;

const LEFT1_MANIFEST: &str = r#"[package]
name = "left1"
version = "0.1.0"
edition = "2021"

[dependencies]
left2 = { path = "../left2" }
"#;

const LEFT2_MANIFEST: &str = r#"[package]
name = "left2"
version = "0.1.0"
edition = "2021"

[dependencies]
left3 = { path = "../left3" }
"#;

const LEFT3_MANIFEST: &str =
    "[package]\nname = \"left3\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";

const RIGHT0_MANIFEST: &str = r#"[package]
name = "right0"
version = "0.1.0"
edition = "2021"

[dependencies]
right1 = { path = "../right1" }
"#;

const RIGHT1_MANIFEST: &str = r#"[package]
name = "right1"
version = "0.1.0"
edition = "2021"

[dependencies]
right2 = { path = "../right2" }
"#;

const RIGHT2_MANIFEST: &str = r#"[package]
name = "right2"
version = "0.1.0"
edition = "2021"

[dependencies]
right3 = { path = "../right3" }
"#;

const RIGHT3_MANIFEST: &str =
    "[package]\nname = \"right3\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
