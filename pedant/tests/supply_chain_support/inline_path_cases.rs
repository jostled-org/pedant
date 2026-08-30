//! Supply-chain evidence for inline path overrides in external sources.

use std::path::Path;

use crate::baseline_store::VendoredWorkspace;
use crate::fixtures::{VendorFixture, manifest, write, write_library_crate};

/// Debug-package inputs expected from the inline path-override fixture.
/// `false` entries are valid generated sources at the duplicated lookup base.
const INLINE_PATH_OVERRIDE_DEBUG_FILES: &[(&str, bool)] = &[
    ("src/lib.rs", true),
    ("src/proto.rs", true),
    ("src/proto/tonic/telemetry.rs", true),
    ("src/proto/grpc/telemetry.rs", true),
    ("src/proto/proto/tonic/telemetry.rs", false),
    ("src/proto/proto/grpc/telemetry.rs", false),
];

/// An inline path override in an external source resolves from that source's
/// declared directory. Nested generated children remain beneath every
/// conditional alternative, never beneath the standard module lookup base.
#[test]
fn init_and_verify_hash_generated_children_beneath_inline_path_overrides() {
    let fixture = VendorFixture::new();
    write_inline_path_override_crate(&fixture.crate_dir("inline-path-children"));
    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());
    let verify = fixture.supply_chain("verify");
    assert!(verify.success(), "verify failed: {}", verify.transcript());
    assert!(
        verify.stdout.contains("All dependencies match baselines."),
        "{}",
        verify.transcript()
    );
    let debug = fixture.debug_package("inline-path-children");
    assert!(debug.success(), "debug failed: {}", debug.transcript());
    let stderr = debug.stderr.as_ref();
    for (path, expected) in INLINE_PATH_OVERRIDE_DEBUG_FILES {
        let label = format!("file: ./{path}").into_boxed_str();
        assert_eq!(stderr.contains(&*label), *expected, "{label}: {stderr}");
    }
}

/// A published crate can retain a workspace-only `cfg_attr` path beside the
/// packaged path Cargo actually builds. `cargo vendor` places the named
/// workspace sibling beside it, but that sibling is not source shipped by this
/// package and must not enter this package's attestation.
#[test]
fn conditional_path_outside_a_vendored_package_is_not_shipped_source() {
    let fixture = VendorFixture::new();
    write_workspace_conditional_crate(&fixture.crate_dir("derive-internals"));
    write_library_crate(
        &fixture.crate_dir("derive"),
        &manifest("derive", "0.1.0"),
        "pub mod internals;\n",
    );
    write(
        &fixture.crate_dir("derive/src/internals.rs"),
        "pub fn workspace_only() {}\n",
    );

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());
    let debug = fixture.debug_package("derive-internals");
    assert!(debug.success(), "debug failed: {}", debug.transcript());
    let files: Vec<&str> = debug
        .stderr
        .lines()
        .filter_map(|line| line.strip_prefix("file: "))
        .filter_map(|line| line.split_once(" bytes=").map(|(path, _)| path))
        .collect();
    assert_eq!(
        files,
        ["./lib.rs", "./src/mod.rs"],
        "the sibling package is attested under its own identity: {}",
        debug.stderr
    );
}

fn write_workspace_conditional_crate(root: &Path) {
    write(
        &root.join("Cargo.toml"),
        format!(
            "{}\n[lib]\npath = \"lib.rs\"\n",
            manifest("derive-internals", "0.1.0")
        ),
    );
    write(
        &root.join("lib.rs"),
        "#[cfg_attr(from_workspace, path = \"../derive/src/internals.rs\")]\n\
         #[cfg_attr(not(from_workspace), path = \"src/mod.rs\")]\n\
         mod internals;\n",
    );
    write(&root.join("src/mod.rs"), "pub fn packaged() {}\n");
}

/// Materializes the correct and duplicated-base trees used by the journey.
fn write_inline_path_override_crate(root: &Path) {
    write_library_crate(
        root,
        &manifest("inline-path-children", "0.1.0"),
        "mod proto;\n",
    );
    write(
        &root.join("src/proto.rs"),
        "#[cfg_attr(unix, path = \"proto/tonic\")]\n\
         #[cfg_attr(windows, path = \"proto/grpc\")]\n\
         mod transport {\n\
             #[path = \"\"]\n\
             mod generated {\n\
                 mod telemetry;\n\
             }\n\
         }\n",
    );
    for path in [
        "src/proto/tonic/telemetry.rs",
        "src/proto/grpc/telemetry.rs",
        "src/proto/proto/tonic/telemetry.rs",
        "src/proto/proto/grpc/telemetry.rs",
    ] {
        write(&root.join(path), "pub fn generated() {}\n");
    }
}
