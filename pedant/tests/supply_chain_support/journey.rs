//! The root-only, complete, failure-atomic supply-chain journey.
//!
//! The union case fixes what a package's primary targets reach. The failure
//! table breaks one healthy vendored crate in each of the ways the
//! specification calls security-fatal, and requires every command to refuse it
//! with the baseline store byte-for-byte unchanged.

use std::path::Path;

use pedant_types::ExecutionContext;

use crate::baseline_store::VendoredWorkspace;
use crate::fixtures::{VendorFixture, manifest, write, write_library_crate};

/// One way a selected source can fail, and the evidence the command must give.
pub(crate) struct FailureRow {
    pub(crate) label: &'static str,
    pub(crate) break_crate: fn(&Path, &Path),
    pub(crate) evidence: &'static str,
}

/// Every closure failure the specification calls security-fatal.
pub(crate) const FAILURE_ROWS: &[FailureRow] = &[
    FailureRow {
        label: "entry read",
        break_crate: break_entry_read,
        evidence: "could not be resolved",
    },
    FailureRow {
        label: "source parse",
        break_crate: break_source_parse,
        evidence: "is not valid Rust",
    },
    FailureRow {
        label: "missing module",
        break_crate: break_missing_module,
        evidence: "no source exists for the declared module",
    },
    FailureRow {
        label: "ambiguous module",
        break_crate: break_ambiguous_module,
        evidence: "both name.rs and name/mod.rs exist",
    },
    FailureRow {
        label: "invalid utf-8",
        break_crate: break_invalid_utf8,
        evidence: "is not valid UTF-8",
    },
    FailureRow {
        label: "symlink escape",
        break_crate: break_symlink_escape,
        evidence: "resolves outside the repository root",
    },
    FailureRow {
        label: "#[path] escape",
        break_crate: break_path_escape,
        evidence: "resolves outside the repository root",
    },
    FailureRow {
        label: "limit excess",
        break_crate: break_limit,
        evidence: "ceiling of 8388608 is exceeded",
    },
];

/// A declared entry point that no file answers.
fn break_entry_read(crate_dir: &Path, _vendor_root: &Path) {
    write(
        &crate_dir.join("Cargo.toml"),
        format!(
            "{}\n[lib]\npath = \"src/ghost.rs\"\n",
            manifest("subject", "0.1.0")
        ),
    );
}

fn break_source_parse(crate_dir: &Path, _vendor_root: &Path) {
    write(&crate_dir.join("src/lib.rs"), "pub fn api( {}\n");
}

fn break_missing_module(crate_dir: &Path, _vendor_root: &Path) {
    write(&crate_dir.join("src/lib.rs"), "mod ghost;\n");
}

fn break_ambiguous_module(crate_dir: &Path, _vendor_root: &Path) {
    write(&crate_dir.join("src/lib.rs"), "mod dual;\n");
    write(&crate_dir.join("src/dual.rs"), "pub fn flat() {}\n");
    write(&crate_dir.join("src/dual/mod.rs"), "pub fn nested() {}\n");
}

fn break_invalid_utf8(crate_dir: &Path, _vendor_root: &Path) {
    write(&crate_dir.join("src/lib.rs"), "mod raw;\n");
    write(&crate_dir.join("src/raw.rs"), [0xffu8, 0xfe, 0x0a]);
}

fn break_symlink_escape(crate_dir: &Path, vendor_root: &Path) {
    let outside = vendor_root.join("escape.rs");
    write(&outside, "pub fn escaped() {}\n");
    write(&crate_dir.join("src/lib.rs"), "mod outside;\n");
    symlink(&outside, &crate_dir.join("src/outside.rs"));
}

fn break_path_escape(crate_dir: &Path, vendor_root: &Path) {
    write(&vendor_root.join("escape.rs"), "pub fn escaped() {}\n");
    write(
        &crate_dir.join("src/lib.rs"),
        "#[path = \"../../escape.rs\"]\nmod outside;\n",
    );
}

/// One byte past the documented 8 MiB per-source ceiling. Size is measured
/// before the file is opened, so the refusal happens without a read.
fn break_limit(crate_dir: &Path, _vendor_root: &Path) {
    write(
        &crate_dir.join("src/lib.rs"),
        vec![b'\n'; 8 * 1024 * 1024 + 1],
    );
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("a fixture symlink");
}

#[cfg(windows)]
fn symlink(target: &Path, link: &Path) {
    std::os::windows::fs::symlink_file(target, link).expect("a fixture symlink");
}

/// The union of one package's library, binary, and build-script closures is
/// exactly what an attestation hashes.
pub(crate) fn primary_target_union_is_root_only_and_complete() {
    let fixture = VendorFixture::new();
    write_primary_target_crate(&fixture.crate_dir("primary"));

    let init = fixture.supply_chain("init");
    assert!(init.success(), "init failed: {}", init.transcript());

    let debug = fixture.debug_package("primary");
    let stderr = debug.stderr.as_ref();
    for selected in SELECTED_SOURCES {
        assert!(stderr.contains(selected), "missing {selected}: {stderr}");
    }
    for excluded in ["unreached", "it.rs", "inner"] {
        assert!(
            !stderr.contains(excluded),
            "unselected {excluded} entered the hash: {stderr}"
        );
    }
    assert!(
        stderr.contains("analysis: analyzed_files=6 skipped_files=0"),
        "a snapshot-backed attestation must report complete analysis: {stderr}"
    );

    let baseline = fixture.baselines().read("primary", "0.3.0");
    let completeness = baseline
        .analysis_completeness
        .as_ref()
        .expect("a snapshot-backed attestation records its completeness");
    assert_eq!(completeness.analyzed_files, 6);
    assert_eq!(completeness.skipped_files, 0);
    assert!(completeness.skipped_details.is_empty());
    assert!(
        !fixture.baselines().path().join("cargo/inner").exists(),
        "a path dependency of a vendored package is not itself attested"
    );

    let build_hook = baseline
        .profile
        .findings
        .iter()
        .find(|finding| finding.location.file.as_ref() == "./helper.rs")
        .expect("the build script's module contributes a capability");
    assert_eq!(
        build_hook.execution_context,
        Some(ExecutionContext::BuildHook),
        "a source only the build script reaches runs at build time"
    );
    let runtime = baseline
        .profile
        .findings
        .iter()
        .find(|finding| finding.location.file.as_ref() == "./src/shared.rs")
        .expect("the source shared by runtime and build targets contributes a capability");
    assert_eq!(
        runtime.execution_context, None,
        "a source any runtime target reaches is not build-hook-only"
    );
}

/// Every source the union covers, in the order `--debug-package` lists them.
const SELECTED_SOURCES: &[&str] = &[
    "file: ./build.rs",
    "file: ./helper.rs",
    "file: ./src/lib.rs",
    "file: ./src/main.rs",
    "file: ./src/shared.rs",
    "file: ./src/tool.rs",
];

/// A vendored crate whose library, binary, and build script each reach their
/// own module, beside sources no primary target reaches.
fn write_primary_target_crate(root: &Path) {
    write(
        &root.join("Cargo.toml"),
        format!(
            "{}\n[dependencies]\ninner = {{ path = \"inner\" }}\n",
            manifest("primary", "0.3.0")
        ),
    );
    write(&root.join("src/lib.rs"), "mod shared;\npub fn api() {}\n");
    write(
        &root.join("src/shared.rs"),
        "use std::fs;\npub fn shared() { let _ = fs::metadata(\".\"); }\n",
    );
    write(
        &root.join("src/main.rs"),
        "mod shared;\nmod tool;\nfn main() { shared::shared(); }\n",
    );
    write(&root.join("src/tool.rs"), "pub fn tool() {}\n");
    write(
        &root.join("build.rs"),
        "#[path = \"src/shared.rs\"]\nmod shared;\nmod helper;\nfn main() { shared::shared(); }\n",
    );
    write(
        &root.join("helper.rs"),
        "use std::process::Command;\npub fn helper() { let _ = Command::new(\"ls\"); }\n",
    );
    // Reached by no primary target, and invalid: selecting either would abort.
    write(&root.join("src/unreached.rs"), "b'\n");
    write(&root.join("tests/it.rs"), "b'\n");
    write_library_crate(
        &root.join("inner"),
        &manifest("inner", "0.1.0"),
        "pub fn inner() {}\n",
    );
}

/// One broken vendored crate refuses every command and writes nothing.
pub(crate) fn selected_failure_is_fatal_and_atomic(row: &FailureRow) {
    let fixture = VendorFixture::new();
    let crate_dir = fixture.crate_dir("subject");
    write_library_crate(
        &crate_dir,
        &manifest("subject", "0.1.0"),
        "pub fn api() {}\n",
    );

    let init = fixture.supply_chain("init");
    assert!(
        init.success(),
        "{}: healthy init failed: {}",
        row.label,
        init.transcript()
    );
    let before = fixture.baselines().bytes();
    assert!(!before.is_empty(), "{}: init wrote no baseline", row.label);

    (row.break_crate)(&crate_dir, fixture.vendor_root());

    for command in ["init", "update", "verify"] {
        let run = fixture.supply_chain(command);
        assert_eq!(
            run.code(),
            Some(2),
            "{}: {command} must fail fatally: {}",
            row.label,
            run.transcript()
        );
        assert!(
            run.stderr.contains(row.evidence),
            "{}: {command} lost its evidence: {}",
            row.label,
            run.transcript()
        );
        assert!(
            run.stderr.contains("error: subject: target "),
            "{}: {command} must name the failing package and target as its own \
             identity, not merely somewhere in a path: {}",
            row.label,
            run.transcript()
        );
        assert_eq!(
            fixture.baselines().bytes(),
            before,
            "{}: {command} mutated the baseline store",
            row.label
        );
    }
}
