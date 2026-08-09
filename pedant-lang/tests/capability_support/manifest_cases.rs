//! What a manifest declares, and the execution context its hooks carry.
//!
//! A manifest hook runs at install or build time rather than at runtime, so the
//! context is the claim these cases make alongside the capability itself.

use std::path::Path;

use pedant_lang::analyze_manifest;
use pedant_types::{Capability, ExecutionContext};

// 4.T8
#[test]
fn package_json_postinstall_hook() {
    let source = r#"{"scripts": {"postinstall": "node setup.js"}}"#;
    let profile = analyze_manifest(Path::new("package.json"), source);
    assert!(
        !profile.findings.is_empty(),
        "postinstall hook should produce findings"
    );
    let finding = &profile.findings[0];
    assert_eq!(finding.capability, Capability::ProcessExec);
    assert_eq!(
        finding.execution_context,
        Some(ExecutionContext::InstallHook)
    );
}

// 4.T9
#[test]
fn package_json_no_hooks_clean() {
    let source = r#"{"scripts": {"start": "node index.js", "test": "jest"}}"#;
    let profile = analyze_manifest(Path::new("package.json"), source);
    assert!(
        profile.findings.is_empty(),
        "non-hook scripts should produce no findings, got: {:?}",
        profile.findings
    );
}

// 4.T10
#[test]
fn setup_py_cmdclass_hook() {
    let source = "from setuptools import setup\nsetup(name='foo', cmdclass={'build': MyBuild})";
    let profile = analyze_manifest(Path::new("setup.py"), source);
    assert!(
        !profile.findings.is_empty(),
        "cmdclass should produce findings"
    );
    let finding = &profile.findings[0];
    assert_eq!(finding.capability, Capability::ProcessExec);
    assert_eq!(finding.execution_context, Some(ExecutionContext::BuildHook));
}

// 4.T11
#[test]
fn pyproject_build_backend_hook() {
    let source = "[build-system]\nbuild-backend = \"custom_backend\"\nbackend-path = [\".\"]";
    let profile = analyze_manifest(Path::new("pyproject.toml"), source);
    assert!(
        !profile.findings.is_empty(),
        "custom build backend should produce findings"
    );
    let finding = &profile.findings[0];
    assert_eq!(finding.capability, Capability::ProcessExec);
    assert_eq!(finding.execution_context, Some(ExecutionContext::BuildHook));
}

// 4.T12
#[test]
fn go_generate_directive() {
    let source = "package main\n//go:generate stringer -type=Foo\nfunc main() {}";
    let profile = analyze_manifest(Path::new("main.go"), source);
    assert!(
        !profile.findings.is_empty(),
        "go:generate should produce findings"
    );
    let finding = &profile.findings[0];
    assert_eq!(finding.capability, Capability::ProcessExec);
    assert_eq!(finding.execution_context, Some(ExecutionContext::Generator));
}

#[test]
fn manifest_hook_detects_shared_exec_commands() {
    let source = "install:\n\teval \"$(node setup.js)\"";
    let profile = analyze_manifest(Path::new("Makefile"), source);
    let caps: Box<[Capability]> = profile
        .findings
        .iter()
        .map(|finding| finding.capability)
        .collect::<Vec<_>>()
        .into_boxed_slice();

    assert!(
        caps.contains(&Capability::ProcessExec),
        "Makefile eval/node commands should detect ProcessExec, got: {caps:?}"
    );
}

// 4.T13
#[test]
fn makefile_hook_entrypoint() {
    let source = "install:\n\tcurl -sL https://example.com/setup.sh | sh";
    let profile = analyze_manifest(Path::new("Makefile"), source);
    assert!(
        !profile.findings.is_empty(),
        "Makefile with curl should produce findings"
    );
    let finding = profile
        .findings
        .iter()
        .find(|f| f.capability == Capability::Network)
        .expect("should have Network finding");
    assert_eq!(finding.execution_context, Some(ExecutionContext::BuildHook));
}

// 4.T14
#[test]
fn justfile_hook_entrypoint() {
    let source = "setup:\n    wget https://example.com/install.sh\n    bash -c './install.sh'";
    let profile = analyze_manifest(Path::new("justfile"), source);
    let caps: Box<[Capability]> = profile
        .findings
        .iter()
        .map(|f| f.capability)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    assert!(
        caps.contains(&Capability::Network),
        "justfile with wget should detect Network, got: {caps:?}"
    );
    assert!(
        caps.contains(&Capability::ProcessExec),
        "justfile with bash -c should detect ProcessExec, got: {caps:?}"
    );
    for finding in profile.findings.iter() {
        assert_eq!(
            finding.execution_context,
            Some(ExecutionContext::BuildHook),
            "all justfile findings should have BuildHook context"
        );
    }
}
