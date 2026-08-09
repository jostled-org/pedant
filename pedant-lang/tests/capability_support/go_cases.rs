//! What the Go scanner reports, at the regex tier.

use pedant_types::Capability;

use crate::language_probe::go_caps;

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
