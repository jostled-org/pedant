//! What the Python scanner reports, at the regex tier.

use std::path::Path;

use pedant_lang::analyze_file;
use pedant_types::{Capability, Language};

use crate::language_probe::{has_py_cap, py_caps};

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
    assert!(
        !profile.findings.is_empty(),
        "the import must report at least one finding for the loop below to judge"
    );
    for finding in profile.findings.iter() {
        assert_eq!(
            finding.language,
            Some(Language::Python),
            "all Python findings should have language set"
        );
    }
}
