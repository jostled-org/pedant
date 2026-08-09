//! What the Bash scanner reports, at the regex tier.

use pedant_types::Capability;

use crate::language_probe::bash_caps;

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
