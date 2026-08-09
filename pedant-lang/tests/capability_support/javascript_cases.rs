//! What the JavaScript and TypeScript scanners report, at the regex tier.

use pedant_types::{Capability, Language};

use crate::language_probe::{caps_for, js_caps};

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
