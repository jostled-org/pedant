use std::path::Path;

use pedant_lang::{FileClassification, classify_path, detect_language};
use pedant_types::Language;

#[test]
fn classify_path_distinguishes_rust_source_manifest_and_unknown() {
    assert_eq!(
        classify_path(Path::new("src/lib.rs")),
        FileClassification::Rust
    );
    assert_eq!(
        classify_path(Path::new("script.py")),
        FileClassification::Source(Language::Python)
    );
    assert_eq!(
        classify_path(Path::new("package.json")),
        FileClassification::Manifest
    );
    assert_eq!(
        classify_path(Path::new("main.go")),
        FileClassification::SourceAndManifest(Language::Go)
    );
    assert_eq!(
        classify_path(Path::new("notes.txt")),
        FileClassification::Unsupported
    );
}

#[test]
fn detect_language_python_extension() {
    let result = detect_language(Path::new("script.py"), "");
    assert_eq!(result, Some(Language::Python));
}

#[test]
fn detect_language_python_uppercase() {
    let result = detect_language(Path::new("Script.PY"), "");
    assert_eq!(result, None, "detection is case-sensitive on extensions");
}

#[test]
fn detect_language_no_extension_no_shebang() {
    let result = detect_language(Path::new("script"), "x = 1");
    assert_eq!(result, None);
}

// 3.T1
#[test]
fn detect_language_js_ts_go() {
    assert_eq!(
        detect_language(Path::new("app.js"), ""),
        Some(Language::JavaScript)
    );
    assert_eq!(
        detect_language(Path::new("component.ts"), ""),
        Some(Language::TypeScript)
    );
    assert_eq!(
        detect_language(Path::new("component.tsx"), ""),
        Some(Language::TypeScript)
    );
    assert_eq!(
        detect_language(Path::new("module.mjs"), ""),
        Some(Language::JavaScript)
    );
    assert_eq!(
        detect_language(Path::new("main.go"), ""),
        Some(Language::Go)
    );
}

// 4.T1
#[test]
fn detect_language_bash_extension() {
    assert_eq!(
        detect_language(Path::new("install.sh"), ""),
        Some(Language::Bash)
    );
    assert_eq!(
        detect_language(Path::new("setup.bash"), ""),
        Some(Language::Bash)
    );
    assert_eq!(
        detect_language(Path::new("init.zsh"), ""),
        Some(Language::Bash)
    );
}

// 4.T2
#[test]
fn detect_language_bash_shebang() {
    let bash_shebang = detect_language(Path::new("script"), "#!/bin/bash\necho hello");
    assert_eq!(bash_shebang, Some(Language::Bash));

    let env_bash_shebang = detect_language(Path::new("script"), "#!/usr/bin/env bash\necho hello");
    assert_eq!(env_bash_shebang, Some(Language::Bash));

    let sh_shebang = detect_language(Path::new("script"), "#!/bin/sh\necho hello");
    assert_eq!(sh_shebang, Some(Language::Bash));
}
