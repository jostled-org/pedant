//! Package manifest and hook-entrypoint analysis.
//!
//! Detects capabilities in files that execute during install or build:
//! - `package.json`: preinstall/install/postinstall hooks
//! - `setup.py`: cmdclass and custom build commands
//! - `pyproject.toml`: custom build backends and backend-path entries
//! - `*.go`: `//go:generate` directives
//! - `Makefile` / `justfile`: build-time commands

use std::path::Path;
use std::sync::Arc;

use pedant_types::{
    Capability, CapabilityFinding, CapabilityProfile, ExecutionContext, FindingOrigin,
    SourceLocation,
};

use crate::bash::{
    NETWORK_COMMAND_PATTERNS, PROCESS_EXEC_COMMAND_PATTERNS, detect_commands_with_patterns,
};

/// Hook script names in `package.json` that execute during install.
const NPM_INSTALL_HOOKS: &[&str] = &["preinstall", "install", "postinstall"];

const HOOK_SHELL_COMMAND_PATTERNS: &[(&str, Capability)] = &[
    ("bash", Capability::ProcessExec),
    ("sh", Capability::ProcessExec),
    ("python", Capability::ProcessExec),
    ("node", Capability::ProcessExec),
];

/// Analyze a manifest or hook-entrypoint file for capability findings.
///
/// Dispatches based on filename. Returns an empty profile for unrecognized files.
pub(crate) fn analyze(path: &Path, source: &str) -> CapabilityProfile {
    let file: Arc<str> = path.to_string_lossy().into();
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    let findings = match filename {
        "package.json" => analyze_package_json(&file, source),
        "setup.py" => analyze_setup_py(&file, source),
        "pyproject.toml" => analyze_pyproject_toml(&file, source),
        "Makefile" | "makefile" | "GNUmakefile" => {
            analyze_hook_entrypoint(&file, source, ExecutionContext::BuildHook)
        }
        "justfile" | "Justfile" => {
            analyze_hook_entrypoint(&file, source, ExecutionContext::BuildHook)
        }
        _ if path.extension().and_then(|e| e.to_str()) == Some("go") => {
            analyze_go_generate(&file, source)
        }
        _ => Box::new([]),
    };

    CapabilityProfile { findings }
}

/// Detect npm install hooks in package.json.
///
/// Looks for `"preinstall"`, `"install"`, or `"postinstall"` keys within a
/// `"scripts"` object. Uses lightweight text scanning — no JSON parser needed
/// for this level of detection.
fn analyze_package_json(file: &Arc<str>, source: &str) -> Box<[CapabilityFinding]> {
    let mut findings = Vec::new();

    // Find the scripts block by locating `"scripts"` key.
    let scripts_pos = match source.find("\"scripts\"") {
        Some(p) => p,
        None => return Box::new([]),
    };

    // Pre-compute quoted hook names to avoid per-line allocations.
    let quoted_hooks: Box<[Box<str>]> = NPM_INSTALL_HOOKS
        .iter()
        .map(|h| format!("\"{h}\"").into_boxed_str())
        .collect();

    let base_line = line_number_at(source, scripts_pos);
    let search_region = &source[scripts_pos..];

    for (line_offset, line) in search_region.lines().enumerate() {
        for (idx, quoted_hook) in quoted_hooks.iter().enumerate() {
            if line.contains(quoted_hook.as_ref()) {
                findings.push(CapabilityFinding {
                    capability: Capability::ProcessExec,
                    location: SourceLocation {
                        file: Arc::clone(file),
                        line: base_line + line_offset,
                        column: 1,
                    },
                    evidence: Arc::from(NPM_INSTALL_HOOKS[idx]),
                    origin: Some(FindingOrigin::ManifestHook),
                    language: None,
                    execution_context: Some(ExecutionContext::InstallHook),
                    reachable: None,
                });
            }
        }
    }

    findings.into_boxed_slice()
}

/// Detect build hooks in `setup.py` (cmdclass, custom commands).
fn analyze_setup_py(file: &Arc<str>, source: &str) -> Box<[CapabilityFinding]> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        if line.contains("cmdclass") {
            findings.push(CapabilityFinding {
                capability: Capability::ProcessExec,
                location: SourceLocation {
                    file: Arc::clone(file),
                    line: line_num + 1,
                    column: 1,
                },
                evidence: Arc::from("cmdclass"),
                origin: Some(FindingOrigin::ManifestHook),
                language: Some(pedant_types::Language::Python),
                execution_context: Some(ExecutionContext::BuildHook),
                reachable: None,
            });
        }
    }

    findings.into_boxed_slice()
}

/// Detect custom build backends in `pyproject.toml`.
///
/// Flags `build-backend` when paired with `backend-path` (indicating a local
/// custom backend, not a standard one like setuptools or flit).
fn analyze_pyproject_toml(file: &Arc<str>, source: &str) -> Box<[CapabilityFinding]> {
    let has_backend_path = source.lines().any(|l| l.trim().starts_with("backend-path"));
    if !has_backend_path {
        return Box::new([]);
    }

    let mut findings = Vec::new();
    for (line_num, line) in source.lines().enumerate() {
        if line.trim().starts_with("build-backend") {
            findings.push(CapabilityFinding {
                capability: Capability::ProcessExec,
                location: SourceLocation {
                    file: Arc::clone(file),
                    line: line_num + 1,
                    column: 1,
                },
                evidence: Arc::from("custom build-backend with backend-path"),
                origin: Some(FindingOrigin::ManifestHook),
                language: Some(pedant_types::Language::Python),
                execution_context: Some(ExecutionContext::BuildHook),
                reachable: None,
            });
        }
    }

    findings.into_boxed_slice()
}

/// Detect `//go:generate` directives in Go source files.
fn analyze_go_generate(file: &Arc<str>, source: &str) -> Box<[CapabilityFinding]> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//go:generate ") {
            findings.push(CapabilityFinding {
                capability: Capability::ProcessExec,
                location: SourceLocation {
                    file: Arc::clone(file),
                    line: line_num + 1,
                    column: 1,
                },
                evidence: Arc::from(trimmed),
                origin: Some(FindingOrigin::ManifestHook),
                language: Some(pedant_types::Language::Go),
                execution_context: Some(ExecutionContext::Generator),
                reachable: None,
            });
        }
    }

    findings.into_boxed_slice()
}

/// Analyze a Makefile or justfile as a hook entrypoint.
///
/// Scans recipe lines (indented with tab or spaces) for known command patterns.
fn analyze_hook_entrypoint(
    file: &Arc<str>,
    source: &str,
    context: ExecutionContext,
) -> Box<[CapabilityFinding]> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        // Recipe lines in Makefiles start with tab; justfiles use spaces.
        let is_recipe_line =
            line.starts_with('\t') || (line.starts_with("    ") && !line.trim().ends_with(':'));

        if !is_recipe_line {
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let findings_before = findings.len();
        detect_commands_with_patterns(
            file,
            trimmed,
            line_num,
            NETWORK_COMMAND_PATTERNS,
            Some(context),
            &mut findings,
        );
        detect_commands_with_patterns(
            file,
            trimmed,
            line_num,
            PROCESS_EXEC_COMMAND_PATTERNS,
            Some(context),
            &mut findings,
        );
        detect_manifest_process_exec_commands(file, trimmed, line_num, context, &mut findings);

        for finding in &mut findings[findings_before..] {
            finding.origin = Some(FindingOrigin::ManifestHook);
        }
    }

    findings.into_boxed_slice()
}

fn detect_manifest_process_exec_commands(
    file: &Arc<str>,
    line: &str,
    line_num: usize,
    context: ExecutionContext,
    findings: &mut Vec<CapabilityFinding>,
) {
    detect_commands_with_patterns(
        file,
        line,
        line_num,
        HOOK_SHELL_COMMAND_PATTERNS,
        Some(context),
        findings,
    );
}

/// Compute 1-based line number for a byte offset in source.
fn line_number_at(source: &str, byte_offset: usize) -> usize {
    source[..byte_offset].matches('\n').count() + 1
}
