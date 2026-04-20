//! Bash capability detection via source-text scanning.
//!
//! Scoped to install/build scripts and explicitly analyzed shell entrypoints.
//! `cat` and `$()` are excluded per spec — too noisy for broad shell scanning.
//!
//! When the `ts-bash` feature is enabled, command detection uses tree-sitter
//! for structured AST extraction. This identifies command nodes directly rather
//! than relying on word-boundary heuristics. Falls back to regex when disabled.

use std::sync::Arc;

use pedant_types::{Capability, CapabilityFinding, FindingOrigin, Language, SourceLocation};

use crate::string_analysis::is_shell_command_boundary;

/// Command patterns: the command name at a word boundary mapped to capability.
pub(crate) const NETWORK_COMMAND_PATTERNS: &[(&str, Capability)] = &[
    // Network
    ("curl", Capability::Network),
    ("wget", Capability::Network),
    ("nc", Capability::Network),
    ("ncat", Capability::Network),
    ("ssh", Capability::Network),
    ("scp", Capability::Network),
    ("rsync", Capability::Network),
];

pub(crate) const PROCESS_EXEC_COMMAND_PATTERNS: &[(&str, Capability)] = &[
    // Process execution
    ("exec", Capability::ProcessExec),
    ("eval", Capability::ProcessExec),
    ("bash -c", Capability::ProcessExec),
    ("sh -c", Capability::ProcessExec),
];

const COMMAND_PATTERNS: &[(&str, Capability)] = &[
    ("curl", Capability::Network),
    ("wget", Capability::Network),
    ("nc", Capability::Network),
    ("ncat", Capability::Network),
    ("ssh", Capability::Network),
    ("scp", Capability::Network),
    ("rsync", Capability::Network),
    ("cp", Capability::FileWrite),
    ("mv", Capability::FileWrite),
    ("rm", Capability::FileWrite),
    ("mkdir", Capability::FileWrite),
    ("touch", Capability::FileWrite),
    ("tee", Capability::FileWrite),
    ("dd", Capability::FileWrite),
    ("exec", Capability::ProcessExec),
    ("eval", Capability::ProcessExec),
    ("bash -c", Capability::ProcessExec),
    ("sh -c", Capability::ProcessExec),
    ("env", Capability::EnvAccess),
    ("printenv", Capability::EnvAccess),
    ("export", Capability::EnvAccess),
    ("openssl", Capability::Crypto),
    ("gpg", Capability::Crypto),
    ("ssh-keygen", Capability::Crypto),
];

/// Analyze Bash source for capability findings.
pub(crate) fn analyze(path: &Arc<str>, source: &str) -> Box<[CapabilityFinding]> {
    let mut findings = Vec::new();

    #[cfg(feature = "ts-bash")]
    ts_analyze(path, source, &mut findings);

    #[cfg(not(feature = "ts-bash"))]
    analyze_regex(path, source, &mut findings);

    findings.into_boxed_slice()
}

fn analyze_regex(path: &Arc<str>, source: &str, findings: &mut Vec<CapabilityFinding>) {
    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments and empty lines.
        match trimmed.as_bytes().first() {
            None | Some(b'#') => continue,
            _ => {}
        }

        detect_commands(path, trimmed, line_num, findings);
    }
}

/// Check whether a command pattern appears at a word boundary in the line.
///
/// A command is at a word boundary when it is preceded by nothing, whitespace,
/// a pipe `|`, a semicolon `;`, backtick, `$(`, or `&&`/`||`.
/// Bash commands also allow `=` after the match (for `export NAME=...`).
fn detect_commands(
    path: &Arc<str>,
    line: &str,
    line_num: usize,
    findings: &mut Vec<CapabilityFinding>,
) {
    detect_commands_with_patterns(path, line, line_num, COMMAND_PATTERNS, None, findings);
}

pub(crate) fn detect_commands_with_patterns(
    path: &Arc<str>,
    line: &str,
    line_num: usize,
    patterns: &[(&str, Capability)],
    context: Option<pedant_types::ExecutionContext>,
    findings: &mut Vec<CapabilityFinding>,
) {
    for &(pattern, capability) in patterns {
        let mut search_from = 0;
        while let Some(pos) = line[search_from..].find(pattern) {
            let abs_pos = search_from + pos;

            if is_shell_command_boundary(line, abs_pos, pattern, b"=") {
                findings.push(CapabilityFinding {
                    capability,
                    location: SourceLocation {
                        file: Arc::clone(path),
                        line: line_num + 1,
                        column: abs_pos + 1,
                    },
                    evidence: Arc::from(pattern),
                    origin: Some(FindingOrigin::CodeSite),
                    language: Some(Language::Bash),
                    execution_context: context,
                    reachable: None,
                });
                break;
            }

            search_from = abs_pos + pattern.len();
        }
    }
}

// ── Tree-sitter structured extraction ──────────────────────────────────

/// Single-word commands mapped to capabilities for tree-sitter lookup.
///
/// Multi-word patterns (`bash -c`, `sh -c`) are handled structurally by
/// inspecting command arguments rather than text matching.
#[cfg(feature = "ts-bash")]
const TS_COMMAND_TABLE: &[(&str, Capability)] = &[
    ("curl", Capability::Network),
    ("wget", Capability::Network),
    ("nc", Capability::Network),
    ("ncat", Capability::Network),
    ("ssh", Capability::Network),
    ("scp", Capability::Network),
    ("rsync", Capability::Network),
    ("cp", Capability::FileWrite),
    ("mv", Capability::FileWrite),
    ("rm", Capability::FileWrite),
    ("mkdir", Capability::FileWrite),
    ("touch", Capability::FileWrite),
    ("tee", Capability::FileWrite),
    ("dd", Capability::FileWrite),
    ("exec", Capability::ProcessExec),
    ("eval", Capability::ProcessExec),
    ("env", Capability::EnvAccess),
    ("printenv", Capability::EnvAccess),
    ("openssl", Capability::Crypto),
    ("gpg", Capability::Crypto),
    ("ssh-keygen", Capability::Crypto),
];

/// Tree-sitter Bash analysis: parses source into an AST and walks
/// `command_name` nodes for structured command detection. Falls back to
/// regex only when parsing fails.
#[cfg(feature = "ts-bash")]
fn ts_analyze(path: &Arc<str>, source: &str, findings: &mut Vec<CapabilityFinding>) {
    use crate::tree_sitter_ext::parse;

    let bytes = source.as_bytes();
    let tree = match parse(bytes, tree_sitter_bash::LANGUAGE.into()) {
        Some(t) => t,
        None => {
            analyze_regex(path, source, findings);
            return;
        }
    };

    ts_extract_commands(tree.root_node(), bytes, path, findings);
}

/// Walk the AST extracting command capabilities.
///
/// Handles three patterns:
/// 1. Simple commands: `curl`, `wget`, `openssl`, etc.
/// 2. Shell-exec patterns: `bash -c` / `sh -c`
/// 3. Export declarations: `export NAME=...`
#[cfg(feature = "ts-bash")]
fn ts_extract_commands(
    root: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    findings: &mut Vec<CapabilityFinding>,
) {
    use crate::tree_sitter_ext::walk_descendants;

    walk_descendants(root, |node| match node.kind() {
        "command" => ts_handle_command(node, source, path, findings),
        "declaration_command" => ts_handle_declaration(node, source, path, findings),
        _ => {}
    });
}

/// Handle a `command` node: extract the command name and match capabilities.
#[cfg(feature = "ts-bash")]
fn ts_handle_command(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    findings: &mut Vec<CapabilityFinding>,
) {
    use crate::tree_sitter_ext::node_text;

    let name_node = match node.child_by_field_name("name") {
        Some(n) => n,
        None => return,
    };
    let cmd = node_text(name_node, source);

    // Check for `bash -c` / `sh -c` pattern.
    match (cmd, has_dash_c_arg(node, source)) {
        ("bash" | "sh", true) => {
            emit_ts_finding(path, node, "bash -c", Capability::ProcessExec, findings);
            return;
        }
        ("bash" | "sh", false) => return,
        _ => {}
    }

    // Lookup single-word command in capability table.
    for &(pattern, capability) in TS_COMMAND_TABLE {
        if cmd == pattern {
            emit_ts_finding(path, node, pattern, capability, findings);
            return;
        }
    }
}

/// Check whether a command node has a `-c` argument among its children.
#[cfg(feature = "ts-bash")]
fn has_dash_c_arg(command: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    use crate::tree_sitter_ext::node_text;

    let mut cursor = command.walk();
    for child in command.children(&mut cursor) {
        match child.kind() {
            "word" | "string" | "raw_string" if node_text(child, source) == "-c" => return true,
            _ => {}
        }
    }
    false
}

/// Handle a `declaration_command` node (e.g., `export NAME=value`).
#[cfg(feature = "ts-bash")]
fn ts_handle_declaration(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    findings: &mut Vec<CapabilityFinding>,
) {
    use crate::tree_sitter_ext::node_text;

    // The first child of a declaration_command is the keyword (export, declare, local, etc.)
    let keyword = match node.child(0) {
        Some(k) => node_text(k, source),
        None => return,
    };
    if keyword == "export" {
        emit_ts_finding(path, node, "export", Capability::EnvAccess, findings);
    }
}

/// Emit a capability finding from a tree-sitter node position.
#[cfg(feature = "ts-bash")]
fn emit_ts_finding(
    path: &Arc<str>,
    node: tree_sitter::Node<'_>,
    evidence: &str,
    capability: Capability,
    findings: &mut Vec<CapabilityFinding>,
) {
    let pos = node.start_position();
    findings.push(CapabilityFinding {
        capability,
        location: SourceLocation {
            file: Arc::clone(path),
            line: pos.row + 1,
            column: pos.column + 1,
        },
        evidence: Arc::from(evidence),
        origin: Some(FindingOrigin::CodeSite),
        language: Some(Language::Bash),
        execution_context: None,
        reachable: None,
    });
}
