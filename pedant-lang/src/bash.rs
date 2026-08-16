//! Bash capability detection via source-text scanning.
//!
//! Scoped to install/build scripts and explicitly analyzed shell entrypoints.
//! `cat` and `$()` are excluded per spec — too noisy for broad shell scanning.
//!
//! When the `ts-bash` feature is enabled, command detection uses tree-sitter
//! for structured AST extraction. This identifies command nodes directly rather
//! than relying on word-boundary heuristics. Falls back to regex when disabled.

use std::sync::Arc;

// Grammar selection, traversal, and the node type the AST signatures below name
// all come from `pedant-syntax`, which owns the grammar and the parser version.
// Naming the node type through a second `tree-sitter` dependency here would pin
// the same crate twice. One gated import serves the whole module: every helper
// below sits under the same feature, so repeating the `use` inside each one
// restates that gate without narrowing anything.
#[cfg(feature = "ts-bash")]
use pedant_syntax::{
    SyntaxLanguage,
    tree_sitter::{self, ParsedSyntax, node_text, parse_bound, walk_descendants},
};
use pedant_types::{
    Capability, CapabilityAnalysis, CapabilityFinding, FindingOrigin, Language, SourceLocation,
};

use crate::attribution;
use crate::string_analysis::{
    CommentStyle, detect_string_literal_findings, is_shell_command_boundary, scan_string_literals,
};

/// Network commands: the command name at a word boundary mapped to capability.
///
/// Also read by `manifest.rs`, which scans recipe bodies with this group alone.
pub(crate) const NETWORK_COMMAND_PATTERNS: &[(&str, Capability)] = &[
    ("curl", Capability::Network),
    ("wget", Capability::Network),
    ("nc", Capability::Network),
    ("ncat", Capability::Network),
    ("ssh", Capability::Network),
    ("scp", Capability::Network),
    ("rsync", Capability::Network),
];

const FILE_WRITE_COMMAND_PATTERNS: &[(&str, Capability)] = &[
    ("cp", Capability::FileWrite),
    ("mv", Capability::FileWrite),
    ("rm", Capability::FileWrite),
    ("mkdir", Capability::FileWrite),
    ("touch", Capability::FileWrite),
    ("tee", Capability::FileWrite),
    ("dd", Capability::FileWrite),
];

/// Process-execution commands, also read by `manifest.rs`.
pub(crate) const PROCESS_EXEC_COMMAND_PATTERNS: &[(&str, Capability)] = &[
    ("exec", Capability::ProcessExec),
    ("eval", Capability::ProcessExec),
    ("bash -c", Capability::ProcessExec),
    ("sh -c", Capability::ProcessExec),
];

const ENV_COMMAND_PATTERNS: &[(&str, Capability)] = &[
    ("env", Capability::EnvAccess),
    ("printenv", Capability::EnvAccess),
    ("export", Capability::EnvAccess),
];

const CRYPTO_COMMAND_PATTERNS: &[(&str, Capability)] = &[
    ("openssl", Capability::Crypto),
    ("gpg", Capability::Crypto),
    ("ssh-keygen", Capability::Crypto),
];

/// The whole Bash command vocabulary, one group per capability.
///
/// Two of the groups are `pub(crate)` because `manifest.rs` scans with them
/// alone. Restating their rows in a flat table made a new network command a
/// three-place edit with nothing checking that all three landed, so the groups
/// are the single source and the flat table below is derived from them.
const COMMAND_PATTERN_GROUPS: &[&[(&str, Capability)]] = &[
    NETWORK_COMMAND_PATTERNS,
    FILE_WRITE_COMMAND_PATTERNS,
    PROCESS_EXEC_COMMAND_PATTERNS,
    ENV_COMMAND_PATTERNS,
    CRYPTO_COMMAND_PATTERNS,
];

const COMMAND_PATTERN_COUNT: usize = NETWORK_COMMAND_PATTERNS.len()
    + FILE_WRITE_COMMAND_PATTERNS.len()
    + PROCESS_EXEC_COMMAND_PATTERNS.len()
    + ENV_COMMAND_PATTERNS.len()
    + CRYPTO_COMMAND_PATTERNS.len();

/// Flatten the groups into one table at compile time, in group order.
const fn flatten_command_groups() -> [(&'static str, Capability); COMMAND_PATTERN_COUNT] {
    let mut table = [("", Capability::Network); COMMAND_PATTERN_COUNT];
    let mut written = 0;
    let mut group = 0;
    while group < COMMAND_PATTERN_GROUPS.len() {
        let rows = COMMAND_PATTERN_GROUPS[group];
        let mut row = 0;
        while row < rows.len() {
            table[written] = rows[row];
            written += 1;
            row += 1;
        }
        group += 1;
    }
    table
}

/// Every command pattern, flattened. Both scanners read this one table.
///
/// A `static` rather than a `const`: both readers take it by reference, and a
/// by-value `const` would leave that to rvalue static promotion instead of
/// naming the one allocation outright.
static COMMAND_PATTERNS: [(&str, Capability); COMMAND_PATTERN_COUNT] = flatten_command_groups();

/// Analyze Bash source for capabilities, and attribute them to callables.
///
/// The structured tier binds one parse session, uses it for detection, and
/// hands it to attribution. A build without the grammar, and a parser that
/// produced no tree, take the text tier and report attribution as unavailable.
pub(crate) fn analyze(path: &Arc<str>, source: &str) -> CapabilityAnalysis {
    let mut findings = Vec::new();

    #[cfg(feature = "ts-bash")]
    let bound = ts_analyze(path, source, &mut findings);

    // No grammar in this build, so no session can exist and the text tier is
    // the only path.
    #[cfg(not(feature = "ts-bash"))]
    let bound: Option<()> = None;

    if bound.is_none() {
        analyze_regex(path, source, &mut findings);
    }

    // Python, JavaScript, and Go all end here, and Bash literals hold the same
    // evidence: a hard-coded endpoint, a PEM block, an `AKIA…` credential. The
    // scanner skips `#` comments, which shell shares — but only at a word
    // start, so `$#` and `${var##*/}` keep the rest of their line as code.
    let literals = scan_string_literals(source, CommentStyle::ShellWord);
    detect_string_literal_findings(path, &literals, Language::Bash, &mut findings);

    #[cfg(feature = "ts-bash")]
    let analysis = attribution::seal(bound, Language::Bash, findings.into_boxed_slice());
    #[cfg(not(feature = "ts-bash"))]
    let analysis = attribution::unavailable(findings.into_boxed_slice());
    analysis
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
    detect_commands_with_patterns(path, line, line_num, &COMMAND_PATTERNS, None, findings);
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
        let boundary = line
            .match_indices(pattern)
            .find(|&(abs_pos, _)| is_shell_command_boundary(line, abs_pos, pattern, b"="))
            .map(|(abs_pos, _)| abs_pos);
        if let Some(abs_pos) = boundary {
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
        }
    }
}

// ── Tree-sitter structured extraction ──────────────────────────────────

/// Tree-sitter Bash analysis: binds one parse session and walks `command_name`
/// nodes for structured command detection.
///
/// `None` means no tree: the caller owes the file its text-tier scan. The
/// session travels back rather than dying here, because attribution asks it the
/// same questions detection just did.
#[cfg(feature = "ts-bash")]
fn ts_analyze<'source>(
    path: &Arc<str>,
    source: &'source str,
    findings: &mut Vec<CapabilityFinding>,
) -> Option<ParsedSyntax<'source>> {
    let parsed = parse_bound(source, SyntaxLanguage::Bash)?;
    ts_extract_commands(parsed.root(), source.as_bytes(), path, findings);
    Some(parsed)
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

    // Look the command name up in the shared table. A `command` node's name is
    // one word, so the equality alone excludes every multi-word row — `bash -c`
    // and `sh -c` match structurally above — and that is what lets one table
    // serve both scanners instead of a second copy drifting from the first.
    // `("export", EnvAccess)` is reachable here for the same reason it is in the
    // table at all, but `export` parses as `declaration_command` rather than
    // `command`, so `ts_handle_declaration` stays its only emitter.
    let matched = COMMAND_PATTERNS.iter().find(|(pattern, _)| cmd == *pattern);
    if let Some(&(pattern, capability)) = matched {
        emit_ts_finding(path, node, pattern, capability, findings);
    }
}

/// Check whether a command node has a `-c` argument among its children.
#[cfg(feature = "ts-bash")]
fn has_dash_c_arg(command: tree_sitter::Node<'_>, source: &[u8]) -> bool {
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
