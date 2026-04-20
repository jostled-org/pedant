//! JavaScript/TypeScript capability detection via source-text scanning.
//!
//! When the `ts-javascript` or `ts-typescript` feature is enabled, import
//! detection uses tree-sitter for structured AST extraction. This handles
//! template-literal `require()` calls accurately. Falls back to regex when
//! disabled.

use std::sync::Arc;

use pedant_types::{Capability, CapabilityFinding, FindingOrigin, Language, SourceLocation};

use crate::string_analysis::{
    detect_call_sites, detect_string_literal_findings, matches_module_prefix,
    scan_js_string_literals,
};

/// Import-level pattern: module name prefix mapped to capability.
const IMPORT_PATTERNS: &[(&str, Capability)] = &[
    // Network
    ("http", Capability::Network),
    ("https", Capability::Network),
    ("axios", Capability::Network),
    ("node-fetch", Capability::Network),
    ("got", Capability::Network),
    // Filesystem
    ("fs", Capability::FileRead),
    // Process execution
    ("child_process", Capability::ProcessExec),
    ("execa", Capability::ProcessExec),
    ("shelljs", Capability::ProcessExec),
    // Env access
    ("dotenv", Capability::EnvAccess),
    // Crypto
    ("crypto", Capability::Crypto),
    ("bcrypt", Capability::Crypto),
    ("jose", Capability::Crypto),
    // FFI
    ("ffi-napi", Capability::Ffi),
    ("node-ffi", Capability::Ffi),
];

/// Call-site pattern: text fragment that indicates a capability.
const CALL_SITE_PATTERNS: &[(&str, Capability, &str)] = &[
    ("fetch(", Capability::Network, "fetch"),
    ("process.env", Capability::EnvAccess, "process.env"),
];

/// Analyze JavaScript or TypeScript source for capability findings.
pub(crate) fn analyze(
    path: &Arc<str>,
    source: &str,
    language: Language,
) -> Box<[CapabilityFinding]> {
    let mut findings = Vec::new();

    #[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
    ts_analyze(path, source, language, &mut findings);

    #[cfg(not(any(feature = "ts-javascript", feature = "ts-typescript")))]
    {
        detect_imports(path, source, language, &mut findings);
        detect_call_sites(path, source, CALL_SITE_PATTERNS, language, &mut findings);
    }

    let literals = scan_js_string_literals(source);
    detect_string_literal_findings(path, &literals, language, &mut findings);

    findings.into_boxed_slice()
}

/// Extract the module name from a `require('module')` or `require("module")` call.
fn extract_require_module(line: &str) -> Option<&str> {
    let pos = line.find("require(")?;
    let after = &line[pos + 8..];
    extract_quoted(after)
}

/// Extract the module name from an ES import statement.
///
/// Handles `import ... from 'module'` and side-effect `import 'module'`.
fn extract_es_import_module(line: &str) -> Option<&str> {
    // `import ... from 'module'`
    if let Some(pos) = line.find(" from ") {
        let after = &line[pos + 6..];
        return extract_quoted(after.trim_start());
    }
    // Side-effect: `import 'module'`
    let after = line.strip_prefix("import ")?;
    extract_quoted(after.trim_start())
}

/// Pull the content of a single- or double-quoted string from the start of `s`.
fn extract_quoted(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let quote = match bytes.first()? {
        q @ (b'\'' | b'"') => *q,
        _ => return None,
    };
    let end = bytes[1..].iter().position(|&b| b == quote)?;
    Some(&s[1..1 + end])
}

fn detect_imports(
    path: &Arc<str>,
    source: &str,
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let module = extract_require_module(trimmed).or_else(|| {
            trimmed
                .starts_with("import")
                .then(|| extract_es_import_module(trimmed))
                .flatten()
        });

        let name = match module {
            Some(n) => n,
            None => continue,
        };

        for &(pattern, capability) in IMPORT_PATTERNS {
            if matches_module_prefix(name, pattern) {
                findings.push(CapabilityFinding {
                    capability,
                    location: SourceLocation {
                        file: Arc::clone(path),
                        line: line_num + 1,
                        column: 1,
                    },
                    evidence: Arc::from(pattern),
                    origin: Some(FindingOrigin::Import),
                    language: Some(language),
                    execution_context: None,
                    reachable: None,
                });
                break;
            }
        }
    }
}

// ── Tree-sitter structured extraction ──────────────────────────────────

#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn ts_analyze(
    path: &Arc<str>,
    source: &str,
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    use crate::tree_sitter_ext::parse;

    let bytes = source.as_bytes();
    let ts_lang = ts_language_for(language);
    let tree = match ts_lang.and_then(|lang| parse(bytes, lang)) {
        Some(t) => t,
        None => {
            // Fall back to regex on parse failure or unsupported language variant.
            detect_imports(path, source, language, findings);
            detect_call_sites(path, source, CALL_SITE_PATTERNS, language, findings);
            return;
        }
    };
    let root = tree.root_node();

    // Phase 1: detect imports via tree-sitter (handles ES imports structurally).
    ts_detect_imports(root, bytes, path, language, findings);

    // Phase 2: detect require() calls including template literal arguments.
    ts_detect_require_calls(root, bytes, path, language, findings);

    // Phase 3: regex call-site patterns (fetch(), process.env, etc.).
    detect_call_sites(path, source, CALL_SITE_PATTERNS, language, findings);
}

/// Get the tree-sitter Language for a pedant Language variant.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn ts_language_for(language: Language) -> Option<tree_sitter::Language> {
    match language {
        #[cfg(feature = "ts-javascript")]
        Language::JavaScript => Some(tree_sitter_javascript::LANGUAGE.into()),
        #[cfg(feature = "ts-typescript")]
        Language::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        _ => None,
    }
}

/// Extract ES import statements from tree-sitter AST.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn ts_detect_imports(
    root: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    use crate::tree_sitter_ext::{node_text, walk_descendants};

    walk_descendants(root, |node| {
        if node.kind() != "import_statement" {
            return;
        }
        let source_node = match node.child_by_field_name("source") {
            Some(n) => n,
            None => return,
        };
        let raw = node_text(source_node, source);
        // Strip quotes from string literal.
        let module_name = raw
            .strip_prefix(|c| c == '\'' || c == '"')
            .and_then(|s| s.strip_suffix(|c| c == '\'' || c == '"'))
            .unwrap_or(raw);

        emit_js_import_finding(module_name, node, path, language, findings);
    });
}

/// Detect `require()` calls with both string and template-literal arguments.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn ts_detect_require_calls(
    root: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    use crate::tree_sitter_ext::{node_text, walk_descendants};

    walk_descendants(root, |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let func = match node.child_by_field_name("function") {
            Some(f) => f,
            None => return,
        };
        if node_text(func, source) != "require" {
            return;
        }
        let args = match node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        // Extract module name from the first argument (string or template_string).
        if let Some(name) = extract_require_arg(args, source) {
            emit_js_import_finding(name, node, path, language, findings);
        }
    });
}

/// Strip surrounding quotes or backticks from a tree-sitter string/template node.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn strip_js_string_delimiters(raw: &str) -> Option<&str> {
    raw.strip_prefix(|c| c == '\'' || c == '"' || c == '`')
        .and_then(|s| s.strip_suffix(|c| c == '\'' || c == '"' || c == '`'))
}

/// Extract the module name from a require() argument node.
///
/// Handles string literals (`'fs'`, `"fs"`) and template strings (`` `fs` ``).
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn extract_require_arg<'a>(args: tree_sitter::Node<'_>, source: &'a [u8]) -> Option<&'a str> {
    use crate::tree_sitter_ext::node_text;

    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "string" | "template_string"))
        .and_then(|child| strip_js_string_delimiters(node_text(child, source)))
}

/// Emit an import finding if the module name matches a known pattern.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn emit_js_import_finding(
    module_name: &str,
    node: tree_sitter::Node<'_>,
    path: &Arc<str>,
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    for &(pattern, capability) in IMPORT_PATTERNS {
        if matches_module_prefix(module_name, pattern) {
            let pos = node.start_position();
            findings.push(CapabilityFinding {
                capability,
                location: SourceLocation {
                    file: Arc::clone(path),
                    line: pos.row + 1,
                    column: pos.column + 1,
                },
                evidence: Arc::from(pattern),
                origin: Some(FindingOrigin::Import),
                language: Some(language),
                execution_context: None,
                reachable: None,
            });
            break;
        }
    }
}
