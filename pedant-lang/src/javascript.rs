//! JavaScript/TypeScript capability detection via source-text scanning.
//!
//! When the `ts-javascript` or `ts-typescript` feature is enabled, import
//! detection uses tree-sitter for structured AST extraction. This handles
//! template-literal `require()` calls accurately. Falls back to regex when
//! disabled.

use std::sync::Arc;

// Grammar selection, traversal, and the node type the AST signatures below name
// all come from `pedant-syntax`, which owns the grammar and the parser version.
// Naming the node type through a second `tree-sitter` dependency here would pin
// the same crate twice. One gated import serves every tree-sitter helper: they
// all sit under the same feature, so repeating the `use` inside each one
// restates that gate without narrowing anything. `SyntaxLanguage` is ungated
// because `analyze` and `grammar_enabled` name it in every configuration.
use pedant_syntax::SyntaxLanguage;
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
use pedant_syntax::tree_sitter::{self, ParsedSyntax, node_text, parse_bound, walk_descendants};
use pedant_types::{
    Capability, CapabilityAnalysis, CapabilityFinding, FindingOrigin, Language, SourceLocation,
};

use crate::attribution;
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
///
/// `language` tags every finding; `syntax` selects the grammar. The two differ
/// for `.tsx`, which carries capability [`Language::TypeScript`] and needs the
/// TSX grammar — the caller resolves that distinction and passes it here.
pub(crate) fn analyze(
    path: &Arc<str>,
    source: &str,
    language: Language,
    syntax: SyntaxLanguage,
) -> CapabilityAnalysis {
    let mut findings = Vec::new();

    #[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
    let bound = ts_analyze(path, source, language, syntax, &mut findings);

    // This build links no JavaScript or TypeScript grammar, so `grammar_enabled`
    // answers false for every syntax and no session can exist.
    #[cfg(not(any(feature = "ts-javascript", feature = "ts-typescript")))]
    let bound = grammar_enabled(syntax).then_some(());

    if bound.is_none() {
        detect_imports(path, source, language, &mut findings);
        detect_call_sites(path, source, CALL_SITE_PATTERNS, language, &mut findings);
    }

    let literals = scan_js_string_literals(source);
    detect_string_literal_findings(path, &literals, language, &mut findings);

    #[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
    let analysis = attribution::seal(bound, language, findings.into_boxed_slice());
    #[cfg(not(any(feature = "ts-javascript", feature = "ts-typescript")))]
    let analysis = attribution::unavailable(findings.into_boxed_slice());
    analysis
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

        if let Some(&(pattern, capability)) = IMPORT_PATTERNS
            .iter()
            .find(|&&(pattern, _)| matches_module_prefix(name, pattern))
        {
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
        }
    }
}

// ── Tree-sitter structured extraction ──────────────────────────────────

/// Structured extraction through tree-sitter, returning the session that did it.
///
/// `None` means this build links no grammar for `syntax`, or the parser failed
/// outright, and the caller owes the file a regex scan. The session travels
/// back rather than dying here, because attribution asks it the same questions
/// detection just did.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn ts_analyze<'source>(
    path: &Arc<str>,
    source: &'source str,
    language: Language,
    syntax: SyntaxLanguage,
    findings: &mut Vec<CapabilityFinding>,
) -> Option<ParsedSyntax<'source>> {
    let parsed = grammar_enabled(syntax)
        .then(|| parse_bound(source, syntax))
        .flatten()?;
    let bytes = source.as_bytes();
    let root = parsed.root();

    // Phase 1: detect module references via tree-sitter — ES imports and
    // require() calls, in one walk.
    ts_detect_module_references(root, bytes, path, language, findings);

    // Phase 2: regex call-site patterns (fetch(), process.env, etc.).
    detect_call_sites(path, source, CALL_SITE_PATTERNS, language, findings);

    Some(parsed)
}

/// Whether this crate's own features link a grammar for `syntax`.
///
/// `pedant_syntax::tree_sitter::parse` answers from the feature set of the whole
/// build, and Cargo unifies features across every member that names
/// `pedant-syntax`. In a build where `pedant-lang/ts-typescript` is off but some
/// other member turns on `pedant-syntax/ts-typescript`, asking `parse` alone
/// would take a `.ts` file down the tree-sitter path that this crate's manifest
/// says is off. The decision is this crate's, so it is made here, and a syntax
/// this build has no feature for falls through to the regex scanner.
///
/// `Tsx` rides `ts-typescript` because one grammar crate ships both tables.
///
/// Every variant names both arms — the `true` its feature enables and the
/// `false` its feature leaves — so the match is exhaustive in every
/// configuration and a new [`SyntaxLanguage`] fails to compile here rather than
/// silently picking a side.
fn grammar_enabled(syntax: SyntaxLanguage) -> bool {
    match syntax {
        #[cfg(feature = "ts-javascript")]
        SyntaxLanguage::JavaScript => true,
        #[cfg(not(feature = "ts-javascript"))]
        SyntaxLanguage::JavaScript => false,
        #[cfg(feature = "ts-typescript")]
        SyntaxLanguage::TypeScript | SyntaxLanguage::Tsx => true,
        #[cfg(not(feature = "ts-typescript"))]
        SyntaxLanguage::TypeScript | SyntaxLanguage::Tsx => false,
        // This module analyzes no other syntax; `analyze_file` dispatches them
        // to their own scanners.
        SyntaxLanguage::Rust
        | SyntaxLanguage::Python
        | SyntaxLanguage::Go
        | SyntaxLanguage::Bash => false,
    }
}

/// Walk the AST once, extracting both spellings of a module reference.
///
/// `import_statement` and `call_expression` are disjoint kinds, and neither
/// handler reads the other's output, so one cursor walk answers both. A second
/// full-tree walk per JS/TS file bought nothing. Findings now interleave by
/// source position instead of grouping imports ahead of requires; this module
/// neither sorts nor dedups, so position order is the honest order.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn ts_detect_module_references(
    root: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    walk_descendants(root, |node| match node.kind() {
        "import_statement" => ts_handle_import(node, source, path, language, findings),
        "call_expression" => ts_handle_require_call(node, source, path, language, findings),
        _ => {}
    });
}

/// Handle an `import_statement` node: pull the module name and match it.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn ts_handle_import(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    let source_node = match node.child_by_field_name("source") {
        Some(n) => n,
        None => return,
    };
    let raw = node_text(source_node, source);
    // An `import` source is always a quoted string, never a template, so the
    // shared helper's extra backtick arm is unreachable here and harmless.
    let module_name = strip_js_string_delimiters(raw).unwrap_or(raw);

    emit_js_import_finding(module_name, node, path, language, findings);
}

/// Handle a `call_expression` node, matching `require()` calls with both
/// string and template-literal arguments.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn ts_handle_require_call(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
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
