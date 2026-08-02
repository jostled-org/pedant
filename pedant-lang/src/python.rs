//! Python capability detection via source-text scanning.
//!
//! When the `ts-python` feature is enabled, import detection uses tree-sitter
//! for structured AST extraction. This handles aliased imports (`import X as Y`)
//! and multi-line imports accurately. Falls back to regex when disabled.

#[cfg(feature = "ts-python")]
use std::collections::BTreeMap;
use std::sync::Arc;

// Grammar selection, traversal, and the node type the AST signatures below name
// all come from `pedant-syntax`, which owns the grammar and the parser version.
// Naming the node type through a second `tree-sitter` dependency here would pin
// the same crate twice. One gated import serves the whole module: every helper
// below sits under the same feature, so repeating the `use` inside each one
// restates that gate without narrowing anything.
#[cfg(feature = "ts-python")]
use pedant_syntax::{
    SyntaxLanguage,
    tree_sitter::{self, node_text, parse, walk_descendants},
};
use pedant_types::{Capability, CapabilityFinding, FindingOrigin, Language, SourceLocation};

use crate::string_analysis::{
    CommentStyle, detect_call_sites, detect_string_literal_findings, scan_string_literals,
};

/// Import-level pattern: module name prefix mapped to capability.
const IMPORT_PATTERNS: &[(&str, Capability)] = &[
    // Network
    ("socket", Capability::Network),
    ("urllib", Capability::Network),
    ("requests", Capability::Network),
    ("httpx", Capability::Network),
    ("aiohttp", Capability::Network),
    // Process execution
    ("subprocess", Capability::ProcessExec),
    // Env access
    ("dotenv", Capability::EnvAccess),
    // Crypto
    ("cryptography", Capability::Crypto),
    ("hashlib", Capability::Crypto),
    ("hmac", Capability::Crypto),
    ("Crypto", Capability::Crypto),
    // FFI
    ("ctypes", Capability::Ffi),
    ("cffi", Capability::Ffi),
];

/// Call-site pattern: text fragment that indicates a capability.
const CALL_SITE_PATTERNS: &[(&str, Capability, &str)] = &[
    ("os.system(", Capability::ProcessExec, "os.system"),
    ("os.execl(", Capability::ProcessExec, "os.exec*"),
    ("os.execle(", Capability::ProcessExec, "os.exec*"),
    ("os.execlp(", Capability::ProcessExec, "os.exec*"),
    ("os.execlpe(", Capability::ProcessExec, "os.exec*"),
    ("os.execv(", Capability::ProcessExec, "os.exec*"),
    ("os.execve(", Capability::ProcessExec, "os.exec*"),
    ("os.execvp(", Capability::ProcessExec, "os.exec*"),
    ("os.execvpe(", Capability::ProcessExec, "os.exec*"),
    ("os.environ", Capability::EnvAccess, "os.environ"),
    ("os.getenv(", Capability::EnvAccess, "os.getenv"),
    ("open(", Capability::FileRead, "open()"),
    ("shutil.copy(", Capability::FileWrite, "shutil.copy"),
    ("shutil.copy2(", Capability::FileWrite, "shutil.copy"),
    ("shutil.copytree(", Capability::FileWrite, "shutil.copy"),
    ("shutil.move(", Capability::FileWrite, "shutil.move"),
    ("shutil.rmtree(", Capability::FileWrite, "shutil.rmtree"),
];

/// Analyze Python source for capability findings.
pub(crate) fn analyze(path: &Arc<str>, source: &str) -> Box<[CapabilityFinding]> {
    let mut findings = Vec::new();

    #[cfg(feature = "ts-python")]
    ts_analyze(path, source, &mut findings);

    #[cfg(not(feature = "ts-python"))]
    {
        detect_imports(path, source, &mut findings);
        detect_call_sites(
            path,
            source,
            CALL_SITE_PATTERNS,
            Language::Python,
            &mut findings,
        );
    }

    // Python ends a line at any unquoted `#`, including one with no space in
    // front of it: `x=1#note` is a comment.
    let literals = scan_string_literals(source, CommentStyle::Always);
    detect_string_literal_findings(path, &literals, Language::Python, &mut findings);

    findings.into_boxed_slice()
}

/// Check if a line is a Python import statement matching one of the known patterns.
///
/// Matches `import <module>` and `from <module> import ...` / `from <module>.<sub> import ...`.
fn match_import(line: &str, module: &str) -> bool {
    let trimmed = line.trim();
    let (prefix, rest) = match (
        trimmed.strip_prefix("import "),
        trimmed.strip_prefix("from "),
    ) {
        (Some(r), _) => ("import", r),
        (_, Some(r)) => ("from", r),
        _ => return false,
    };
    let starts = rest.starts_with(module);
    let delimiter = rest.as_bytes().get(module.len());
    match prefix {
        "import" => rest == module || (starts && delimiter == Some(&b'.')),
        _ => starts && delimiter.is_some_and(|&b| b == b' ' || b == b'.'),
    }
}

fn detect_imports(path: &Arc<str>, source: &str, findings: &mut Vec<CapabilityFinding>) {
    for (line_num, line) in source.lines().enumerate() {
        IMPORT_PATTERNS
            .iter()
            .filter(|&&(module, _)| match_import(line, module))
            .for_each(|&(module, capability)| {
                findings.push(CapabilityFinding {
                    capability,
                    location: SourceLocation {
                        file: Arc::clone(path),
                        line: line_num + 1,
                        column: 1,
                    },
                    evidence: Arc::from(module),
                    origin: Some(FindingOrigin::Import),
                    language: Some(Language::Python),
                    execution_context: None,
                    reachable: None,
                });
            });
    }
}

// ── Tree-sitter structured extraction ──────────────────────────────────

#[cfg(feature = "ts-python")]
fn ts_analyze(path: &Arc<str>, source: &str, findings: &mut Vec<CapabilityFinding>) {
    let bytes = source.as_bytes();
    let tree = match parse(bytes, SyntaxLanguage::Python) {
        Some(t) => t,
        None => {
            // Fall back to regex on parse failure.
            detect_imports(path, source, findings);
            detect_call_sites(path, source, CALL_SITE_PATTERNS, Language::Python, findings);
            return;
        }
    };
    let root = tree.root_node();

    // Phase 1: extract imports and build alias map.
    let mut alias_map = BTreeMap::new();
    ts_extract_imports(root, bytes, path, findings, &mut alias_map);

    // Phase 2: detect call sites (regex patterns + alias-aware calls).
    detect_call_sites(path, source, CALL_SITE_PATTERNS, Language::Python, findings);
    ts_detect_aliased_calls(root, bytes, path, &alias_map, findings);
}

/// Extract imports from tree-sitter AST and build alias map.
#[cfg(feature = "ts-python")]
fn ts_extract_imports(
    root: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    findings: &mut Vec<CapabilityFinding>,
    alias_map: &mut BTreeMap<Box<str>, Box<str>>,
) {
    walk_descendants(root, |node| match node.kind() {
        "import_statement" => {
            ts_process_import_statement(node, source, path, findings, alias_map);
        }
        "import_from_statement" => {
            ts_process_import_from_statement(node, source, path, findings);
        }
        _ => {}
    });
}

/// Process `import X` or `import X as Y` statements.
#[cfg(feature = "ts-python")]
fn ts_process_import_statement(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    findings: &mut Vec<CapabilityFinding>,
    alias_map: &mut BTreeMap<Box<str>, Box<str>>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let (module_name, alias) = match child.kind() {
            "dotted_name" => (node_text(child, source), None),
            "aliased_import" => {
                let name = child
                    .child_by_field_name("name")
                    .map(|n| node_text(n, source))
                    .unwrap_or("");
                let alias = child
                    .child_by_field_name("alias")
                    .map(|n| node_text(n, source));
                (name, alias)
            }
            _ => continue,
        };

        if let Some(alias_name) = alias {
            alias_map.insert(Box::from(alias_name), Box::from(module_name));
        }

        emit_import_if_matches(module_name, node, path, findings);
    }
}

/// Process `from X import ...` statements.
#[cfg(feature = "ts-python")]
fn ts_process_import_from_statement(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    findings: &mut Vec<CapabilityFinding>,
) {
    let module_node = match node.child_by_field_name("module_name") {
        Some(n) => n,
        None => return,
    };
    let module_name = node_text(module_node, source);
    emit_import_if_matches(module_name, node, path, findings);
}

/// Match a module name against IMPORT_PATTERNS and emit a finding.
#[cfg(feature = "ts-python")]
fn emit_import_if_matches(
    module_name: &str,
    node: tree_sitter::Node<'_>,
    path: &Arc<str>,
    findings: &mut Vec<CapabilityFinding>,
) {
    let top_module = module_name.split('.').next().unwrap_or(module_name);
    for &(pattern, capability) in IMPORT_PATTERNS {
        if top_module == pattern || module_name.starts_with(pattern) {
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
                language: Some(Language::Python),
                execution_context: None,
                reachable: None,
            });
            break;
        }
    }
}

/// An `alias.method(...)` call whose receiver resolved to an imported module.
#[cfg(feature = "ts-python")]
struct AliasedCall<'a> {
    /// Original module the alias resolves to, e.g. `requests`.
    module: &'a str,
    /// Attribute invoked on the alias, e.g. `get`.
    method: &'a str,
    /// Alias as written at the call site, e.g. `r`.
    object_name: &'a str,
    line: usize,
    column: usize,
}

/// Resolve an `alias.method(...)` call against the import alias map.
///
/// Yields `None` for any node that is not a call on a known alias.
#[cfg(feature = "ts-python")]
fn resolve_aliased_call<'a>(
    node: tree_sitter::Node<'_>,
    source: &'a [u8],
    alias_map: &'a BTreeMap<Box<str>, Box<str>>,
) -> Option<AliasedCall<'a>> {
    match node.kind() {
        "call" => {}
        _ => return None,
    }
    let func = node.child_by_field_name("function")?;
    // Only handle `alias.method(...)` calls (attribute access on an alias).
    match func.kind() {
        "attribute" => {}
        _ => return None,
    }
    let object_name = node_text(func.child_by_field_name("object")?, source);
    let module = alias_map.get(object_name)?.as_ref();
    let method = node_text(func.child_by_field_name("attribute")?, source);
    let pos = node.start_position();

    Some(AliasedCall {
        module,
        method,
        object_name,
        line: pos.row + 1,
        column: pos.column + 1,
    })
}

/// Build a finding located at an aliased call site.
#[cfg(feature = "ts-python")]
fn aliased_finding(
    call: &AliasedCall<'_>,
    path: &Arc<str>,
    capability: Capability,
    evidence: Arc<str>,
) -> CapabilityFinding {
    CapabilityFinding {
        capability,
        location: SourceLocation {
            file: Arc::clone(path),
            line: call.line,
            column: call.column,
        },
        evidence,
        origin: Some(FindingOrigin::CodeSite),
        language: Some(Language::Python),
        execution_context: None,
        reachable: None,
    }
}

/// Detect call sites where the receiver is an aliased import.
///
/// For `import requests as r`, calling `r.get(...)` should produce a Network
/// finding because `r` resolves to `requests`.
#[cfg(feature = "ts-python")]
fn ts_detect_aliased_calls(
    root: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    alias_map: &BTreeMap<Box<str>, Box<str>>,
    findings: &mut Vec<CapabilityFinding>,
) {
    if alias_map.is_empty() {
        return;
    }

    walk_descendants(root, |node| {
        let Some(call) = resolve_aliased_call(node, source, alias_map) else {
            return;
        };

        // CALL_SITE_PATTERNS expect the "module.method(" form.
        let qualified = format!("{}.{}(", call.module, call.method);
        let call_site = CALL_SITE_PATTERNS
            .iter()
            .find(|(pattern, _, _)| qualified.starts_with(pattern));
        if let Some(&(_, capability, evidence)) = call_site {
            findings.push(aliased_finding(
                &call,
                path,
                capability,
                Arc::from(evidence),
            ));
        }

        // The module itself may also carry a capability: `r.get()` where `r` is
        // `requests` yields Network from the import, not just the call site.
        let import = IMPORT_PATTERNS
            .iter()
            .find(|(pattern, _)| call.module.starts_with(pattern));
        if let Some(&(_, capability)) = import {
            let evidence = format!("{}.{}", call.object_name, call.method);
            findings.push(aliased_finding(
                &call,
                path,
                capability,
                Arc::from(evidence.as_str()),
            ));
        }
    });
}
