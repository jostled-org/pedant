//! Python capability detection via source-text scanning.
//!
//! When the `ts-python` feature is enabled, import detection uses tree-sitter
//! for structured AST extraction. This handles aliased imports (`import X as Y`)
//! and multi-line imports accurately. Falls back to regex when disabled.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{Capability, CapabilityFinding, FindingOrigin, Language, SourceLocation};

use crate::string_analysis::{
    detect_call_sites, detect_string_literal_findings, scan_string_literals,
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

    let literals = scan_string_literals(source);
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
        for &(module, capability) in IMPORT_PATTERNS {
            if match_import(line, module) {
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
            }
        }
    }
}

// ── Tree-sitter structured extraction ──────────────────────────────────

#[cfg(feature = "ts-python")]
fn ts_analyze(path: &Arc<str>, source: &str, findings: &mut Vec<CapabilityFinding>) {
    use crate::tree_sitter_ext::parse;

    let bytes = source.as_bytes();
    let tree = match parse(bytes, tree_sitter_python::LANGUAGE.into()) {
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
    use crate::tree_sitter_ext::walk_descendants;

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
    use crate::tree_sitter_ext::node_text;

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
    use crate::tree_sitter_ext::node_text;

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
    use crate::tree_sitter_ext::{node_text, walk_descendants};

    if alias_map.is_empty() {
        return;
    }

    walk_descendants(root, |node| {
        if node.kind() != "call" {
            return;
        }
        let func = match node.child_by_field_name("function") {
            Some(f) => f,
            None => return,
        };
        // Only handle `alias.method(...)` calls (attribute access on an alias).
        if func.kind() != "attribute" {
            return;
        }
        let object = match func.child_by_field_name("object") {
            Some(o) => o,
            None => return,
        };
        let object_name = node_text(object, source);

        // Resolve alias to original module name.
        let module = match alias_map.get(object_name) {
            Some(module_name) => module_name.as_ref(),
            None => return,
        };

        // Build the qualified call: "module.method"
        let method = match func.child_by_field_name("attribute") {
            Some(a) => node_text(a, source),
            None => return,
        };

        // Check against CALL_SITE_PATTERNS (which expect "module.method(" format).
        let qualified = format!("{module}.{method}(");
        for &(pattern, capability, evidence) in CALL_SITE_PATTERNS {
            if qualified.starts_with(pattern) {
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
                    language: Some(Language::Python),
                    execution_context: None,
                    reachable: None,
                });
                break;
            }
        }

        // Also check if the module itself has a capability (e.g., `r.get()` where
        // `r` = `requests` → Network capability from the call).
        for &(import_pattern, capability) in IMPORT_PATTERNS {
            if module == import_pattern || module.starts_with(import_pattern) {
                let pos = node.start_position();
                findings.push(CapabilityFinding {
                    capability,
                    location: SourceLocation {
                        file: Arc::clone(path),
                        line: pos.row + 1,
                        column: pos.column + 1,
                    },
                    evidence: Arc::from(format!("{object_name}.{method}").as_str()),
                    origin: Some(FindingOrigin::CodeSite),
                    language: Some(Language::Python),
                    execution_context: None,
                    reachable: None,
                });
                break;
            }
        }
    });
}
