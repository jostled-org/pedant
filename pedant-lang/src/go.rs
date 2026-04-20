//! Go capability detection via source-text scanning.
//!
//! When the `ts-go` feature is enabled, import and call-site detection uses
//! tree-sitter for structured AST extraction. This resolves qualified calls
//! (`os.Open`) to their imported package accurately. Falls back to regex
//! when disabled.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{Capability, CapabilityFinding, FindingOrigin, Language, SourceLocation};

use crate::string_analysis::{
    detect_call_sites, detect_string_literal_findings, matches_module_prefix,
    scan_go_string_literals,
};

/// Import-level pattern: Go package path prefix mapped to capability.
///
/// Bare `os`, `io`, and `bufio` are deliberately excluded — only specific
/// call sites (e.g. `os.Open`) trigger filesystem capabilities.
const IMPORT_PATTERNS: &[(&str, Capability)] = &[
    // Network
    ("net", Capability::Network),
    // Crypto
    ("crypto", Capability::Crypto),
    // Process execution
    ("os/exec", Capability::ProcessExec),
    // FFI (cgo)
    ("C", Capability::Ffi),
    // Unsafe
    ("unsafe", Capability::UnsafeCode),
];

/// Call-site pattern: text fragment that indicates a capability.
const CALL_SITE_PATTERNS: &[(&str, Capability, &str)] = &[
    ("os.Open(", Capability::FileRead, "os.Open"),
    ("os.Create(", Capability::FileWrite, "os.Create"),
    ("os.ReadFile(", Capability::FileRead, "os.ReadFile"),
    ("os.WriteFile(", Capability::FileWrite, "os.WriteFile"),
    ("os.Getenv(", Capability::EnvAccess, "os.Getenv"),
    ("os.Environ(", Capability::EnvAccess, "os.Environ"),
    ("exec.Command(", Capability::ProcessExec, "exec.Command"),
    ("syscall.Exec(", Capability::ProcessExec, "syscall.Exec"),
];

/// Analyze Go source for capability findings.
pub(crate) fn analyze(path: &Arc<str>, source: &str) -> Box<[CapabilityFinding]> {
    let mut findings = Vec::new();

    #[cfg(feature = "ts-go")]
    ts_analyze(path, source, &mut findings);

    #[cfg(not(feature = "ts-go"))]
    {
        detect_imports(path, source, &mut findings);
        detect_call_sites(
            path,
            source,
            CALL_SITE_PATTERNS,
            Language::Go,
            &mut findings,
        );
    }

    let literals = scan_go_string_literals(source);
    detect_string_literal_findings(path, &literals, Language::Go, &mut findings);

    findings.into_boxed_slice()
}

/// Extract the package path from a Go import line.
///
/// Handles `"package"`, `_ "package"`, and `alias "package"` forms.
fn extract_go_package_path(s: &str) -> Option<&str> {
    let start = s.find('"')? + 1;
    let end = start + s[start..].find('"')?;
    Some(&s[start..end])
}

fn detect_imports(path: &Arc<str>, source: &str, findings: &mut Vec<CapabilityFinding>) {
    let mut in_import_block = false;

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        match (in_import_block, trimmed) {
            (true, s) if s.starts_with(')') => in_import_block = false,
            (true, s) if s.is_empty() || s.starts_with("//") => {}
            (true, s) => try_emit_import(path, s, line_num, findings),
            (false, _) => {
                in_import_block = process_import_line(path, trimmed, line_num, findings);
            }
        }
    }
}

/// Process a non-block line starting with `import`. Returns `true` if an
/// import block was opened.
fn process_import_line(
    path: &Arc<str>,
    trimmed: &str,
    line_num: usize,
    findings: &mut Vec<CapabilityFinding>,
) -> bool {
    let rest = match trimmed.strip_prefix("import") {
        Some(r) => r.trim_start(),
        None => return false,
    };
    match rest.starts_with('(') {
        true => true,
        false => {
            try_emit_import(path, rest, line_num, findings);
            false
        }
    }
}

fn try_emit_import(
    path: &Arc<str>,
    text: &str,
    line_num: usize,
    findings: &mut Vec<CapabilityFinding>,
) {
    if let Some(pkg) = extract_go_package_path(text) {
        emit_import_findings(path, pkg, line_num, findings);
    }
}

fn emit_import_findings(
    path: &Arc<str>,
    pkg: &str,
    line_num: usize,
    findings: &mut Vec<CapabilityFinding>,
) {
    for &(pattern, capability) in IMPORT_PATTERNS {
        if matches_module_prefix(pkg, pattern) {
            findings.push(CapabilityFinding {
                capability,
                location: SourceLocation {
                    file: Arc::clone(path),
                    line: line_num + 1,
                    column: 1,
                },
                evidence: Arc::from(pkg),
                origin: Some(FindingOrigin::Import),
                language: Some(Language::Go),
                execution_context: None,
                reachable: None,
            });
            break;
        }
    }
}

// ── Tree-sitter structured extraction ──────────────────────────────────

#[cfg(feature = "ts-go")]
fn ts_analyze(path: &Arc<str>, source: &str, findings: &mut Vec<CapabilityFinding>) {
    use crate::tree_sitter_ext::parse;

    let bytes = source.as_bytes();
    let tree = match parse(bytes, tree_sitter_go::LANGUAGE.into()) {
        Some(t) => t,
        None => {
            detect_imports(path, source, findings);
            detect_call_sites(path, source, CALL_SITE_PATTERNS, Language::Go, findings);
            return;
        }
    };
    let root = tree.root_node();

    // Phase 1: extract imports and build package-name → path map.
    let mut pkg_map = BTreeMap::new();
    ts_extract_imports(root, bytes, path, findings, &mut pkg_map);

    // Phase 2: detect qualified calls by resolving selector expressions against
    // imports, plus regex call-site fallback for bare patterns without imports.
    ts_detect_qualified_calls(root, bytes, path, &pkg_map, findings);
    detect_call_sites(path, source, CALL_SITE_PATTERNS, Language::Go, findings);
    dedup_call_findings(findings);
}

/// Remove duplicate call-site findings at the same location (tree-sitter and
/// regex may both fire for the same qualified call).
#[cfg(feature = "ts-go")]
fn dedup_call_findings(findings: &mut Vec<CapabilityFinding>) {
    findings.sort_by(|a, b| {
        a.location
            .line
            .cmp(&b.location.line)
            .then(a.location.column.cmp(&b.location.column))
            .then(a.capability.cmp(&b.capability))
    });
    findings.dedup_by(|a, b| {
        a.location.line == b.location.line
            && a.location.column == b.location.column
            && a.capability == b.capability
    });
}

/// Extract Go imports from tree-sitter AST and build a local-name → package-path map.
#[cfg(feature = "ts-go")]
fn ts_extract_imports(
    root: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    findings: &mut Vec<CapabilityFinding>,
    pkg_map: &mut BTreeMap<Box<str>, Box<str>>,
) {
    use crate::tree_sitter_ext::{node_text, walk_descendants};

    walk_descendants(root, |node| {
        if node.kind() != "import_spec" {
            return;
        }
        let path_node = match node.child_by_field_name("path") {
            Some(n) => n,
            None => return,
        };
        let raw_path = node_text(path_node, source);
        let pkg_path = raw_path.trim_matches('"');

        // Determine local name: explicit alias or last segment of path.
        let alias_text = node
            .child_by_field_name("name")
            .map(|n| node_text(n, source));
        // Blank and dot imports don't create a usable local name.
        if matches!(alias_text, Some("_" | ".")) {
            return;
        }
        let local_name = match alias_text {
            Some(name) => Box::from(name),
            None => Box::from(pkg_path.rsplit('/').next().unwrap_or(pkg_path)),
        };

        pkg_map.insert(local_name, Box::from(pkg_path));

        // Emit import-level capability findings.
        let pos = node.start_position();
        for &(pattern, capability) in IMPORT_PATTERNS {
            if matches_module_prefix(pkg_path, pattern) {
                findings.push(CapabilityFinding {
                    capability,
                    location: SourceLocation {
                        file: Arc::clone(path),
                        line: pos.row + 1,
                        column: pos.column + 1,
                    },
                    evidence: Arc::from(pkg_path),
                    origin: Some(FindingOrigin::Import),
                    language: Some(Language::Go),
                    execution_context: None,
                    reachable: None,
                });
                break;
            }
        }
    });
}

/// Detect qualified calls by resolving `pkg.Func()` against the import map.
#[cfg(feature = "ts-go")]
fn ts_detect_qualified_calls(
    root: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Arc<str>,
    pkg_map: &BTreeMap<Box<str>, Box<str>>,
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
        if func.kind() != "selector_expression" {
            return;
        }
        let operand = match func.child_by_field_name("operand") {
            Some(o) => o,
            None => return,
        };
        let field = match func.child_by_field_name("field") {
            Some(f) => f,
            None => return,
        };

        let receiver = node_text(operand, source);
        let method = node_text(field, source);

        // Resolve receiver to package path via import map.
        let pkg_path = match pkg_map.get(receiver) {
            Some(pkg_path) => pkg_path.as_ref(),
            None => return,
        };

        // Build qualified call pattern: "pkg_last_segment.Method("
        let last_segment = pkg_path.rsplit('/').next().unwrap_or(pkg_path);
        let qualified = format!("{last_segment}.{method}(");

        for &(pattern, capability, evidence) in CALL_SITE_PATTERNS {
            if qualified == pattern {
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
                    language: Some(Language::Go),
                    execution_context: None,
                    reachable: None,
                });
                break;
            }
        }
    });
}
