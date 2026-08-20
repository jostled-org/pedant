//! Go capability detection over one bounded fact inventory.
//!
//! When the `ts-go` feature is enabled, import and call-site detection reads
//! the [`GoFileFacts`](pedant_syntax::go::GoFileFacts) inventory
//! `pedant-syntax` extracts from one bound parse session. That inventory is the
//! workspace's sole Go grammar mapping, so this module states no node kind of
//! its own and cannot drift from the resolver that reads the same facts. A
//! build without the grammar falls back to the text tier.

use std::sync::Arc;

// The inventory, its compatibility ceiling, and the reference shape this
// module reads all come from `pedant-syntax`, which owns the grammar and the
// parser version. One gated import serves the whole module: every helper below
// sits under the same feature, so repeating the `use` inside each one restates
// that gate without narrowing anything.
#[cfg(feature = "ts-go")]
use pedant_syntax::go::{GoFactLimits, GoFileFacts, GoReferenceFact, GoReferenceKind};
#[cfg(feature = "ts-go")]
use pedant_syntax::{SyntaxLanguage, tree_sitter::parse_bound};
use pedant_types::{
    Capability, CapabilityAnalysis, CapabilityFinding, FindingOrigin, Language, SourceLocation,
};

use crate::attribution;
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

/// Analyze Go source for capabilities, and attribute them to callables.
///
/// The structured tier extracts one fact inventory, uses it for detection, and
/// hands it to attribution. A build without the grammar, and a parser that
/// produced no tree, take the text tier and report attribution as unavailable.
pub(crate) fn analyze(path: &Arc<str>, source: &str) -> CapabilityAnalysis {
    let mut findings = Vec::new();

    #[cfg(feature = "ts-go")]
    let bound = ts_analyze(path, source, &mut findings);

    // No grammar in this build, so no inventory can exist and the text tier is
    // the only path.
    #[cfg(not(feature = "ts-go"))]
    let bound: Option<()> = None;

    if bound.is_none() {
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

    #[cfg(feature = "ts-go")]
    let analysis = attribution::symbols::seal(bound, Language::Go, findings.into_boxed_slice());
    #[cfg(not(feature = "ts-go"))]
    let analysis = attribution::envelope::unavailable(findings.into_boxed_slice());
    analysis
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
        // The text tier reads whole lines, so it can name the line an import
        // sits on but not the column its specification opens at.
        emit_import_findings(path, pkg, line_num + 1, 1, findings);
    }
}

fn emit_import_findings(
    path: &Arc<str>,
    pkg: &str,
    line: usize,
    column: usize,
    findings: &mut Vec<CapabilityFinding>,
) {
    for &(pattern, capability) in IMPORT_PATTERNS {
        if matches_module_prefix(pkg, pattern) {
            findings.push(CapabilityFinding {
                capability,
                location: SourceLocation {
                    file: Arc::clone(path),
                    line,
                    column,
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

// ── Structured detection over one fact inventory ───────────────────────

/// Detect through the Go fact inventory, returning the inventory that did it.
///
/// `None` means no tree: the caller owes the file its text-tier scan. The
/// inventory travels back rather than dying here, because attribution asks it
/// the same declaration questions detection just did.
#[cfg(feature = "ts-go")]
fn ts_analyze<'source>(
    path: &Arc<str>,
    source: &'source str,
    findings: &mut Vec<CapabilityFinding>,
) -> Option<GoFileFacts<'source>> {
    let parsed = parse_bound(source, SyntaxLanguage::Go)?;
    let facts = parsed.go_file_facts(GoFactLimits::UNBOUNDED).ok()?;

    // Phase 1: import-level capabilities, in the order the file states them.
    detect_fact_imports(path, &facts, findings);

    // Phase 2: qualified calls resolved against those same imports, plus the
    // text-tier scan for bare patterns no import introduced.
    detect_fact_calls(path, &facts, findings);
    detect_call_sites(path, source, CALL_SITE_PATTERNS, Language::Go, findings);
    dedup_call_findings(findings);

    Some(facts)
}

/// Remove duplicate call-site findings at the same location (the fact tier and
/// the text tier may both fire for the same qualified call).
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

/// Emit an import-level finding for every import the inventory states.
#[cfg(feature = "ts-go")]
fn detect_fact_imports(
    path: &Arc<str>,
    facts: &GoFileFacts<'_>,
    findings: &mut Vec<CapabilityFinding>,
) {
    for import in facts.imports() {
        let span = import.span();
        emit_import_findings(
            path,
            import.path(),
            span.start_line() + 1,
            span.start_column() + 1,
            findings,
        );
    }
}

/// Emit a call-site finding for every qualified call the inventory states.
#[cfg(feature = "ts-go")]
fn detect_fact_calls(
    path: &Arc<str>,
    facts: &GoFileFacts<'_>,
    findings: &mut Vec<CapabilityFinding>,
) {
    for reference in facts.references() {
        let Some(qualified) = qualified_call(facts, reference) else {
            continue;
        };
        emit_call_finding(path, &qualified, reference, findings);
    }
}

/// The `package.Method(` fragment one reference states, resolved through the
/// file's own imports.
///
/// The first import binding the receiver name wins. Go forbids two imports
/// binding one name in a file, so the choice only arises for source that would
/// not compile.
#[cfg(feature = "ts-go")]
fn qualified_call(facts: &GoFileFacts<'_>, reference: &GoReferenceFact<'_>) -> Option<String> {
    if reference.kind() != GoReferenceKind::QualifiedCall {
        return None;
    }
    let receiver = reference.qualifier()?;
    let imported = facts
        .imports()
        .iter()
        .find(|import| import.local_name() == Some(receiver))?
        .path();
    let last_segment = imported.rsplit('/').next().unwrap_or(imported);
    Some(format!("{last_segment}.{}(", reference.name()))
}

/// Emit the capability a resolved qualified call names, if it names one.
#[cfg(feature = "ts-go")]
fn emit_call_finding(
    path: &Arc<str>,
    qualified: &str,
    reference: &GoReferenceFact<'_>,
    findings: &mut Vec<CapabilityFinding>,
) {
    for &(pattern, capability, evidence) in CALL_SITE_PATTERNS {
        if qualified == pattern {
            let span = reference.span();
            findings.push(CapabilityFinding {
                capability,
                location: SourceLocation {
                    file: Arc::clone(path),
                    line: span.start_line() + 1,
                    column: span.start_column() + 1,
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
}
