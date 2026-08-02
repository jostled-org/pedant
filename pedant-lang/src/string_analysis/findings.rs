//! Finding construction shared by language-specific scanners.

use std::sync::Arc;

use pedant_types::{Capability, CapabilityFinding, FindingOrigin, Language, SourceLocation};

use super::evidence::{KEY_MATERIAL_CHECKS, STRING_LITERAL_CHECKS, truncate_evidence};

pub(crate) fn matches_module_prefix(name: &str, pattern: &str) -> bool {
    name == pattern
        || (name.starts_with(pattern) && name.as_bytes().get(pattern.len()) == Some(&b'/'))
}

pub(crate) fn detect_call_sites(
    path: &Arc<str>,
    source: &str,
    patterns: &[(&str, Capability, &str)],
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    source.lines().enumerate().for_each(|(line_number, line)| {
        patterns
            .iter()
            .filter_map(|&(pattern, capability, evidence)| {
                line.find(pattern)
                    .map(|column| (column, capability, evidence))
            })
            .for_each(|(column, capability, evidence)| {
                findings.push(CapabilityFinding {
                    capability,
                    location: SourceLocation {
                        file: Arc::clone(path),
                        line: line_number + 1,
                        column: column + 1,
                    },
                    evidence: Arc::from(evidence),
                    origin: Some(FindingOrigin::CodeSite),
                    language: Some(language),
                    execution_context: None,
                    reachable: None,
                });
            });
    });
}

pub(crate) fn detect_string_literal_findings(
    path: &Arc<str>,
    literals: &[(Box<str>, usize, usize)],
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    literals.iter().for_each(|(value, line, column)| {
        if let Some(&(_, capability)) = STRING_LITERAL_CHECKS
            .iter()
            .find(|&&(checker, _)| checker(value))
        {
            findings.push(CapabilityFinding {
                capability,
                location: SourceLocation {
                    file: Arc::clone(path),
                    line: *line,
                    column: *column,
                },
                evidence: Arc::from(value.as_ref()),
                origin: Some(FindingOrigin::StringLiteral),
                language: Some(language),
                execution_context: None,
                reachable: None,
            });
        }

        if KEY_MATERIAL_CHECKS.iter().any(|check| check(value)) {
            let evidence = truncate_evidence(value);
            findings.push(CapabilityFinding {
                capability: Capability::Crypto,
                location: SourceLocation {
                    file: Arc::clone(path),
                    line: *line,
                    column: *column,
                },
                evidence: Arc::from(evidence.as_ref()),
                origin: Some(FindingOrigin::StringLiteral),
                language: Some(language),
                execution_context: None,
                reachable: None,
            });
        }
    });
}

pub(crate) fn is_shell_command_boundary(
    line: &str,
    position: usize,
    pattern: &str,
    extra_after: &[u8],
) -> bool {
    let before_ok = match position {
        0 => true,
        _ => matches!(
            line.as_bytes()[position - 1],
            b' ' | b'\t' | b'|' | b';' | b'`' | b'(' | b'&'
        ),
    };
    let after_position = position + pattern.len();
    let after_ok = match line.as_bytes().get(after_position) {
        None => true,
        Some(byte) => {
            matches!(byte, b' ' | b'\t' | b';' | b'|' | b'&' | b'\n' | b')')
                || extra_after.contains(byte)
        }
    };
    before_ok && after_ok
}
