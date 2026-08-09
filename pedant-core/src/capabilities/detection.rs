use std::sync::Arc;

use pedant_types::{
    Capability, CapabilityFinding, CapabilityProfile, ExecutionContext, FindingOrigin,
    SourceLocation,
};

use super::paths::resolve_capabilities;
use super::strings::{KEY_MATERIAL_CHECKS, STRING_LITERAL_CHECKS, truncate_evidence};
use crate::ir::FileIr;
use crate::observe::{self, Observation};

struct FindingEmitter<'a> {
    findings: &'a mut Vec<CapabilityFinding>,
    file: &'a Arc<str>,
    origin: FindingOrigin,
    execution_context: Option<ExecutionContext>,
}

impl FindingEmitter<'_> {
    fn emit(&mut self, capability: Capability, line: usize, column: usize, evidence: &str) {
        self.findings.push(CapabilityFinding {
            capability,
            location: SourceLocation {
                file: Arc::clone(self.file),
                line,
                column: column + 1,
            },
            evidence: Arc::from(evidence),
            origin: Some(self.origin),
            language: None,
            execution_context: self.execution_context,
            reachable: None,
        });
    }

    fn emit_from_facts<'a, T: 'a>(
        &mut self,
        facts: &'a [T],
        mut mapper: impl FnMut(&'a T) -> Option<(Capability, usize, usize, &'a str)>,
    ) {
        for fact in facts {
            if let Some((capability, line, column, evidence)) = mapper(fact) {
                self.emit(capability, line, column, evidence);
            }
        }
    }
}

/// Scan all IR facts for capability usage and produce a profile.
///
/// When `execution_context` is present, every finding is tagged with that
/// context, such as [`ExecutionContext::BuildHook`] for `build.rs`.
pub fn detect_capabilities(
    ir: &FileIr,
    execution_context: Option<ExecutionContext>,
) -> CapabilityProfile {
    let file_path = &ir.file_path;
    observe::record(Observation::CapabilityProjection(file_path));
    let mut findings = Vec::new();

    detect_use_paths(ir, file_path, execution_context, &mut findings);
    detect_unsafe_sites(ir, file_path, execution_context, &mut findings);
    detect_extern_blocks(ir, file_path, execution_context, &mut findings);
    detect_attributes(ir, file_path, execution_context, &mut findings);
    detect_string_literals(ir, file_path, execution_context, &mut findings);

    CapabilityProfile {
        findings: findings.into_boxed_slice(),
    }
}

fn detect_use_paths(
    ir: &FileIr,
    file_path: &Arc<str>,
    execution_context: Option<ExecutionContext>,
    findings: &mut Vec<CapabilityFinding>,
) {
    let mut emitter = FindingEmitter {
        findings,
        file: file_path,
        origin: FindingOrigin::Import,
        execution_context,
    };
    emitter.emit_from_facts(&ir.use_paths, |use_path| {
        resolve_capabilities(&use_path.path).map(|capability| {
            (
                capability,
                use_path.span.line,
                use_path.span.column,
                use_path.path.as_ref(),
            )
        })
    });
}

fn detect_unsafe_sites(
    ir: &FileIr,
    file_path: &Arc<str>,
    execution_context: Option<ExecutionContext>,
    findings: &mut Vec<CapabilityFinding>,
) {
    let mut emitter = FindingEmitter {
        findings,
        file: file_path,
        origin: FindingOrigin::CodeSite,
        execution_context,
    };
    emitter.emit_from_facts(&ir.unsafe_sites, |site| {
        Some((
            Capability::UnsafeCode,
            site.span.line,
            site.span.column,
            site.evidence.as_ref(),
        ))
    });
}

fn detect_extern_blocks(
    ir: &FileIr,
    file_path: &Arc<str>,
    execution_context: Option<ExecutionContext>,
    findings: &mut Vec<CapabilityFinding>,
) {
    let mut emitter = FindingEmitter {
        findings,
        file: file_path,
        origin: FindingOrigin::CodeSite,
        execution_context,
    };
    emitter.emit_from_facts(&ir.extern_blocks, |block| {
        Some((
            Capability::Ffi,
            block.span.line,
            block.span.column,
            "extern block",
        ))
    });
}

fn detect_attributes(
    ir: &FileIr,
    file_path: &Arc<str>,
    execution_context: Option<ExecutionContext>,
    findings: &mut Vec<CapabilityFinding>,
) {
    let mut emitter = FindingEmitter {
        findings,
        file: file_path,
        origin: FindingOrigin::Attribute,
        execution_context,
    };
    emitter.emit_from_facts(&ir.attributes, |attribute| {
        let (capability, evidence) = match &*attribute.name {
            "link" => (Capability::Ffi, "#[link]"),
            "proc_macro" => (Capability::ProcMacro, "#[proc_macro]"),
            "proc_macro_derive" => (Capability::ProcMacro, "#[proc_macro_derive]"),
            "proc_macro_attribute" => (Capability::ProcMacro, "#[proc_macro_attribute]"),
            _ => return None,
        };
        Some((
            capability,
            attribute.span.line,
            attribute.span.column,
            evidence,
        ))
    });
}

fn detect_string_literals(
    ir: &FileIr,
    file_path: &Arc<str>,
    execution_context: Option<ExecutionContext>,
    findings: &mut Vec<CapabilityFinding>,
) {
    let mut emitter = FindingEmitter {
        findings,
        file: file_path,
        origin: FindingOrigin::StringLiteral,
        execution_context,
    };
    for literal in &ir.string_literals {
        let line = literal.span.line;
        let column = literal.span.column;

        if let Some(&(_, capability)) = STRING_LITERAL_CHECKS
            .iter()
            .find(|&&(checker, _)| checker(&literal.value))
        {
            emitter.emit(capability, line, column, &literal.value);
        }
        if KEY_MATERIAL_CHECKS
            .iter()
            .any(|check| check(&literal.value))
        {
            let evidence = truncate_evidence(&literal.value);
            emitter.emit(Capability::Crypto, line, column, &evidence);
        }
    }
}
