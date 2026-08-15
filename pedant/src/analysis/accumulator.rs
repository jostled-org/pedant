use std::io::Write;

use pedant_core::AnalysisResult;
use pedant_core::project::FileShape;

use crate::ProcessError;

pub(crate) struct AnalysisAccumulator {
    pub(crate) violations: Vec<pedant_core::Violation>,
    pub(crate) findings: Vec<pedant_types::CapabilityFinding>,
    pub(crate) data_flows: Vec<pedant_core::ir::DataFlowFact>,
    /// One shape per analyzed Rust file, feeding the whole-crate checks.
    pub(crate) file_shapes: Vec<FileShape>,
    pub(crate) had_error: bool,
}

impl AnalysisAccumulator {
    pub(crate) fn with_capacity(file_count: usize) -> Self {
        Self {
            violations: Vec::with_capacity(file_count),
            findings: Vec::with_capacity(file_count),
            data_flows: Vec::new(),
            file_shapes: Vec::with_capacity(file_count),
            had_error: false,
        }
    }

    pub(crate) fn handle(
        &mut self,
        result: Result<(AnalysisResult, FileShape), ProcessError>,
        context: &str,
        stderr: &mut impl Write,
    ) {
        match result {
            Ok((r, shape)) => {
                self.violations.append(&mut r.violations.into_vec());
                self.findings
                    .append(&mut r.capabilities.into_profile().findings.into_vec());
                self.data_flows.extend_from_slice(&r.data_flows);
                self.file_shapes.push(shape);
            }
            Err(e) => {
                crate::report_error(stderr, format_args!("{context}: {e}"));
                self.had_error = true;
            }
        }
    }
}
