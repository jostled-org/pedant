use std::collections::BTreeMap;
use std::io::Write;

use pedant_core::check_config::CheckConfig;
use pedant_core::hash::compute_source_hash;
use pedant_core::lint::analyze_with_shape;

use crate::ProcessError;

use super::files::{analyze_file_list, process_stdin, read_stdin_source};
use super::{AnalysisAccumulator, AnalysisContext, AnalysisRequest};

/// Select the input source (stdin vs files) and run analysis, returning a source
/// hash when attestation mode requires one.
pub(crate) fn run_analysis(
    request: &AnalysisRequest<'_>,
    ctx: &AnalysisContext<'_>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Option<Box<str>> {
    match (request.collect_source_hash, request.stdin) {
        (true, true) => attest_stdin(ctx.base_config, acc, stderr),
        (true, false) => Some(attest_files(request.files, ctx, acc, stderr)),
        (false, true) => {
            acc.handle(process_stdin(ctx.base_config), "error", stderr);
            None
        }
        (false, false) => {
            analyze_file_list(request.files, ctx, None, acc, stderr);
            None
        }
    }
}

fn attest_stdin(
    config: &CheckConfig,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Option<Box<str>> {
    let source = match read_stdin_source() {
        Ok(s) => s,
        Err(e) => {
            crate::report_error(stderr, format_args!("error: {e}"));
            acc.had_error = true;
            return None;
        }
    };
    acc.handle(
        analyze_with_shape("<stdin>", &source, config, None).map_err(ProcessError::from),
        "error",
        stderr,
    );
    let mut sources = BTreeMap::new();
    sources.insert(Box::<str>::from("<stdin>"), source);
    Some(compute_source_hash(&sources))
}

fn attest_files(
    files: &[String],
    ctx: &AnalysisContext<'_>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Box<str> {
    let mut sources = BTreeMap::new();
    analyze_file_list(files, ctx, Some(&mut sources), acc, stderr);
    compute_source_hash(&sources)
}
