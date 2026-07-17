use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use super::error::{SupplyChainError, path_text};
use super::report::{Report, overall_status};

/// Publish `status` and `report` to `$GITHUB_OUTPUT` when running in Actions.
///
/// Outside Actions the variable is unset and this is a no-op.
pub(super) fn emit_github_output(report: &Report) -> Result<(), SupplyChainError> {
    let Some(github_output) = std::env::var_os("GITHUB_OUTPUT") else {
        return Ok(());
    };

    let report_path = persist_report(report)?;
    let fail = output_error(&github_output);
    let mut output = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&github_output)
        .map_err(&fail)?;
    writeln!(output, "status={}", overall_status(&report.findings)).map_err(&fail)?;
    writeln!(output, "report={}", report_path.display()).map_err(&fail)?;
    Ok(())
}

fn output_error(github_output: &OsStr) -> impl Fn(std::io::Error) -> SupplyChainError {
    let path = path_text(Path::new(github_output));
    move |source| SupplyChainError::GithubOutput {
        path: path.clone(),
        source,
    }
}

/// Write the report somewhere the workflow can read after this process exits.
fn persist_report(report: &Report) -> Result<PathBuf, SupplyChainError> {
    let file = NamedTempFile::new().map_err(SupplyChainError::PersistReport)?;
    serde_json::to_writer_pretty(file.as_file(), report).map_err(|source| {
        SupplyChainError::BaselineParse {
            path: path_text(file.path()),
            source,
        }
    })?;
    let (_file, path) = file
        .keep()
        .map_err(|error| SupplyChainError::PersistReport(error.error))?;
    Ok(path)
}
