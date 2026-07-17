use serde::Serialize;

use crate::config::FailOn;
use crate::github::AnnotationLevel;

/// What a finding says about a dependency, ordered by how much it matters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum FindingLevel {
    HashMismatch,
    NewCapability,
    NewDependency,
    AnalysisIncomplete,
}

impl FindingLevel {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::HashMismatch => "hash-mismatch",
            Self::NewCapability => "new-capability",
            Self::NewDependency => "new-dependency",
            Self::AnalysisIncomplete => "analysis-incomplete",
        }
    }

    pub(super) fn annotation_level(self) -> AnnotationLevel {
        match self {
            Self::HashMismatch => AnnotationLevel::Error,
            Self::NewCapability => AnnotationLevel::Warning,
            Self::NewDependency => AnnotationLevel::Notice,
            Self::AnalysisIncomplete => AnnotationLevel::Notice,
        }
    }

    /// Rank used against the `--fail-on` threshold; higher is worse.
    fn severity_rank(self) -> usize {
        match self {
            Self::HashMismatch => 3,
            Self::NewCapability => 2,
            Self::NewDependency => 1,
            Self::AnalysisIncomplete => 0,
        }
    }

    /// Shifted so `AnalysisIncomplete` outranks the "clean" floor of zero.
    fn status_rank(self) -> usize {
        self.severity_rank() + 1
    }
}

#[derive(Serialize)]
pub(super) struct ReportFinding {
    pub(super) level: FindingLevel,
    pub(super) ecosystem: &'static str,
    pub(super) name: Box<str>,
    pub(super) version: Box<str>,
    pub(super) detail: Box<str>,
}

#[derive(Serialize)]
pub(super) struct Report {
    pub(super) findings: Vec<ReportFinding>,
}

/// The worst level present, or `clean` when nothing was found.
pub(super) fn overall_status(findings: &[ReportFinding]) -> &'static str {
    findings
        .iter()
        .map(|finding| finding.level)
        .max_by_key(|level| level.status_rank())
        .map(FindingLevel::as_str)
        .unwrap_or("clean")
}

pub(super) fn should_fail(findings: &[ReportFinding], fail_on: FailOn) -> bool {
    let threshold = match fail_on {
        FailOn::HashMismatch => 3,
        FailOn::NewCapability => 2,
        FailOn::NewDependency => 1,
        FailOn::None => 0,
    };
    match threshold {
        0 => false,
        _ => findings
            .iter()
            .any(|finding| finding.level.severity_rank() >= threshold),
    }
}
